// Unit tests for ObsidianGuardLite.
//
// Verifies key generation, save/load (RSA/PQ PEM only), encryption/decryption
// round-trips, every error return code with its exact value, and thread
// safety (concurrent use of one shared instance, including concurrent key
// mutation). No external test framework is required.
//
// The return codes are aligned with ObsidianGuard's CryptoErrorCode:
//   0 = ok, -1 = InvalidArgument, -2 = OpenSslFailure, -3 = AuthFailed,
//   -4 = Unavailable, -5 = Internal, -6 = kErrFile (Lite-only extension).
//
// Worker threads only touch per-thread atomic failure counters, so the
// reporting counters stay single-threaded.

#include "Aes256.hpp"
#include "Rsa4096.hpp"
#include "PostQuantum.hpp"

#include <openssl/opensslv.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  include <io.h>  // _isatty / _fileno: pause only for an interactive console
#endif

// ---------------------------------------------------------------------------
// The aligned error-code scheme is a compile-time contract.
// ---------------------------------------------------------------------------
static_assert(ObsidianGuardLite::Aes256::kOk == 0, "kOk must be 0");
static_assert(ObsidianGuardLite::Aes256::kErrInvalidArgument == -1,
              "kErrInvalidArgument must be -1");
static_assert(ObsidianGuardLite::Aes256::kErrOpenSsl == -2, "kErrOpenSsl must be -2");
static_assert(ObsidianGuardLite::Aes256::kErrAuth == -3, "kErrAuth must be -3");
static_assert(ObsidianGuardLite::Aes256::kErrUnavailable == -4,
              "kErrUnavailable must be -4");
static_assert(ObsidianGuardLite::Aes256::kErrInternal == -5, "kErrInternal must be -5");
static_assert(ObsidianGuardLite::Aes256::kErrFile == -6, "kErrFile must be -6");
// The same values must be exposed by all three classes.
static_assert(ObsidianGuardLite::Rsa4096::kErrOpenSsl ==
                  ObsidianGuardLite::Aes256::kErrOpenSsl,
              "RSA and AES must share the aligned codes");
static_assert(ObsidianGuardLite::PostQuantum::kErrUnavailable ==
                  ObsidianGuardLite::Aes256::kErrUnavailable,
              "PostQuantum and AES must share the aligned codes");

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        ++g_checks;                                                          \
        if (cond) {                                                          \
            std::cout << "  ok   - " << (msg) << std::endl;                  \
        } else {                                                             \
            ++g_failures;                                                    \
            std::cout << "  FAIL - " << (msg) << "  [" << __FILE__ << ":"    \
                      << __LINE__ << "]" << std::endl;                       \
        }                                                                    \
    } while (0)

namespace {

std::filesystem::path makeTempDir() {
    const auto now = std::chrono::high_resolution_clock::now()
                         .time_since_epoch()
                         .count();
    auto path = std::filesystem::temp_directory_path() /
                ("ObsidianGuardLite_test_" + std::to_string(now));
    std::filesystem::create_directories(path);
    return path;
}

std::vector<unsigned char> bytes(const std::string& s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

/// True when the test should wait for a keypress before exiting: only for an
/// interactive console (double-click or a terminal window). Piped/redirected
/// runs (CTest, CI) skip the pause, and OBSIDIAN_GUARD_NO_PAUSE forces it off.
bool pauseRequested() {
#if defined(_WIN32)
    if (std::getenv("OBSIDIAN_GUARD_NO_PAUSE") != nullptr) {
        return false;
    }
    return _isatty(_fileno(stdin)) != 0;
#else
    return std::getenv("OBSIDIAN_GUARD_NO_PAUSE") == nullptr;
#endif
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------
void testAes() {
    std::cout << "\n[AES-256-GCM]\n";

    ObsidianGuardLite::Aes256 aes;
    std::vector<unsigned char> out;

    // No key yet -> kErrInvalidArgument.
    CHECK(aes.encrypt(bytes("x"), out) == ObsidianGuardLite::Aes256::kErrInvalidArgument,
          "AES: encrypt without key returns -1");

    CHECK(aes.generateKey() == 0, "AES: generate key returns 0");
    CHECK(aes.hasKey(), "AES: hasKey() after generate");
    CHECK(aes.getKey().size() == ObsidianGuardLite::Aes256::kKeySize,
          "AES: getKey() returns a 32-byte copy");

    const auto plain = bytes("The quick brown fox jumps over the lazy dog");
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> recovered;

    CHECK(aes.encrypt(plain, cipher) == 0, "AES: encrypt returns 0");
    CHECK(cipher.size() == plain.size() + ObsidianGuardLite::Aes256::kIvSize +
                                 ObsidianGuardLite::Aes256::kTagSize,
          "AES: ciphertext size = plaintext + IV + tag");
    CHECK(aes.decrypt(cipher, recovered) == 0, "AES: decrypt returns 0");
    CHECK(recovered == plain, "AES: round-trip matches");

    // Copy the key in memory (setKey) and decrypt with it.
    ObsidianGuardLite::Aes256 aes2;
    CHECK(aes2.setKey(aes.getKey()) == 0, "AES: setKey returns 0");
    recovered.clear();
    CHECK(aes2.decrypt(cipher, recovered) == 0, "AES: decrypt with copied key");
    CHECK(recovered == plain, "AES: round-trip matches with copied key");

    // setKey with the wrong size -> kErrInvalidArgument.
    CHECK(aes2.setKey(bytes("too short")) == ObsidianGuardLite::Aes256::kErrInvalidArgument,
          "AES: setKey wrong size returns -1");

    // Malformed ciphertext (shorter than IV + tag) -> kErrInvalidArgument.
    recovered.clear();
    CHECK(aes.decrypt(bytes("tiny"), recovered) ==
              ObsidianGuardLite::Aes256::kErrInvalidArgument,
          "AES: truncated ciphertext returns -1");
    CHECK(recovered.empty(), "AES: no output on malformed input");

    // Wrong key -> kErrAuth.
    ObsidianGuardLite::Aes256 wrong;
    CHECK(wrong.generateKey() == 0, "AES: generate wrong key");
    recovered.clear();
    CHECK(wrong.decrypt(cipher, recovered) == ObsidianGuardLite::Aes256::kErrAuth,
          "AES: wrong key returns -3");
    CHECK(recovered.empty(), "AES: no plaintext leaked on failure");

    // Corrupted ciphertext -> kErrAuth.
    auto tampered = cipher;
    tampered[ObsidianGuardLite::Aes256::kIvSize] ^= 0x01; // flip one ciphertext byte
    recovered.clear();
    CHECK(aes.decrypt(tampered, recovered) == ObsidianGuardLite::Aes256::kErrAuth,
          "AES: tampered ciphertext returns -3");
    CHECK(recovered.empty(), "AES: no plaintext leaked on failure");

    // AAD overloads: bind associated data into the tag.
    const auto aad = bytes("header-metadata");
    std::vector<unsigned char> aadCipher;
    recovered.clear();
    CHECK(aes.encrypt(plain, aad, aadCipher) == 0, "AES: encrypt with AAD returns 0");
    CHECK(aes.decrypt(aadCipher, aad, recovered) == 0, "AES: decrypt with AAD returns 0");
    CHECK(recovered == plain, "AES: AAD round-trip matches");

    // Wrong / missing AAD -> kErrAuth, no output.
    auto wrongAad = aad;
    wrongAad[0] ^= 0x01;
    recovered.clear();
    CHECK(aes.decrypt(aadCipher, wrongAad, recovered) == ObsidianGuardLite::Aes256::kErrAuth,
          "AES: wrong AAD returns -3");
    CHECK(recovered.empty(), "AES: no output on wrong AAD");
    recovered.clear();
    CHECK(aes.decrypt(aadCipher, bytes(""), recovered) ==
              ObsidianGuardLite::Aes256::kErrAuth,
          "AES: missing AAD returns -3");

    // Empty AAD behaves exactly like the no-AAD overload.
    std::vector<unsigned char> plainCipher;
    recovered.clear();
    CHECK(aes.encrypt(plain, bytes(""), plainCipher) == 0,
          "AES: encrypt with empty AAD returns 0");
    CHECK(aes.decrypt(plainCipher, recovered) == 0,
          "AES: empty-AAD ciphertext decrypts without AAD");
    CHECK(recovered == plain, "AES: empty-AAD round-trip matches");
}

// ---------------------------------------------------------------------------
// RSA-4096 / OAEP-SHA256
// ---------------------------------------------------------------------------
void testRsa() {
    std::cout << "\n[RSA-4096 / OAEP-SHA256]\n";
    const auto dir = makeTempDir();

    ObsidianGuardLite::Rsa4096 rsa;
    std::vector<unsigned char> out;

    CHECK(rsa.encrypt(bytes("x"), out) == ObsidianGuardLite::Rsa4096::kErrInvalidArgument,
          "RSA: encrypt without key returns -1");

    // File I/O errors -> kErrFile (-6).
    const auto missing = (dir / "does_not_exist.pem").string();
    CHECK(rsa.loadPublicKey(missing) == ObsidianGuardLite::Rsa4096::kErrFile,
          "RSA: loadPublicKey(missing file) returns -6");
    CHECK(rsa.loadPrivateKey(missing) == ObsidianGuardLite::Rsa4096::kErrFile,
          "RSA: loadPrivateKey(missing file) returns -6");

    std::cout << "  (generating a 4096-bit RSA key, this can take a few seconds...)\n";
    CHECK(rsa.generateKeyPair() == 0, "RSA: generate key pair returns 0");
    CHECK(rsa.hasPublicKey(), "RSA: hasPublicKey()");
    CHECK(rsa.hasPrivateKey(), "RSA: hasPrivateKey()");

    // Save to an unwritable path -> kErrFile (-6) (needs a key first).
    const auto badPath = (dir / "no_such_subdir" / "x.pem").string();
    CHECK(rsa.savePublicKey(badPath) == ObsidianGuardLite::Rsa4096::kErrFile,
          "RSA: savePublicKey(unwritable path) returns -6");

    const auto plain = bytes("Confidential RSA message");
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> recovered;

    CHECK(rsa.encrypt(plain, cipher) == 0, "RSA: encrypt returns 0");
    CHECK(cipher.size() == ObsidianGuardLite::Rsa4096::kModulusSize,
          "RSA: ciphertext is 512 bytes");
    CHECK(rsa.decrypt(cipher, recovered) == 0, "RSA: decrypt returns 0");
    CHECK(recovered == plain, "RSA: round-trip matches");

    // Oversized plaintext -> kErrInvalidArgument.
    std::vector<unsigned char> tooBig(ObsidianGuardLite::Rsa4096::kMaxPlaintext + 1, 'a');
    cipher.clear();
    CHECK(rsa.encrypt(tooBig, cipher) == ObsidianGuardLite::Rsa4096::kErrInvalidArgument,
          "RSA: oversized plaintext returns -1");

    // Wrong-size ciphertext -> kErrInvalidArgument.
    recovered.clear();
    CHECK(rsa.decrypt(bytes("short"), recovered) ==
              ObsidianGuardLite::Rsa4096::kErrInvalidArgument,
          "RSA: wrong-size ciphertext returns -1");

    // Corrupted ciphertext -> OAEP padding error -> kErrOpenSsl (-2), NOT -3.
    // (cipher was cleared by the oversized-plaintext test: encrypt again.)
    CHECK(rsa.encrypt(plain, cipher) == 0, "RSA: re-encrypt for tamper test");
    auto tampered = cipher;
    tampered[tampered.size() / 2] ^= 0xFF;
    recovered.clear();
    CHECK(rsa.decrypt(tampered, recovered) == ObsidianGuardLite::Rsa4096::kErrOpenSsl,
          "RSA: corrupted ciphertext returns -2 (padding error)");
    CHECK(recovered.empty(), "RSA: no plaintext leaked on failure");

    // Save / load keys.
    const auto pubPath = (dir / "rsa_pub.pem").string();
    const auto privPath = (dir / "rsa_priv.pem").string();
    CHECK(rsa.savePublicKey(pubPath) == 0, "RSA: save public key returns 0");
    CHECK(rsa.savePrivateKey(privPath) == 0, "RSA: save private key returns 0");

    ObsidianGuardLite::Rsa4096 pub;
    ObsidianGuardLite::Rsa4096 priv;
    CHECK(pub.loadPublicKey(pubPath) == 0, "RSA: load public key returns 0");
    CHECK(priv.loadPrivateKey(privPath) == 0, "RSA: load private key returns 0");
    CHECK(pub.hasPublicKey() && !pub.hasPrivateKey(), "RSA: public-only object");

    std::vector<unsigned char> cipher2;
    recovered.clear();
    CHECK(pub.encrypt(plain, cipher2) == 0, "RSA: encrypt with loaded public key");
    CHECK(priv.decrypt(cipher2, recovered) == 0, "RSA: decrypt with loaded private key");
    CHECK(recovered == plain, "RSA: round-trip with loaded keys");

    // Public-only object cannot decrypt -> kErrInvalidArgument.
    recovered.clear();
    CHECK(pub.decrypt(cipher, recovered) == ObsidianGuardLite::Rsa4096::kErrInvalidArgument,
          "RSA: public key cannot decrypt (-1)");

    // Public-only object cannot save a private key -> kErrInvalidArgument.
    CHECK(pub.savePrivateKey((dir / "nope.pem").string()) ==
              ObsidianGuardLite::Rsa4096::kErrInvalidArgument,
          "RSA: savePrivateKey without private key returns -1");

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Post-Quantum ML-KEM-768 + AES-256-GCM
// ---------------------------------------------------------------------------
void testPostQuantum() {
    std::cout << "\n[Post-Quantum ML-KEM-768 + AES-256-GCM]\n";
    const auto dir = makeTempDir();

    ObsidianGuardLite::PostQuantum pq;
    std::vector<unsigned char> out;

    CHECK(pq.encrypt(bytes("x"), out) == ObsidianGuardLite::PostQuantum::kErrInvalidArgument,
          "PQ: encrypt without key returns -1");

    // File I/O errors -> kErrFile (-6).
    const auto missing = (dir / "does_not_exist.pem").string();
    CHECK(pq.loadPublicKey(missing) == ObsidianGuardLite::PostQuantum::kErrFile,
          "PQ: loadPublicKey(missing file) returns -6");

    const int rc = pq.generateKeyPair();
    if (rc == ObsidianGuardLite::PostQuantum::kErrUnavailable) {
        // OpenSSL built without ML-KEM: the aligned Unavailable code (-4).
        std::cout << "  (ML-KEM not available in this OpenSSL build;"
                     " checking the unavailable-code contract)\n";
        CHECK(rc == ObsidianGuardLite::PostQuantum::kErrUnavailable,
              "PQ: generateKeyPair returns -4 when ML-KEM is unavailable");
        std::filesystem::remove_all(dir);
        return;
    }
    CHECK(rc == 0, "PQ: generate key pair returns 0");
    CHECK(pq.hasPublicKey(), "PQ: hasPublicKey()");
    CHECK(pq.hasPrivateKey(), "PQ: hasPrivateKey()");

    // Save to an unwritable path -> kErrFile (-6) (needs a key first).
    CHECK(pq.savePublicKey((dir / "no_such_subdir" / "x.pem").string()) ==
              ObsidianGuardLite::PostQuantum::kErrFile,
          "PQ: savePublicKey(unwritable path) returns -6");

    const auto plain = bytes("A post-quantum encrypted message");
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> recovered;

    CHECK(pq.encrypt(plain, cipher) == 0, "PQ: encrypt returns 0");
    CHECK(!cipher.empty(), "PQ: ciphertext non-empty");
    CHECK(pq.decrypt(cipher, recovered) == 0, "PQ: decrypt returns 0");
    CHECK(recovered == plain, "PQ: round-trip matches");

    // Malformed ciphertext (shorter than the header + IV + tag) -> -1.
    recovered.clear();
    CHECK(pq.decrypt(bytes("tiny"), recovered) ==
              ObsidianGuardLite::PostQuantum::kErrInvalidArgument,
          "PQ: truncated ciphertext returns -1");

    // Save / load keys.
    const auto pubPath = (dir / "pq_pub.pem").string();
    const auto privPath = (dir / "pq_priv.pem").string();
    CHECK(pq.savePublicKey(pubPath) == 0, "PQ: save public key returns 0");
    CHECK(pq.savePrivateKey(privPath) == 0, "PQ: save private key returns 0");

    ObsidianGuardLite::PostQuantum pub;
    ObsidianGuardLite::PostQuantum priv;
    CHECK(pub.loadPublicKey(pubPath) == 0, "PQ: load public key returns 0");
    CHECK(priv.loadPrivateKey(privPath) == 0, "PQ: load private key returns 0");

    std::vector<unsigned char> cipher2;
    recovered.clear();
    CHECK(pub.encrypt(plain, cipher2) == 0, "PQ: encrypt with loaded public key");
    CHECK(priv.decrypt(cipher2, recovered) == 0, "PQ: decrypt with loaded private key");
    CHECK(recovered == plain, "PQ: round-trip with loaded keys");

    // Corrupted ciphertext -> kErrAuth.
    auto tampered = cipher;
    tampered[tampered.size() / 2] ^= 0x01;
    recovered.clear();
    CHECK(pq.decrypt(tampered, recovered) == ObsidianGuardLite::PostQuantum::kErrAuth,
          "PQ: tampered ciphertext returns -3");

    // A different private key -> kErrAuth.
    ObsidianGuardLite::PostQuantum other;
    CHECK(other.generateKeyPair() == 0, "PQ: generate a second key pair");
    recovered.clear();
    CHECK(other.decrypt(cipher, recovered) == ObsidianGuardLite::PostQuantum::kErrAuth,
          "PQ: wrong key returns -3");

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Thread safety: one shared instance, many threads
// ---------------------------------------------------------------------------
void testAesThreads() {
    std::cout << "\n[AES thread safety (one shared instance)]\n";

    ObsidianGuardLite::Aes256 shared;
    CHECK(shared.generateKey() == 0, "AES threads: setup key");
    const auto key = shared.getKey();

    // Storm 1: concurrent setKey (same bytes) + encrypt + decrypt. The key
    // snapshot never changes value, so every round trip must succeed.
    {
        constexpr int kThreads = 4;
        constexpr int kIterations = 30;
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&shared, &key, &failures, t]() {
                std::vector<unsigned char> plain(128);
                for (std::size_t i = 0; i < plain.size(); ++i) {
                    plain[i] = static_cast<unsigned char>(t * 7 + static_cast<int>(i));
                }
                for (int i = 0; i < kIterations; ++i) {
                    std::vector<unsigned char> cipher;
                    std::vector<unsigned char> recovered;
                    if (shared.setKey(key) != 0 ||
                        shared.encrypt(plain, cipher) != 0 ||
                        shared.decrypt(cipher, recovered) != 0 ||
                        recovered != plain) {
                        ++failures;
                        return;
                    }
                }
            });
        }
        for (std::thread& thread : threads) {
            thread.join();
        }
        CHECK(failures.load() == 0, "AES threads: concurrent setKey/encrypt/decrypt storm");
    }

    // Storm 2: one thread keeps replacing the key while others encrypt and
    // decrypt. A decrypt either sees the same key (0) or the new one
    // (kErrAuth), never anything else; on failure the output must be empty.
    {
        constexpr int kWorkers = 3;
        constexpr int kIterations = 40;
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        threads.reserve(kWorkers + 1);
        for (int t = 0; t < kWorkers; ++t) {
            threads.emplace_back([&shared, &failures, t]() {
                std::vector<unsigned char> plain(64);
                for (std::size_t i = 0; i < plain.size(); ++i) {
                    plain[i] = static_cast<unsigned char>(t * 31 + static_cast<int>(i));
                }
                for (int i = 0; i < kIterations; ++i) {
                    std::vector<unsigned char> cipher;
                    std::vector<unsigned char> recovered;
                    if (shared.encrypt(plain, cipher) != 0) {
                        ++failures;
                        return;
                    }
                    const int rc = shared.decrypt(cipher, recovered);
                    if (rc == 0) {
                        if (recovered != plain) {
                            ++failures;
                            return;
                        }
                    } else if (rc == ObsidianGuardLite::Aes256::kErrAuth) {
                        if (!recovered.empty()) {
                            ++failures;
                            return;
                        }
                    } else {
                        ++failures;
                        return;
                    }
                }
            });
        }
        threads.emplace_back([&shared, &failures]() {
            for (int i = 0; i < kIterations; ++i) {
                if (shared.generateKey() != 0) {
                    ++failures;
                    return;
                }
            }
        });
        for (std::thread& thread : threads) {
            thread.join();
        }
        CHECK(failures.load() == 0,
              "AES threads: concurrent generateKey/encrypt/decrypt storm");

        // The instance must still be fully usable after the storm.
        std::vector<unsigned char> cipher;
        std::vector<unsigned char> recovered;
        const auto plain = bytes("post-storm sanity check");
        CHECK(shared.encrypt(plain, cipher) == 0 && shared.decrypt(cipher, recovered) == 0 &&
                  recovered == plain,
              "AES threads: round trip still works after the storm");
    }
}

void testRsaThreads() {
    std::cout << "\n[RSA thread safety (one shared instance)]\n";

    ObsidianGuardLite::Rsa4096 shared;
    CHECK(shared.generateKeyPair() == 0, "RSA threads: setup key");
    const auto dir = makeTempDir();
    const auto privPath = (dir / "rsa_priv.pem").string();
    CHECK(shared.savePrivateKey(privPath) == 0, "RSA threads: save private key");

    // Concurrent loadPrivateKey (same key material) + encrypt + decrypt:
    // every round trip must succeed even while the pointer is being swapped.
    {
        constexpr int kThreads = 4;
        constexpr int kIterations = 15;
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&shared, &privPath, &failures, t]() {
                std::vector<unsigned char> plain(64);
                for (std::size_t i = 0; i < plain.size(); ++i) {
                    plain[i] = static_cast<unsigned char>(t * 11 + static_cast<int>(i));
                }
                for (int i = 0; i < kIterations; ++i) {
                    std::vector<unsigned char> cipher;
                    std::vector<unsigned char> recovered;
                    if (shared.loadPrivateKey(privPath) != 0 ||
                        shared.encrypt(plain, cipher) != 0 ||
                        shared.decrypt(cipher, recovered) != 0 ||
                        recovered != plain) {
                        ++failures;
                        return;
                    }
                }
            });
        }
        for (std::thread& thread : threads) {
            thread.join();
        }
        CHECK(failures.load() == 0, "RSA threads: concurrent load/encrypt/decrypt storm");
    }

    std::filesystem::remove_all(dir);
}

void testPostQuantumThreads() {
    std::cout << "\n[PostQuantum thread safety (one shared instance)]\n";

    ObsidianGuardLite::PostQuantum shared;
    const int rc = shared.generateKeyPair();
    if (rc == ObsidianGuardLite::PostQuantum::kErrUnavailable) {
        std::cout << "  (ML-KEM not available; skipping the PQ thread test)\n";
        return;
    }
    CHECK(rc == 0, "PQ threads: setup key");
    const auto dir = makeTempDir();
    const auto privPath = (dir / "pq_priv.pem").string();
    CHECK(shared.savePrivateKey(privPath) == 0, "PQ threads: save private key");

    // Concurrent loadPrivateKey (same key material) + encrypt + decrypt.
    {
        constexpr int kThreads = 4;
        constexpr int kIterations = 15;
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&shared, &privPath, &failures, t]() {
                std::vector<unsigned char> plain(96);
                for (std::size_t i = 0; i < plain.size(); ++i) {
                    plain[i] = static_cast<unsigned char>(t * 13 + static_cast<int>(i));
                }
                for (int i = 0; i < kIterations; ++i) {
                    std::vector<unsigned char> cipher;
                    std::vector<unsigned char> recovered;
                    if (shared.loadPrivateKey(privPath) != 0 ||
                        shared.encrypt(plain, cipher) != 0 ||
                        shared.decrypt(cipher, recovered) != 0 ||
                        recovered != plain) {
                        ++failures;
                        return;
                    }
                }
            });
        }
        for (std::thread& thread : threads) {
            thread.join();
        }
        CHECK(failures.load() == 0, "PQ threads: concurrent load/encrypt/decrypt storm");
    }

    std::filesystem::remove_all(dir);
}

} // namespace

int main() {
    std::cout << "ObsidianGuardLite unit tests\n";
    std::cout << "OpenSSL " << OPENSSL_VERSION_TEXT << "\n";

    testAes();
    testRsa();
    testPostQuantum();
    testAesThreads();
    testRsaThreads();
    testPostQuantumThreads();

    std::cout << "\n========================================\n";
    std::cout << g_checks << " checks, " << g_failures << " failure(s)\n";
    const bool passed = (g_failures == 0);
    std::cout << (passed ? "ALL TESTS PASSED" : "TESTS FAILED") << "\n";

    // Keep the console window open so the output can be read — only when
    // running interactively (CTest and redirected runs skip the pause).
    if (pauseRequested()) {
#if defined(_WIN32)
        std::system("pause");
#else
        std::cout << "Press Enter to continue..." << std::flush;
        std::cin.get();
#endif
    }

    return passed ? 0 : 1;
}
