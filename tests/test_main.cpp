// Unit tests for ObsidianGuardLite.
//
// Verifies key generation, save/load (RSA/PQ PEM only), encryption/decryption
// round-trips, and error return codes. No external test framework is required.

#include "Aes256.hpp"
#include "Rsa4096.hpp"
#include "PostQuantum.hpp"

#include <openssl/opensslv.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        ++g_checks;                                                          \
        if (cond) {                                                          \
            std::cout << "  ok   - " << (msg) << "\n";                       \
        } else {                                                             \
            ++g_failures;                                                    \
            std::cout << "  FAIL - " << (msg) << "  [" << __FILE__ << ":"    \
                      << __LINE__ << "]\n";                                  \
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

void testAes() {
    std::cout << "\n[AES-256-GCM]\n";

    ObsidianGuardLite::Aes256 aes;
    std::vector<unsigned char> out;

    // No key yet -> kErrNoKey.
    CHECK(aes.encrypt(bytes("x"), out) == ObsidianGuardLite::Aes256::kErrNoKey,
          "AES: encrypt without key returns -1");

    CHECK(aes.generateKey() == 0, "AES: generate key returns 0");
    CHECK(aes.hasKey(), "AES: hasKey() after generate");
    CHECK(aes.getKey().size() == ObsidianGuardLite::Aes256::kKeySize, "AES: key is 32 bytes");

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

    // setKey with the wrong size -> kErrBadArg.
    CHECK(aes2.setKey(bytes("too short")) == ObsidianGuardLite::Aes256::kErrBadArg,
          "AES: setKey wrong size returns -2");

    // Wrong key -> kErrAuth.
    ObsidianGuardLite::Aes256 wrong;
    CHECK(wrong.generateKey() == 0, "AES: generate wrong key");
    recovered.clear();
    CHECK(wrong.decrypt(cipher, recovered) == ObsidianGuardLite::Aes256::kErrAuth,
          "AES: wrong key returns -4");
    CHECK(recovered.empty(), "AES: no plaintext leaked on failure");

    // Corrupted ciphertext -> kErrAuth.
    auto tampered = cipher;
    tampered[ObsidianGuardLite::Aes256::kIvSize] ^= 0x01; // flip one ciphertext byte
    recovered.clear();
    CHECK(aes.decrypt(tampered, recovered) == ObsidianGuardLite::Aes256::kErrAuth,
          "AES: tampered ciphertext returns -4");
}

void testRsa() {
    std::cout << "\n[RSA-4096 / OAEP-SHA256]\n";
    const auto dir = makeTempDir();

    ObsidianGuardLite::Rsa4096 rsa;
    std::vector<unsigned char> out;

    CHECK(rsa.encrypt(bytes("x"), out) == ObsidianGuardLite::Rsa4096::kErrNoKey,
          "RSA: encrypt without key returns -1");

    std::cout << "  (generating a 4096-bit RSA key, this can take a few seconds...)\n";
    CHECK(rsa.generateKeyPair() == 0, "RSA: generate key pair returns 0");
    CHECK(rsa.hasPublicKey(), "RSA: hasPublicKey()");
    CHECK(rsa.hasPrivateKey(), "RSA: hasPrivateKey()");

    const auto plain = bytes("Confidential RSA message");
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> recovered;

    CHECK(rsa.encrypt(plain, cipher) == 0, "RSA: encrypt returns 0");
    CHECK(cipher.size() == ObsidianGuardLite::Rsa4096::kModulusSize,
          "RSA: ciphertext is 512 bytes");
    CHECK(rsa.decrypt(cipher, recovered) == 0, "RSA: decrypt returns 0");
    CHECK(recovered == plain, "RSA: round-trip matches");

    // Oversized plaintext -> kErrBadArg.
    std::vector<unsigned char> tooBig(ObsidianGuardLite::Rsa4096::kMaxPlaintext + 1, 'a');
    cipher.clear();
    CHECK(rsa.encrypt(tooBig, cipher) == ObsidianGuardLite::Rsa4096::kErrBadArg,
          "RSA: oversized plaintext returns -2");

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

    // Public-only object cannot decrypt -> kErrNoKey.
    recovered.clear();
    CHECK(pub.decrypt(cipher, recovered) == ObsidianGuardLite::Rsa4096::kErrNoKey,
          "RSA: public key cannot decrypt (-1)");

    std::filesystem::remove_all(dir);
}

void testPostQuantum() {
    std::cout << "\n[Post-Quantum ML-KEM-768 + AES-256-GCM]\n";
    const auto dir = makeTempDir();

    ObsidianGuardLite::PostQuantum pq;
    std::vector<unsigned char> out;

    CHECK(pq.encrypt(bytes("x"), out) == ObsidianGuardLite::PostQuantum::kErrNoKey,
          "PQ: encrypt without key returns -1");

    CHECK(pq.generateKeyPair() == 0, "PQ: generate key pair returns 0");
    CHECK(pq.hasPublicKey(), "PQ: hasPublicKey()");
    CHECK(pq.hasPrivateKey(), "PQ: hasPrivateKey()");

    const auto plain = bytes("A post-quantum encrypted message");
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> recovered;

    CHECK(pq.encrypt(plain, cipher) == 0, "PQ: encrypt returns 0");
    CHECK(!cipher.empty(), "PQ: ciphertext non-empty");
    CHECK(pq.decrypt(cipher, recovered) == 0, "PQ: decrypt returns 0");
    CHECK(recovered == plain, "PQ: round-trip matches");

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
          "PQ: tampered ciphertext returns -4");

    // A different private key -> kErrAuth.
    ObsidianGuardLite::PostQuantum other;
    CHECK(other.generateKeyPair() == 0, "PQ: generate a second key pair");
    recovered.clear();
    CHECK(other.decrypt(cipher, recovered) == ObsidianGuardLite::PostQuantum::kErrAuth,
          "PQ: wrong key returns -4");

    std::filesystem::remove_all(dir);
}

} // namespace

int main() {
    std::cout << "ObsidianGuardLite unit tests\n";
    std::cout << "OpenSSL " << OPENSSL_VERSION_TEXT << "\n";

    testAes();
    testRsa();
    testPostQuantum();

    std::cout << "\n========================================\n";
    std::cout << g_checks << " checks, " << g_failures << " failure(s)\n";
    const bool passed = (g_failures == 0);
    std::cout << (passed ? "ALL TESTS PASSED" : "TESTS FAILED") << "\n";

    // Keep the console window open so the output can be read.
    std::cout << std::endl;
    std::system("pause");

    return passed ? 0 : 1;
}
