// AES-256 authenticated encryption (AES-256-GCM).
//
// The 256-bit key lives ONLY in memory. It is never written to or read from
// disk: generate a random key with generateKey(), or supply one with setKey().
//
// Ciphertext layout (binary): [ 12-byte IV ][ ciphertext ][ 16-byte GCM tag ]
//
// Thread safety: every method locks internally, so a single instance may be
// shared freely between threads. encrypt()/decrypt() snapshot the key under
// the lock and run the crypto on that snapshot, so even concurrent
// generateKey()/setKey() calls cannot race; a call either sees the old key
// or the new one, never a torn state.
#ifndef OBSIDIAN_GUARD_LITE_AES256_HPP
#define OBSIDIAN_GUARD_LITE_AES256_HPP

// DLL import/export macro (Windows).
#ifndef OBSIDIAN_GUARD_LITE_API
    #ifdef OBSIDIAN_GUARD_LITE_STATIC
        #define OBSIDIAN_GUARD_LITE_API
    #elif defined(OBSIDIAN_GUARD_LITE_EXPORTS)
        #define OBSIDIAN_GUARD_LITE_API __declspec(dllexport)
    #else
        #define OBSIDIAN_GUARD_LITE_API __declspec(dllimport)
    #endif
#endif

#include <cstddef>
#include <mutex>
#include <vector>

namespace ObsidianGuardLite {

class OBSIDIAN_GUARD_LITE_API Aes256 {
public:
    static constexpr std::size_t kKeySize = 32; // bytes = 256 bits
    static constexpr std::size_t kIvSize  = 12; // bytes = 96 bits (GCM)
    static constexpr std::size_t kTagSize = 16; // bytes = 128 bits

    // Return codes, aligned with ObsidianGuard's CryptoErrorCode categories
    // (see README for the full table):
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input / no key available
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (Lite-only extension)

    Aes256();
    ~Aes256();

    // The key is owned exclusively by this object; copying/moving is disabled.
    Aes256(const Aes256&) = delete;
    Aes256& operator=(const Aes256&) = delete;
    Aes256(Aes256&&) = delete;
    Aes256& operator=(Aes256&&) = delete;

    // ---- key management (in memory only) --------------------------------
    // Generate a fresh random 256-bit key. Returns kOk (0) on success.
    int generateKey();
    // Set the key from an existing 32-byte buffer. Returns
    // kErrInvalidArgument (-1) if the buffer is not exactly 32 bytes.
    int setKey(const std::vector<unsigned char>& key);
    // True once a key has been generated or set.
    bool hasKey() const;
    // Copy of the stored key bytes (returned by value so it is a consistent
    // snapshot even when other threads keep using the object).
    std::vector<unsigned char> getKey() const;

    // ---- encryption / decryption ---------------------------------------
    int encrypt(const std::vector<unsigned char>& plaintext,
                std::vector<unsigned char>& ciphertext) const;
    int decrypt(const std::vector<unsigned char>& ciphertext,
                std::vector<unsigned char>& plaintext) const;

    // AAD overloads: bind associated data (headers, IDs, metadata) into the
    // GCM tag. AAD is authenticated but not encrypted; tampering with either
    // the ciphertext or the AAD is detected at decryption (kErrAuth). The
    // ciphertext layout is unchanged: [12-byte IV][ciphertext][16-byte tag].
    int encrypt(const std::vector<unsigned char>& plaintext,
                const std::vector<unsigned char>& aad,
                std::vector<unsigned char>& ciphertext) const;
    int decrypt(const std::vector<unsigned char>& ciphertext,
                const std::vector<unsigned char>& aad,
                std::vector<unsigned char>& plaintext) const;

private:
    void clearKey();  // call only with mutex_ held (or during destruction)

    mutable std::mutex mutex_;  // guards key_ and hasKey_
    std::vector<unsigned char> key_;
    bool hasKey_;
};

} // namespace ObsidianGuardLite

#endif // OBSIDIAN_GUARD_LITE_AES256_HPP
