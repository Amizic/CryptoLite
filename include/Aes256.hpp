// AES-256 authenticated encryption (AES-256-GCM).
//
// The 256-bit key lives ONLY in memory. It is never written to or read from
// disk: generate a random key with generateKey(), or supply one with setKey().
//
// Ciphertext layout (binary): [ 12-byte IV ][ ciphertext ][ 16-byte GCM tag ]
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
#include <vector>

namespace ObsidianGuardLite {

class OBSIDIAN_GUARD_LITE_API Aes256 {
public:
    static constexpr std::size_t kKeySize = 32; // bytes = 256 bits
    static constexpr std::size_t kIvSize  = 12; // bytes = 96 bits (GCM)
    static constexpr std::size_t kTagSize = 16; // bytes = 128 bits

    // Return codes (see README for the full table).
    static constexpr int kOk        = 0;
    static constexpr int kErrNoKey  = -1;
    static constexpr int kErrBadArg = -2;
    static constexpr int kErrCrypto = -3;
    static constexpr int kErrAuth   = -4;
    static constexpr int kErrMemory = -6;

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
    // Set the key from an existing 32-byte buffer. Returns kErrBadArg (-2) if
    // the buffer is not exactly 32 bytes.
    int setKey(const std::vector<unsigned char>& key);
    // True once a key has been generated or set.
    bool hasKey() const;
    // Direct (read-only) access to the stored key bytes.
    const std::vector<unsigned char>& getKey() const;

    // ---- encryption / decryption ---------------------------------------
    int encrypt(const std::vector<unsigned char>& plaintext,
                std::vector<unsigned char>& ciphertext) const;
    int decrypt(const std::vector<unsigned char>& ciphertext,
                std::vector<unsigned char>& plaintext) const;

private:
    void clearKey();

    std::vector<unsigned char> key_;
    bool hasKey_;
};

} // namespace ObsidianGuardLite

#endif // OBSIDIAN_GUARD_LITE_AES256_HPP
