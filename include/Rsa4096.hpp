// RSA-4096 asymmetric encryption (OAEP-SHA256).
//
// Encrypt with the public key, decrypt with the private key. Keys are stored in
// standard PEM format. A 4096-bit key can encrypt at most 446 bytes per call
// (OAEP-SHA256 overhead), so use RSA to wrap a symmetric key, not bulk data.
#ifndef OBSIDIAN_GUARD_LITE_RSA4096_HPP
#define OBSIDIAN_GUARD_LITE_RSA4096_HPP

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
#include <string>
#include <vector>

// Forward declaration so the public header does not need OpenSSL includes.
typedef struct evp_pkey_st EVP_PKEY;

namespace ObsidianGuardLite {

class OBSIDIAN_GUARD_LITE_API Rsa4096 {
public:
    static constexpr int kBits = 4096;
    static constexpr std::size_t kModulusSize = kBits / 8;                 // 512 bytes
    static constexpr std::size_t kMaxPlaintext = kModulusSize - 2 * 32 - 2; // 446 bytes

    // Return codes (see README for the full table).
    static constexpr int kOk        = 0;
    static constexpr int kErrNoKey  = -1;
    static constexpr int kErrBadArg = -2;
    static constexpr int kErrCrypto = -3;
    static constexpr int kErrFile   = -5;
    static constexpr int kErrMemory = -6;

    Rsa4096();
    ~Rsa4096();

    // The key is owned exclusively by this object; copying/moving is disabled.
    Rsa4096(const Rsa4096&) = delete;
    Rsa4096& operator=(const Rsa4096&) = delete;
    Rsa4096(Rsa4096&&) = delete;
    Rsa4096& operator=(Rsa4096&&) = delete;

    // ---- key management -------------------------------------------------
    // Generate a new 4096-bit key pair. Returns kOk (0) on success.
    int generateKeyPair();
    // Save/load the public key in PEM format.
    int savePublicKey(const std::string& path) const;
    int loadPublicKey(const std::string& path);
    // Save/load the private key in PEM format (unencrypted).
    int savePrivateKey(const std::string& path) const;
    int loadPrivateKey(const std::string& path);
    // True once a public/private key is available.
    bool hasPublicKey() const;
    bool hasPrivateKey() const;

    // ---- encryption / decryption ---------------------------------------
    int encrypt(const std::vector<unsigned char>& plaintext,
                std::vector<unsigned char>& ciphertext) const;
    int decrypt(const std::vector<unsigned char>& ciphertext,
                std::vector<unsigned char>& plaintext) const;

private:
    void freeKey();

    EVP_PKEY* pkey_;
    bool hasPrivate_;
};

} // namespace ObsidianGuardLite

#endif // OBSIDIAN_GUARD_LITE_RSA4096_HPP
