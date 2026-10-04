// RSA-4096 asymmetric encryption (OAEP-SHA256).
//
// Encrypt with the public key, decrypt with the private key. Keys are stored in
// standard PEM format. A 4096-bit key can encrypt at most 446 bytes per call
// (OAEP-SHA256 overhead), so use RSA to wrap a symmetric key, not bulk data.
//
// Thread safety: every method locks internally, so a single instance may be
// shared freely between threads. Crypto calls take an up-referenced snapshot
// of the key under the lock and run on that snapshot, so concurrent
// generateKeyPair()/load*() calls cannot race; a call either sees the old key
// or the new one, never a torn state.
#ifndef CRYPTO_LITE_RSA4096_HPP
#define CRYPTO_LITE_RSA4096_HPP

// DLL import/export macro (Windows).
#ifndef CRYPTO_LITE_API
    #ifdef CRYPTO_LITE_STATIC
        #define CRYPTO_LITE_API
    #elif defined(CRYPTO_LITE_EXPORTS)
        #define CRYPTO_LITE_API __declspec(dllexport)
    #else
        #define CRYPTO_LITE_API __declspec(dllimport)
    #endif
#endif

#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

// Forward declaration so the public header does not need OpenSSL includes.
typedef struct evp_pkey_st EVP_PKEY;

namespace CryptoLite {

class CRYPTO_LITE_API Rsa4096 {
public:
    static constexpr int kBits = 4096;
    static constexpr std::size_t kModulusSize = kBits / 8;                 // 512 bytes
    static constexpr std::size_t kMaxPlaintext = kModulusSize - 2 * 32 - 2; // 446 bytes

    // Return codes, aligned with Crypto's CryptoErrorCode categories
    // (see README for the full table):
    static constexpr int kOk                = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // bad input / no key available
    static constexpr int kErrOpenSsl        = -2;  // underlying OpenSSL call failed
    static constexpr int kErrAuth           = -3;  // tampered data / wrong key
    static constexpr int kErrUnavailable    = -4;  // algorithm unavailable at runtime
    static constexpr int kErrInternal       = -5;  // unexpected internal failure
    static constexpr int kErrFile           = -6;  // file I/O error (Lite-only extension)

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
    mutable std::mutex mutex_;  // guards pkey_ and hasPrivate_

    EVP_PKEY* pkey_;
    bool hasPrivate_;
};

} // namespace CryptoLite

#endif // CRYPTO_LITE_RSA4096_HPP
