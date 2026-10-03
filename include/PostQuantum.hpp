// Post-quantum hybrid encryption: ML-KEM-768 (Kyber) + AES-256-GCM.
//
// encrypt(): run an ML-KEM-768 key encapsulation to establish a shared secret,
//            then AES-256-GCM encrypt the message with that secret.
// decrypt(): decapsulate to recover the secret, then AES-256-GCM decrypt.
//
// Ciphertext layout (binary):
//   [ 4-byte little-endian KEM ciphertext length ][ KEM ciphertext ]
//   [ AES-256-GCM ciphertext: 12-byte IV ][ data ][ 16-byte tag ]
//
// Requires OpenSSL 3.5.0 or newer. Keys are stored in standard PEM format.
#ifndef OBSIDIAN_GUARD_LITE_POSTQUANTUM_HPP
#define OBSIDIAN_GUARD_LITE_POSTQUANTUM_HPP

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

class OBSIDIAN_GUARD_LITE_API PostQuantum {
public:
    // The ML-KEM parameter set (NIST security category 3).
    static constexpr const char* kAlgorithm = "ML-KEM-768";

    // Return codes (see README for the full table).
    static constexpr int kOk        = 0;
    static constexpr int kErrNoKey  = -1;
    static constexpr int kErrBadArg = -2;
    static constexpr int kErrCrypto = -3;
    static constexpr int kErrAuth   = -4;
    static constexpr int kErrFile   = -5;
    static constexpr int kErrMemory = -6;

    PostQuantum();
    ~PostQuantum();

    // The key is owned exclusively by this object; copying/moving is disabled.
    PostQuantum(const PostQuantum&) = delete;
    PostQuantum& operator=(const PostQuantum&) = delete;
    PostQuantum(PostQuantum&&) = delete;
    PostQuantum& operator=(PostQuantum&&) = delete;

    // ---- key management -------------------------------------------------
    // Generate a new ML-KEM-768 key pair. Returns kOk (0) on success.
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

#endif // OBSIDIAN_GUARD_LITE_POSTQUANTUM_HPP
