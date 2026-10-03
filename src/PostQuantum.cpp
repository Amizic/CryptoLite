#include "PostQuantum.hpp"

#include "Aes256.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdint>

// ML-KEM (and the EVP_PKEY_encapsulate/decapsulate API) require OpenSSL 3.5.
#if OPENSSL_VERSION_NUMBER < 0x30500000L
    #error "PostQuantum requires OpenSSL 3.5.0 or newer for ML-KEM support."
#endif

namespace ObsidianGuardLite {

PostQuantum::PostQuantum() : pkey_(nullptr), hasPrivate_(false) {}

PostQuantum::~PostQuantum() {
    freeKey();
}

void PostQuantum::freeKey() {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
    hasPrivate_ = false;
}

int PostQuantum::generateKeyPair() {
    freeKey();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, kAlgorithm, nullptr);
    if (ctx == nullptr) {
        return kErrMemory;
    }

    int rc = kErrCrypto;
    do {
        if (EVP_PKEY_keygen_init(ctx) != 1) {
            break;
        }
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            break;
        }
        pkey_ = pkey;
        hasPrivate_ = true;
        rc = kOk;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int PostQuantum::savePublicKey(const std::string& path) const {
    if (pkey_ == nullptr) {
        return kErrNoKey;
    }
    BIO* bio = BIO_new_file(path.c_str(), "wb");
    if (bio == nullptr) {
        return kErrFile;
    }
    const int rc = (PEM_write_bio_PUBKEY(bio, pkey_) == 1) ? kOk : kErrFile;
    BIO_free(bio);
    return rc;
}

int PostQuantum::savePrivateKey(const std::string& path) const {
    if (pkey_ == nullptr) {
        return kErrNoKey;
    }
    BIO* bio = BIO_new_file(path.c_str(), "wb");
    if (bio == nullptr) {
        return kErrFile;
    }
    const int rc = (PEM_write_bio_PrivateKey(bio, pkey_, nullptr,
                                             nullptr, 0, nullptr, nullptr) == 1)
                       ? kOk
                       : kErrFile;
    BIO_free(bio);
    return rc;
}

int PostQuantum::loadPublicKey(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (bio == nullptr) {
        return kErrFile;
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (pkey == nullptr) {
        return kErrFile;
    }
    freeKey();
    pkey_ = pkey;
    hasPrivate_ = false;
    return kOk;
}

int PostQuantum::loadPrivateKey(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (bio == nullptr) {
        return kErrFile;
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (pkey == nullptr) {
        return kErrFile;
    }
    freeKey();
    pkey_ = pkey;
    hasPrivate_ = true;
    return kOk;
}

bool PostQuantum::hasPublicKey() const {
    return pkey_ != nullptr;
}

bool PostQuantum::hasPrivateKey() const {
    return hasPrivate_;
}

int PostQuantum::encrypt(const std::vector<unsigned char>& plaintext,
                         std::vector<unsigned char>& ciphertext) const {
    ciphertext.clear();
    if (pkey_ == nullptr) {
        return kErrNoKey;
    }

    // 1. Encapsulate: produce a KEM ciphertext and a 32-byte shared secret.
    std::vector<unsigned char> kemCt;
    std::vector<unsigned char> secret;
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (ctx == nullptr) {
            return kErrMemory;
        }
        std::size_t ctLen = 0;
        std::size_t secretLen = 0;
        int rc = kErrCrypto;
        do {
            if (EVP_PKEY_encapsulate_init(ctx, nullptr) != 1) {
                break;
            }
            if (EVP_PKEY_encapsulate(ctx, nullptr, &ctLen, nullptr, &secretLen) != 1) {
                break;
            }
            kemCt.resize(ctLen);
            secret.resize(secretLen);
            if (EVP_PKEY_encapsulate(ctx, kemCt.data(), &ctLen,
                                     secret.data(), &secretLen) != 1) {
                break;
            }
            kemCt.resize(ctLen);
            secret.resize(secretLen);
            rc = kOk;
        } while (false);
        EVP_PKEY_CTX_free(ctx);
        if (rc != kOk) {
            return rc;
        }
    }

    // 2. Encrypt the message with the shared secret (AES-256-GCM).
    std::vector<unsigned char> sym;
    Aes256 aes;
    int rc = aes.setKey(secret);
    OPENSSL_cleanse(secret.data(), secret.size());
    if (rc != kOk) {
        return rc;
    }
    rc = aes.encrypt(plaintext, sym);
    if (rc != kOk) {
        return rc;
    }

    // 3. Assemble: [4-byte KEM length][KEM ciphertext][AES ciphertext].
    const std::uint32_t kemLen = static_cast<std::uint32_t>(kemCt.size());
    ciphertext.reserve(4 + kemCt.size() + sym.size());
    for (int i = 0; i < 4; ++i) {
        ciphertext.push_back(static_cast<unsigned char>((kemLen >> (8 * i)) & 0xFF));
    }
    ciphertext.insert(ciphertext.end(), kemCt.begin(), kemCt.end());
    ciphertext.insert(ciphertext.end(), sym.begin(), sym.end());
    return kOk;
}

int PostQuantum::decrypt(const std::vector<unsigned char>& ciphertext,
                         std::vector<unsigned char>& plaintext) const {
    plaintext.clear();
    if (pkey_ == nullptr || !hasPrivate_) {
        return kErrNoKey;
    }
    if (ciphertext.size() < 4 + Aes256::kIvSize + Aes256::kTagSize) {
        return kErrBadArg;
    }

    // 1. Parse: [4-byte KEM length][KEM ciphertext][AES ciphertext].
    std::uint32_t kemLen = 0;
    for (int i = 0; i < 4; ++i) {
        kemLen |= static_cast<std::uint32_t>(ciphertext[i]) << (8 * i);
    }
    if (ciphertext.size() < 4 + kemLen + Aes256::kIvSize + Aes256::kTagSize) {
        return kErrBadArg;
    }
    std::vector<unsigned char> kemCt(ciphertext.begin() + 4,
                                     ciphertext.begin() + 4 + kemLen);
    std::vector<unsigned char> sym(ciphertext.begin() + 4 + kemLen,
                                   ciphertext.end());

    // 2. Decapsulate to recover the shared secret.
    std::vector<unsigned char> secret;
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (ctx == nullptr) {
            return kErrMemory;
        }
        std::size_t secretLen = 0;
        int rc = kErrCrypto;
        do {
            if (EVP_PKEY_decapsulate_init(ctx, nullptr) != 1) {
                break;
            }
            if (EVP_PKEY_decapsulate(ctx, nullptr, &secretLen,
                                     kemCt.data(), kemCt.size()) != 1) {
                break;
            }
            secret.resize(secretLen);
            if (EVP_PKEY_decapsulate(ctx, secret.data(), &secretLen,
                                     kemCt.data(), kemCt.size()) != 1) {
                break;
            }
            secret.resize(secretLen);
            rc = kOk;
        } while (false);
        EVP_PKEY_CTX_free(ctx);
        if (rc != kOk) {
            return rc;
        }
    }

    // 3. Decrypt with the shared secret (AES-256-GCM).
    Aes256 aes;
    int rc = aes.setKey(secret);
    OPENSSL_cleanse(secret.data(), secret.size());
    if (rc != kOk) {
        return rc;
    }
    return aes.decrypt(sym, plaintext);
}

} // namespace ObsidianGuardLite
