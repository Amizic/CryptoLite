#include "Rsa4096.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace ObsidianGuardLite {

Rsa4096::Rsa4096() : pkey_(nullptr), hasPrivate_(false) {}

Rsa4096::~Rsa4096() {
    freeKey();
}

void Rsa4096::freeKey() {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
    hasPrivate_ = false;
}

int Rsa4096::generateKeyPair() {
    freeKey();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr) {
        return kErrMemory;
    }

    int rc = kErrCrypto;
    do {
        if (EVP_PKEY_keygen_init(ctx) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, kBits) != 1) {
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

int Rsa4096::savePublicKey(const std::string& path) const {
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

int Rsa4096::savePrivateKey(const std::string& path) const {
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

int Rsa4096::loadPublicKey(const std::string& path) {
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

int Rsa4096::loadPrivateKey(const std::string& path) {
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

bool Rsa4096::hasPublicKey() const {
    return pkey_ != nullptr;
}

bool Rsa4096::hasPrivateKey() const {
    return hasPrivate_;
}

int Rsa4096::encrypt(const std::vector<unsigned char>& plaintext,
                     std::vector<unsigned char>& ciphertext) const {
    ciphertext.clear();
    if (pkey_ == nullptr) {
        return kErrNoKey;
    }
    if (plaintext.empty() || plaintext.size() > kMaxPlaintext) {
        return kErrBadArg;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
    if (ctx == nullptr) {
        return kErrMemory;
    }

    int rc = kErrCrypto;
    std::size_t outLen = 0;
    do {
        if (EVP_PKEY_encrypt_init(ctx) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1) {
            break;
        }
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen,
                             plaintext.data(), plaintext.size()) != 1) {
            break;
        }
        ciphertext.resize(outLen);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outLen,
                             plaintext.data(), plaintext.size()) != 1) {
            break;
        }
        ciphertext.resize(outLen);
        rc = kOk;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    if (rc != kOk) {
        ciphertext.clear();
    }
    return rc;
}

int Rsa4096::decrypt(const std::vector<unsigned char>& ciphertext,
                     std::vector<unsigned char>& plaintext) const {
    plaintext.clear();
    if (pkey_ == nullptr || !hasPrivate_) {
        return kErrNoKey;
    }
    if (ciphertext.size() != kModulusSize) {
        return kErrBadArg;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
    if (ctx == nullptr) {
        return kErrMemory;
    }

    int rc = kErrCrypto;
    std::size_t outLen = 0;
    do {
        if (EVP_PKEY_decrypt_init(ctx) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) {
            break;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1) {
            break;
        }
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen,
                             ciphertext.data(), ciphertext.size()) != 1) {
            break;
        }
        plaintext.resize(outLen);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outLen,
                             ciphertext.data(), ciphertext.size()) != 1) {
            break;
        }
        plaintext.resize(outLen);
        rc = kOk;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    if (rc != kOk) {
        plaintext.clear();
    }
    return rc;
}

} // namespace ObsidianGuardLite
