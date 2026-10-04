#include "Rsa4096.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <memory>
#include <mutex>

namespace CryptoLite {
namespace {

struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept {
        EVP_PKEY_free(p);
    }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

} // namespace

Rsa4096::Rsa4096() : pkey_(nullptr), hasPrivate_(false) {}

Rsa4096::~Rsa4096() {
    // No locking: no member function may run concurrently with destruction.
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
    hasPrivate_ = false;
}

int Rsa4096::generateKeyPair() {
    // Key generation is slow: do it OUTSIDE the lock, then swap atomically.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr) {
        return kErrOpenSsl;
    }

    PkeyPtr newKey;
    int rc = kErrOpenSsl;
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
        newKey.reset(pkey);
        rc = kOk;
    } while (false);
    EVP_PKEY_CTX_free(ctx);
    if (rc != kOk) {
        return rc;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    EVP_PKEY_free(pkey_);
    pkey_ = newKey.release();
    hasPrivate_ = true;
    return kOk;
}

int Rsa4096::savePublicKey(const std::string& path) const {
    PkeyPtr snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pkey_ == nullptr) {
            return kErrInvalidArgument;
        }
        if (EVP_PKEY_up_ref(pkey_) != 1) {
            return kErrInternal;
        }
        snapshot.reset(pkey_);
    }

    BIO* bio = BIO_new_file(path.c_str(), "wb");
    if (bio == nullptr) {
        return kErrFile;
    }
    const int rc = (PEM_write_bio_PUBKEY(bio, snapshot.get()) == 1) ? kOk : kErrFile;
    BIO_free(bio);
    return rc;
}

int Rsa4096::savePrivateKey(const std::string& path) const {
    PkeyPtr snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pkey_ == nullptr || !hasPrivate_) {
            return kErrInvalidArgument;
        }
        if (EVP_PKEY_up_ref(pkey_) != 1) {
            return kErrInternal;
        }
        snapshot.reset(pkey_);
    }

    BIO* bio = BIO_new_file(path.c_str(), "wb");
    if (bio == nullptr) {
        return kErrFile;
    }
    const int rc = (PEM_write_bio_PrivateKey(bio, snapshot.get(), nullptr,
                                             nullptr, 0, nullptr, nullptr) == 1)
                       ? kOk
                       : kErrFile;
    BIO_free(bio);
    return rc;
}

int Rsa4096::loadPublicKey(const std::string& path) {
    // Parsing is done outside the lock; only the pointer swap is locked.
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (bio == nullptr) {
        return kErrFile;
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (pkey == nullptr) {
        return kErrFile;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    EVP_PKEY_free(pkey_);
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

    std::lock_guard<std::mutex> lock(mutex_);
    EVP_PKEY_free(pkey_);
    pkey_ = pkey;
    hasPrivate_ = true;
    return kOk;
}

bool Rsa4096::hasPublicKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pkey_ != nullptr;
}

bool Rsa4096::hasPrivateKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hasPrivate_;
}

int Rsa4096::encrypt(const std::vector<unsigned char>& plaintext,
                     std::vector<unsigned char>& ciphertext) const {
    ciphertext.clear();

    // Up-referenced snapshot: the key stays alive and immutable even if a
    // concurrent generateKeyPair()/load*() replaces the instance's pointer.
    PkeyPtr key;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pkey_ == nullptr) {
            return kErrInvalidArgument;
        }
        if (EVP_PKEY_up_ref(pkey_) != 1) {
            return kErrInternal;
        }
        key.reset(pkey_);
    }

    if (plaintext.empty() || plaintext.size() > kMaxPlaintext) {
        return kErrInvalidArgument;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key.get(), nullptr);
    if (ctx == nullptr) {
        return kErrOpenSsl;
    }

    int rc = kErrOpenSsl;
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

    PkeyPtr key;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pkey_ == nullptr || !hasPrivate_) {
            return kErrInvalidArgument;
        }
        if (EVP_PKEY_up_ref(pkey_) != 1) {
            return kErrInternal;
        }
        key.reset(pkey_);
    }

    if (ciphertext.size() != kModulusSize) {
        return kErrInvalidArgument;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key.get(), nullptr);
    if (ctx == nullptr) {
        return kErrOpenSsl;
    }

    int rc = kErrOpenSsl;
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

} // namespace CryptoLite
