#include "Aes256.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace ObsidianGuardLite {

Aes256::Aes256() : key_(kKeySize, 0), hasKey_(false) {}

Aes256::~Aes256() {
    clearKey();
}

void Aes256::clearKey() {
    if (!key_.empty()) {
        OPENSSL_cleanse(key_.data(), key_.size());
    }
    key_.assign(kKeySize, 0);
    hasKey_ = false;
}

int Aes256::generateKey() {
    if (RAND_bytes(key_.data(), static_cast<int>(kKeySize)) != 1) {
        clearKey();
        return kErrCrypto;
    }
    hasKey_ = true;
    return kOk;
}

int Aes256::setKey(const std::vector<unsigned char>& key) {
    if (key.size() != kKeySize) {
        return kErrBadArg;
    }
    key_ = key;
    hasKey_ = true;
    return kOk;
}

bool Aes256::hasKey() const {
    return hasKey_;
}

const std::vector<unsigned char>& Aes256::getKey() const {
    return key_;
}

int Aes256::encrypt(const std::vector<unsigned char>& plaintext,
                    std::vector<unsigned char>& ciphertext) const {
    ciphertext.clear();
    if (!hasKey_) {
        return kErrNoKey;
    }

    std::vector<unsigned char> iv(kIvSize, 0);
    if (RAND_bytes(iv.data(), static_cast<int>(kIvSize)) != 1) {
        return kErrCrypto;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return kErrMemory;
    }

    std::vector<unsigned char> ct(plaintext.size() + kTagSize, 0);
    std::vector<unsigned char> tag(kTagSize, 0);
    int outLen = 0;
    int finalLen = 0;
    int rc = kErrCrypto;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(kIvSize), nullptr) != 1) {
            break;
        }
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv.data()) != 1) {
            break;
        }
        if (!plaintext.empty() &&
            EVP_EncryptUpdate(ctx, ct.data(), &outLen, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1) {
            break;
        }
        if (EVP_EncryptFinal_ex(ctx, ct.data() + outLen, &finalLen) != 1) {
            break;
        }
        outLen += finalLen;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(kTagSize), tag.data()) != 1) {
            break;
        }
        ct.resize(static_cast<std::size_t>(outLen));

        ciphertext.reserve(kIvSize + ct.size() + kTagSize);
        ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());
        ciphertext.insert(ciphertext.end(), ct.begin(), ct.end());
        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        rc = kOk;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (rc != kOk) {
        ciphertext.clear();
    }
    return rc;
}

int Aes256::decrypt(const std::vector<unsigned char>& ciphertext,
                    std::vector<unsigned char>& plaintext) const {
    plaintext.clear();
    if (!hasKey_) {
        return kErrNoKey;
    }
    if (ciphertext.size() < kIvSize + kTagSize) {
        return kErrBadArg;
    }

    const unsigned char* iv = ciphertext.data();
    const unsigned char* tag = ciphertext.data() + ciphertext.size() - kTagSize;
    const unsigned char* ct = ciphertext.data() + kIvSize;
    const std::size_t ctLen = ciphertext.size() - kIvSize - kTagSize;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return kErrMemory;
    }

    std::vector<unsigned char> out(ctLen + kTagSize, 0);
    int outLen = 0;
    int finalLen = 0;
    int rc = kErrCrypto;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(kIvSize), nullptr) != 1) {
            break;
        }
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv) != 1) {
            break;
        }
        if (ctLen > 0 &&
            EVP_DecryptUpdate(ctx, out.data(), &outLen, ct,
                              static_cast<int>(ctLen)) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                static_cast<int>(kTagSize),
                                const_cast<unsigned char*>(tag)) != 1) {
            break;
        }
        if (EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
            rc = kErrAuth; // tag mismatch / corrupted data
            break;
        }
        outLen += finalLen;
        plaintext.assign(out.begin(), out.begin() + outLen);
        rc = kOk;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (rc != kOk) {
        plaintext.clear();
    }
    return rc;
}

} // namespace ObsidianGuardLite
