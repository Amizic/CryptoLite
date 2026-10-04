// CryptoLite - src/Sha256.cpp
// One-shot SHA-256 / SHA-512 hashing.

#include "Sha256.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <vector>

namespace CryptoLite {
namespace {

int digestMessage(const std::vector<uint8_t>& message, const EVP_MD* algorithm,
                  std::vector<uint8_t>& digest) noexcept {
    ERR_clear_error();
    digest.clear();

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        return Sha256::kErrOpenSsl;
    }

    int rc = Sha256::kErrOpenSsl;
    do {
        if (EVP_DigestInit_ex(context, algorithm, nullptr) != 1) {
            break;
        }
        if (!message.empty() &&
            EVP_DigestUpdate(context, message.data(), message.size()) != 1) {
            break;
        }
        digest.resize(EVP_MAX_MD_SIZE);
        unsigned int digestLength = 0;
        if (EVP_DigestFinal_ex(context, digest.data(), &digestLength) != 1) {
            break;
        }
        digest.resize(digestLength);
        rc = Sha256::kOk;
    } while (false);

    EVP_MD_CTX_free(context);
    if (rc != Sha256::kOk) {
        digest.clear();  // no partial digest escapes on failure
    }
    return rc;
}

} // namespace

const char* Sha256::algorithmName() const noexcept {
    return "SHA-256 / SHA-512";
}

int Sha256::hash(const std::vector<uint8_t>& message,
                 std::vector<uint8_t>& digest) noexcept {
    return digestMessage(message, EVP_sha256(), digest);
}

int Sha256::hash512(const std::vector<uint8_t>& message,
                    std::vector<uint8_t>& digest) noexcept {
    return digestMessage(message, EVP_sha512(), digest);
}

} // namespace CryptoLite
