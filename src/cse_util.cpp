#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <array>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>
#include <map>
#include <iostream>
#include <iomanip>

#include "s3fs_logger.h"
#include "cse_util.h"

namespace CseUtil {

// todo: remove this once debugging is done because it's terribly insecure, don't leak secrets
template<typename Iterator>
void hex_dump(Iterator begin, Iterator end) {
    for (auto it = begin; it != end; ++it) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(*it) << " ";
    }
    std::cout << std::endl;
}

// Helper function for base64 decoding
std::vector<unsigned char>* base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), -1);
    if (!bio) return nullptr;

    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free_all(bio);
        S3FS_PRN_ERR("Failed to create BIO for base64 decoding.");
        return nullptr;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<unsigned char>* decoded = new std::vector<unsigned char>(3 * (encoded.length() / 4));
    int decoded_length = BIO_read(bio, decoded->data(), encoded.length());

    BIO_free_all(bio);

    if (decoded_length < 0) {
        delete decoded;
        S3FS_PRN_ERR("Base64 decoding failed.");
        return nullptr;
    }

    decoded->resize(decoded_length);
    return decoded;
}

std::vector<unsigned char>* decrypt_aes_gcm(
    const std::vector<unsigned char>& key,
    const std::array<unsigned char, AES_GCM_IV_LENGTH>& iv,
    std::array<unsigned char, AES_GCM_TAG_LENGTH>& tag,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>* aad,
    bool padding
) {
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        S3FS_PRN_ERR("Failed to create EVP_CIPHER_CTX.");
        return nullptr;
    }

    const EVP_CIPHER* evp_cipher = nullptr;
    if (key.size() == 16) {
        evp_cipher = EVP_aes_128_gcm(); // AES-128-GCM
    } else if (key.size() == 24) {
        evp_cipher = EVP_aes_192_gcm(); // AES-192-GCM
    } else if (key.size() == 32) {
        evp_cipher = EVP_aes_256_gcm(); // AES-256-GCM
    } else {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Invalid key size for AES-GCM decryption.");
        return nullptr;
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Failed to initialize decryption context.");
        return nullptr;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Failed to set IV length.");
        return nullptr;
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Failed to initialize decryption with key and IV.");
        return nullptr;
    }

    // Set the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Failed to set authentication tag.");
        return nullptr;
    }

    // Set additional authenticated data (AAD)
    if (aad) {
        int aad_len = 0;
        if (EVP_DecryptUpdate(ctx, NULL, &aad_len, aad->data(), aad->size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            S3FS_PRN_ERR("Failed to set AAD.");
            return nullptr;
        }
    }

    if (padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    // Allocate result vector
    std::vector<unsigned char>* result = new std::vector<unsigned char>(ciphertext.size());
    if (!result) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Memory allocation failed for decryption result.");
        return nullptr;
    }

    int len = 0;
    int plaintext_len = 0;

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, result->data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        delete result;
        S3FS_PRN_ERR("Decryption failed during EVP_DecryptUpdate.");
        return nullptr;
    }
    plaintext_len = len;

    // Finalize decryption and verify authentication tag
    if (EVP_DecryptFinal_ex(ctx, result->data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        delete result;
        S3FS_PRN_ERR("Decryption failed during EVP_DecryptFinal_ex.");
        return nullptr;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    result->resize(plaintext_len);
    return result;
}

static std::vector<unsigned char>* cstr_to_vector(const char* str) {
    size_t len = strlen(str);
    std::vector<unsigned char>* vec = new std::vector<unsigned char>(len);
    memcpy(vec->data(), str, len);
    return vec;
}

// Main decryption function - returns pointer to vector or nullptr on error
// Caller is responsible for deleting the returned vector
std::vector<unsigned char>* decrypt_cek(
    const std::string& encrypted_cek_b64,
    const std::vector<unsigned char>& kek
) {
    // Decode base64 encrypted data
    std::vector<unsigned char>* encrypted_cek(base64_decode(encrypted_cek_b64));
    if (!encrypted_cek) {
        S3FS_PRN_ERR("Base64 decoding failed for the CSE CEK.");
        return nullptr;
    }

    // Extract components
    std::array<unsigned char, AES_GCM_IV_LENGTH>iv;
    std::copy(
        encrypted_cek->begin(),
        encrypted_cek->begin() + iv.size(),
        iv.begin()
    );

    std::array<unsigned char, AES_GCM_TAG_LENGTH>tag;
    std::copy(
        encrypted_cek->end() - tag.size(),
        encrypted_cek->end(),
        tag.begin()
    );

    const char* str = "AES/GCM/NoPadding";
    std::vector<unsigned char>* aad = cstr_to_vector(str);

    std::vector<unsigned char>* result = decrypt_aes_gcm(
        kek,
        iv,
        tag,
        std::vector<unsigned char>(encrypted_cek->begin() + iv.size(), encrypted_cek->end() - tag.size()),
        aad,
        false
    );

    delete encrypted_cek;
    delete aad;

    return result;
}

}
