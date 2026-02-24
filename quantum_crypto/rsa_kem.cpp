#include "rsa_kem.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <vector>

// Helper: Get OpenSSL Error string
static std::string get_openssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

// Helper: Convert EVP_PKEY to DER vector
static std::vector<unsigned char> pkey_to_der(EVP_PKEY* pkey, bool is_private) {
    unsigned char* buf = nullptr;
    int len = 0;
    
    if (is_private)
        len = i2d_PrivateKey(pkey, &buf);
    else
        len = i2d_PublicKey(pkey, &buf);

    if (len <= 0) {
        throw std::runtime_error("Key serialization failed: " + get_openssl_error());
    }

    std::vector<unsigned char> der(buf, buf + len);
    OPENSSL_free(buf);
    return der;
}

// Helper: Convert DER vector to EVP_PKEY
static EVP_PKEY* der_to_pkey(const std::vector<unsigned char>& der, bool is_private) {
    const unsigned char* p = der.data();
    EVP_PKEY* pkey = nullptr;

    if (is_private)
        pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, der.size());
    else
        pkey = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, der.size());

    if (!pkey) {
        throw std::runtime_error("Key deserialization failed: " + get_openssl_error());
    }
    return pkey;
}

// RSA Key Generation (2048-bit)
RSAKeys rsa_keygen(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("Context creation failed");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Keygen init failed");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Set bits failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Keygen failed: " + get_openssl_error());
    }

    RSAKeys keys;
    keys.public_key_der = pkey_to_der(pkey, false);
    keys.private_key_der = pkey_to_der(pkey, true);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return keys;
}

// RSA Encapsulation (OAEP Encryption of a Random Key)
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> rsa_encapsulate(
    const std::vector<unsigned char>& public_key_der
) {
    // 1. Generate Shared Secret (32 bytes for AES-256)
    std::vector<unsigned char> shared_secret(32);
    if (RAND_bytes(shared_secret.data(), shared_secret.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    // 2. Load Public Key
    EVP_PKEY* pkey = der_to_pkey(public_key_der, false);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Context creation failed");
    }

    // 3. Encrypt Shared Secret (OAEP)
    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encryption init failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, shared_secret.data(), shared_secret.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encryption size check failed");
    }

    std::vector<unsigned char> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, shared_secret.data(), shared_secret.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encryption failed: " + get_openssl_error());
    }

    ciphertext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return {ciphertext, shared_secret};
}

// RSA Decapsulation (OAEP Decryption)
std::vector<unsigned char> rsa_decapsulate(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& private_key_der
) {
    // 1. Load Private Key
    EVP_PKEY* pkey = der_to_pkey(private_key_der, true);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Context creation failed");
    }

    // 2. Decrypt Ciphertext (OAEP)
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decryption init failed");
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decryption size check failed");
    }

    std::vector<unsigned char> shared_secret(outlen);
    if (EVP_PKEY_decrypt(ctx, shared_secret.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Decryption failed: " + get_openssl_error());
    }

    shared_secret.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return shared_secret;
}
