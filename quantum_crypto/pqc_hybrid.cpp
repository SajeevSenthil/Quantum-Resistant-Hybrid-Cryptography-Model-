#include "pqc_hybrid.h"
#include <oqs/oqs.h>
#include <stdexcept>
#include <iostream>

// Use ML-KEM-768 (Kyber-768 standard)
static const char* OQS_ALG_NAME = OQS_KEM_alg_kyber_768;

// Function to handle cleanup on errors (RAII wrapper would be better, but C-style for now)
void cleanup_kem(OQS_KEM* kem) {
    if (kem) OQS_KEM_free(kem);
}

PQCKeys pqc_keygen() {
    PQCKeys keys;
    OQS_KEM* kem = OQS_KEM_new(OQS_ALG_NAME);
    if (!kem) throw std::runtime_error("OQS_KEM_new failed");

    keys.public_key.resize(kem->length_public_key);
    keys.private_key.resize(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, keys.public_key.data(), keys.private_key.data()) != OQS_SUCCESS) {
        cleanup_kem(kem);
        throw std::runtime_error("OQS_KEM_keypair failed");
    }

    cleanup_kem(kem);
    return keys;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pqc_encapsulate(
    const std::vector<uint8_t>& public_key
) {
    OQS_KEM* kem = OQS_KEM_new(OQS_ALG_NAME);
    if (!kem) throw std::runtime_error("OQS_KEM_new failed");

    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(), public_key.data()) != OQS_SUCCESS) {
        cleanup_kem(kem);
        throw std::runtime_error("OQS_KEM_encaps failed");
    }

    cleanup_kem(kem);
    return {ciphertext, shared_secret};
}

std::vector<uint8_t> pqc_decapsulate(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& private_key
) {
    OQS_KEM* kem = OQS_KEM_new(OQS_ALG_NAME);
    if (!kem) throw std::runtime_error("OQS_KEM_new failed");

    std::vector<uint8_t> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), private_key.data()) != OQS_SUCCESS) {
        cleanup_kem(kem);
        throw std::runtime_error("OQS_KEM_decaps failed");
    }

    cleanup_kem(kem);
    return shared_secret;
}

