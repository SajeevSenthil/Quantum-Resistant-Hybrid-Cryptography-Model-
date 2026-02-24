#ifndef PQC_HYBRID_H
#define PQC_HYBRID_H

#include <vector>
#include <string>
#include <utility>
#include <cstdint>

// Structure to hold PQC keys (Kyber-768)
struct PQCKeys {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

// Functions wrapping liboqs for Kyber-768
PQCKeys pqc_keygen();

// Returns {ciphertext, shared_secret}
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pqc_encapsulate(
    const std::vector<uint8_t>& public_key
);

// Returns {shared_secret}
std::vector<uint8_t> pqc_decapsulate(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& private_key
);

#endif
