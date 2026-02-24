#ifndef RSA_KEM_H
#define RSA_KEM_H

#include <vector>
#include <string>

// RSA Key Structure (simplified for simulation/demo)
struct RSAKeys {
    std::vector<unsigned char> public_key_der;
    std::vector<unsigned char> private_key_der;
};

// Generate RSA-2048 Key Pair
RSAKeys rsa_keygen(int bits = 2048);

// RSA Encapsulation:
// 1. Generates a random 32-byte shared secret.
// 2. Encrypts it with the RSA public key (OAEP padding).
// Returns pair: {simulated_ciphertext, shared_secret}
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> rsa_encapsulate(
    const std::vector<unsigned char>& public_key_der
);

// RSA Decapsulation:
// 1. Decrypts the ciphertext using RSA private key.
// Returns the shared secret.
std::vector<unsigned char> rsa_decapsulate(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& private_key_der
);

#endif
