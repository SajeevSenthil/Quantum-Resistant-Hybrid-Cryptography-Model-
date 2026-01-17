#ifndef AES_H
#define AES_H

#include <vector>

// Encrypt plaintext using AES-256
std::vector<unsigned char> aes_encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv
);

// Decrypt ciphertext using AES-256
std::vector<unsigned char> aes_decrypt(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv
);

#endif
