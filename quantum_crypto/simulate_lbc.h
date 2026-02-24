#ifndef SIMULATED_LBC_H
#define SIMULATED_LBC_H

#include <vector>

// Simulated lattice key structure
struct LBCKeys {
    std::vector<int> public_component;
    std::vector<int> private_component;
};

// Simulated lattice-based key generation
LBCKeys simulated_lbc_keygen(int n);

struct LBCResult {
    std::vector<unsigned char> shared_secret;
    std::vector<int> ciphertext; // Simulated ciphertext
};

// Simulated Key Encapsulation (Bob uses Alice's Public Key)
LBCResult simulated_lbc_encaps(const std::vector<int>& public_key);

// Simulated Key Decapsulation (Alice uses her Private Key & Ciphertext)
std::vector<unsigned char> simulated_lbc_decaps(
    const std::vector<int>& ciphertext,
    const std::vector<int>& private_key
);

#endif
