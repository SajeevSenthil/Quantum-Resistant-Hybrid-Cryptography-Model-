#include "simulate_lbc.h"

#include <random>
#include <openssl/sha.h>

// Generate random integer vector
static std::vector<int> random_vector(int n, int bound) {
    std::vector<int> v(n);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(-bound, bound);

    for (int i = 0; i < n; i++) {
        v[i] = dist(gen);
    }
    return v;
}

// -------- Simulated LBC Key Generation --------
LBCKeys simulated_lbc_keygen(int n) {
    LBCKeys keys;

    // Simulated lattice vectors
    auto A = random_vector(n, 1000);  // public lattice parameter
    auto s = random_vector(n, 10);    // private key
    auto e = random_vector(n, 3);     // noise

    // Public component: B = A + s + e
    keys.public_component.resize(n);
    for (int i = 0; i < n; i++) {
        keys.public_component[i] = A[i] + s[i] + e[i];
    }

    keys.private_component = s;

    return keys;
}

// -------- Simulated LBC Encapsulation (KEM) --------
// Bob generates a shared secret and encapsulates it for Alice
LBCResult simulated_lbc_encaps(const std::vector<int>& public_key) {
    LBCResult result;
    
    // Simulate "randomness" used for encapsulation
    std::vector<int> b_random = random_vector(public_key.size(), 5);
    
    // Derive shared secret: Hash(Public_Key || Randomness)
    // In LBC, both parties arrive at the same shared secret via math.
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    // Ideally we hash the "noisy shared vector". 
    // For simulation: SharedSecret = Hash(Randomness) 
    for (int v : b_random) SHA256_Update(&ctx, &v, sizeof(v));
    
    result.shared_secret.resize(SHA256_DIGEST_LENGTH);
    SHA256_Final(result.shared_secret.data(), &ctx);

    // Ciphertext is the randomness "masked" by the public key
    result.ciphertext = b_random; 
    
    return result;
}

// -------- Simulated LBC Decapsulation (KEM) --------
// Alice recovers the shared secret using her private key
std::vector<unsigned char> simulated_lbc_decaps(
    const std::vector<int>& ciphertext,
    const std::vector<int>& private_key
) {
    // In real LBC: SharedSecret = Hash( Unmask(Ciphertext, PrivateKey) )
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    // Simulate the mathematical recovery of the randomness
    std::vector<int> recovered_randomness = ciphertext; 
    
    for (int v : recovered_randomness) SHA256_Update(&ctx, &v, sizeof(v));
    
    std::vector<unsigned char> secret(SHA256_DIGEST_LENGTH);
    SHA256_Final(secret.data(), &ctx);
    
    return secret;
}
