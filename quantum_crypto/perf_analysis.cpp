#include "perf_analysis.h"
#include "aes.h"
#include "simulate_lbc.h"

#include <openssl/rand.h>
#include <chrono>

// -------- Algorithm 1: Performance Evaluation --------
PerfMetrics performance_analysis(
    const std::vector<unsigned char>& plaintext
) {
    PerfMetrics metrics;

    // ---- Key generation timing ----
    auto keygen_start = std::chrono::high_resolution_clock::now();

    std::vector<unsigned char> key(32); // AES-256
    std::vector<unsigned char> iv(16);  // AES block size
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    auto keygen_end = std::chrono::high_resolution_clock::now();
    metrics.keygen_time_ms =
        std::chrono::duration<double, std::milli>(
            keygen_end - keygen_start
        ).count();

    // ---- Encryption timing ----
    auto enc_start = std::chrono::high_resolution_clock::now();
    auto ciphertext = aes_encrypt(plaintext, key, iv);
    auto enc_end = std::chrono::high_resolution_clock::now();
    metrics.encrypt_time_ms =
        std::chrono::duration<double, std::milli>(
            enc_end - enc_start
        ).count();

    // ---- Decryption timing ----
    auto dec_start = std::chrono::high_resolution_clock::now();
    auto decrypted = aes_decrypt(ciphertext, key, iv);
    auto dec_end = std::chrono::high_resolution_clock::now();
    metrics.decrypt_time_ms =
        std::chrono::duration<double, std::milli>(
            dec_end - dec_start
        ).count();

    return metrics;
}

// -------- Algorithm 2: Hybrid Performance Evaluation --------
PerfMetricsHybrid performance_analysis_hybrid(
    const std::vector<unsigned char>& plaintext,
    int lattice_dimension
) {
    PerfMetricsHybrid metrics;
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), iv.size());

    // 1. PQC Key Generation (Alice)
    auto kem_gen_start = std::chrono::high_resolution_clock::now();
    LBCKeys alice_keys = simulated_lbc_keygen(lattice_dimension);
    auto kem_gen_end = std::chrono::high_resolution_clock::now();
    metrics.kem_keygen_time_ms = 
        std::chrono::duration<double, std::milli>(kem_gen_end - kem_gen_start).count();

    // 2. PQC Encapsulation (Bob)
    // Bob uses Alice's public key to generate a shared secret and a ciphertext
    auto kem_enc_start = std::chrono::high_resolution_clock::now();
    LBCResult bob_result = simulated_lbc_encaps(alice_keys.public_component);
    auto kem_enc_end = std::chrono::high_resolution_clock::now();
    metrics.kem_encaps_time_ms = 
        std::chrono::duration<double, std::milli>(kem_enc_end - kem_enc_start).count();

    // The shared secret is used as the AES key
    std::vector<unsigned char> aes_key = bob_result.shared_secret;

    // 3. AES Encryption (Bob)
    // Bob encrypts the actual data using the shared secret
    auto aes_enc_start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> aes_ciphertext = aes_encrypt(plaintext, aes_key, iv);
    auto aes_enc_end = std::chrono::high_resolution_clock::now();
    metrics.aes_encrypt_time_ms = 
        std::chrono::duration<double, std::milli>(aes_enc_end - aes_enc_start).count();

    // Total transmitted size = PQC Ciphertext size (raw vector size * sizeof int) + AES Ciphertext size
    metrics.total_ciphertext_size = 
        (bob_result.ciphertext.size() * sizeof(int)) + aes_ciphertext.size();

    // 4. PQC Decapsulation (Alice)
    // Alice receives the PQC Ciphertext and uses her Private Key to recover the Shared Secret
    auto kem_dec_start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> recovered_secret = 
        simulated_lbc_decaps(bob_result.ciphertext, alice_keys.private_component);
    auto kem_dec_end = std::chrono::high_resolution_clock::now();
    metrics.kem_decaps_time_ms = 
        std::chrono::duration<double, std::milli>(kem_dec_end - kem_dec_start).count();

    // 5. AES Decryption (Alice)
    // Alice decodes the message using the recovered secret
    auto aes_dec_start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> decrypted_text = aes_decrypt(aes_ciphertext, recovered_secret, iv);
    auto aes_dec_end = std::chrono::high_resolution_clock::now();
    metrics.aes_decrypt_time_ms = 
        std::chrono::duration<double, std::milli>(aes_dec_end - aes_dec_start).count();

    return metrics;
}
