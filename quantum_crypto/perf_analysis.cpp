#include "perf_analysis.h"
#include "aes.h"

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
