#ifndef PERF_ANALYSIS_H
#define PERF_ANALYSIS_H

#include <vector>

// Structure to store performance metrics
struct PerfMetrics {
    double keygen_time_ms;
    double encrypt_time_ms;
    double decrypt_time_ms;
};

// Structure to store Hybrid (PQC + AES) performance metrics
struct PerfMetricsHybrid {
    double kem_keygen_time_ms;   // PQC KeyGen
    double kem_encaps_time_ms;   // PQC Encaps (derives shared secret)
    double kem_decaps_time_ms;   // PQC Decaps (recovers shared secret)
    double aes_encrypt_time_ms;  // AES Encrypt (using shared secret)
    double aes_decrypt_time_ms;  // AES Decrypt (using shared secret)
    size_t total_ciphertext_size;// PQC Encap Ciphertext + AES Ciphertext
};

// Algorithm-1: Performance Evaluation
PerfMetrics performance_analysis(
    const std::vector<unsigned char>& plaintext
);

// Algorithm-2: Hybrid Performance Evaluation
PerfMetricsHybrid performance_analysis_hybrid(
    const std::vector<unsigned char>& plaintext,
    int lattice_dimension
);

#endif
