#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>

#include "aes.h"
#include "perf_analysis.h"
#include "simulate_lbc.h"
#include "rsa_kem.h"
#include "pqc_hybrid.h"

// -------- File reader --------
std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Unable to open input file");

    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

int main() {
    try {
        std::vector<std::string> input_files = {
            "input_10KB.txt",
            "input_10MB.txt",
            "input_100MB.txt"
        };

        std::cout << "=== Performance Evaluation (Algorithm 1: AES) ===\n";

        // ---------- AES PERFORMANCE ----------
        for (const auto& file : input_files) {
            auto plaintext = read_file(file);
            auto metrics = performance_analysis(plaintext);

            std::cout << "\nFile: " << file << std::endl;
            std::cout << "Input size (bytes): " << plaintext.size() << std::endl;
            std::cout << "Key generation time (ms): "
                      << metrics.keygen_time_ms << std::endl;
            std::cout << "Encryption time (ms): "
                      << metrics.encrypt_time_ms << std::endl;
            std::cout << "Decryption time (ms): "
                      << metrics.decrypt_time_ms << std::endl;
        }

        // ---------- SIMULATED LBC PERFORMANCE ----------
        std::cout << "\n=== Performance Evaluation (Algorithm 2: Classical RSA-2048 Hybrid) ===\n";

        auto rsa_keygen_start = std::chrono::high_resolution_clock::now();
        auto rsa_keys = rsa_keygen(2048);
        auto rsa_keygen_end = std::chrono::high_resolution_clock::now();

        auto rsa_encaps_start = std::chrono::high_resolution_clock::now();
        auto rsa_capsule = rsa_encapsulate(rsa_keys.public_key_der);
        auto rsa_encaps_end = std::chrono::high_resolution_clock::now();

        auto rsa_decaps_start = std::chrono::high_resolution_clock::now();
        auto rsa_secret = rsa_decapsulate(rsa_capsule.first, rsa_keys.private_key_der);
        auto rsa_decaps_end = std::chrono::high_resolution_clock::now();

        double rsa_keygen_time =
            std::chrono::duration<double, std::milli>(
                rsa_keygen_end - rsa_keygen_start
            ).count();

        double rsa_encaps_time =
            std::chrono::duration<double, std::milli>(
                rsa_encaps_end - rsa_encaps_start
            ).count();

        double rsa_decaps_time =
            std::chrono::duration<double, std::milli>(
                rsa_decaps_end - rsa_decaps_start
            ).count();

        std::cout << "RSA Key generation time (ms): "
                  << rsa_keygen_time << std::endl;
        std::cout << "RSA Encapsulation time (ms): "
                  << rsa_encaps_time << std::endl;
        std::cout << "RSA Decapsulation time (ms): "
                  << rsa_decaps_time << std::endl;
        std::cout << "Shared secret size (bytes): "
                  << rsa_secret.size() << std::endl;

        std::cout << "\n=== Performance Evaluation (Algorithm 3: Simulated LBC) ===\n";

        int n = 512; // lattice dimension (security parameter)

        auto lbc_keygen_start = std::chrono::high_resolution_clock::now();
        auto lbc_keys = simulated_lbc_keygen(n);
        auto lbc_keygen_end = std::chrono::high_resolution_clock::now();

        auto lbc_encaps_start = std::chrono::high_resolution_clock::now();
        auto lbc_result = simulated_lbc_encaps(lbc_keys.public_component);
        auto lbc_encaps_end = std::chrono::high_resolution_clock::now();

        double keygen_time_lbc =
            std::chrono::duration<double, std::milli>(
                lbc_keygen_end - lbc_keygen_start
            ).count();

        double encaps_time_lbc =
            std::chrono::duration<double, std::milli>(
                lbc_encaps_end - lbc_encaps_start
            ).count();

        std::cout << "Lattice dimension (n): " << n << std::endl;
        std::cout << "LBC key generation time (ms): "
                  << keygen_time_lbc << std::endl;
        std::cout << "LBC encapsulation time (ms): "
                  << encaps_time_lbc << std::endl;
        std::cout << "Shared secret size (bytes): "
                  << lbc_result.shared_secret.size() << std::endl;


        // ---------- HYBRID PERFORMANCE ----------
        std::cout << "\n=== Performance Evaluation (Algorithm 2: Hybrid PQC + AES) ===\n";
        
        for (const auto& file : input_files) {
            auto plaintext = read_file(file);
            auto hybrid_metrics = performance_analysis_hybrid(plaintext, n);

            std::cout << "\nFile: " << file << std::endl;
            std::cout << "Input size (bytes): " << plaintext.size() << std::endl;
            std::cout << "--- PQC Phase (KEM) ---" << std::endl;
            std::cout << "  Alice KeyGen (ms): " << hybrid_metrics.kem_keygen_time_ms << std::endl;
            std::cout << "  Bob Encaps (ms):   " << hybrid_metrics.kem_encaps_time_ms << std::endl;
            std::cout << "  Alice Decaps (ms): " << hybrid_metrics.kem_decaps_time_ms << std::endl;
            std::cout << "--- Symmetric Phase (AES) ---" << std::endl;
            std::cout << "  AES Encrypt (ms):  " << hybrid_metrics.aes_encrypt_time_ms << std::endl;
            std::cout << "  AES Decrypt (ms):  " << hybrid_metrics.aes_decrypt_time_ms << std::endl;
            std::cout << "--- Total Overhead ---" << std::endl;
            std::cout << "  Total Encrypt (PQC+AES) (ms): " 
                      << (hybrid_metrics.kem_encaps_time_ms + hybrid_metrics.aes_encrypt_time_ms) << std::endl;
            std::cout << "  Total Decrypt (PQC+AES) (ms): " 
                      << (hybrid_metrics.kem_decaps_time_ms + hybrid_metrics.aes_decrypt_time_ms) << std::endl;
            std::cout << "  Total Ciphertext Size (bytes): " << hybrid_metrics.total_ciphertext_size << std::endl;
        }

        // ---------- PQC HYBRID PERFORMANCE (Real Kyber-768) ----------
        std::cout << "\n=== Performance Evaluation (Algorithm 4: PQC Hybrid - Kyber768 + AES-256) ===\n";

        auto pqc_keygen_start = std::chrono::high_resolution_clock::now();
        auto pqc_keys = pqc_keygen();
        auto pqc_keygen_end = std::chrono::high_resolution_clock::now();

        auto pqc_encaps_start = std::chrono::high_resolution_clock::now();
        auto pqc_capsule = pqc_encapsulate(pqc_keys.public_key);
        auto pqc_encaps_end = std::chrono::high_resolution_clock::now();

        auto pqc_decaps_start = std::chrono::high_resolution_clock::now();
        auto pqc_secret = pqc_decapsulate(pqc_capsule.first, pqc_keys.private_key);
        auto pqc_decaps_end = std::chrono::high_resolution_clock::now();

        double pqc_keygen_time =
            std::chrono::duration<double, std::milli>(
                pqc_keygen_end - pqc_keygen_start
            ).count();

        double pqc_encaps_time =
            std::chrono::duration<double, std::milli>(
                pqc_encaps_end - pqc_encaps_start
            ).count();

        double pqc_decaps_time =
            std::chrono::duration<double, std::milli>(
                pqc_decaps_end - pqc_decaps_start
            ).count();

        std::cout << "PQC Key generation time (ms): "
                  << pqc_keygen_time << std::endl;
        std::cout << "PQC Encapsulation time (ms): "
                  << pqc_encaps_time << std::endl;
        std::cout << "PQC Decapsulation time (ms): "
                  << pqc_decaps_time << std::endl;
        std::cout << "PQC Shared secret size (bytes): "
                  << pqc_secret.size() << std::endl;
        
        // Note: For full hybrid encryption, add AES encryption time (same as Algorithm 1)
        // to the PQC Key exchange time.

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
