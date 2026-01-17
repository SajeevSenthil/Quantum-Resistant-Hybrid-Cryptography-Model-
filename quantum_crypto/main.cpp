#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include "aes.h"
#include "perf_analysis.h"   

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

        std::cout << "=== Performance Evaluation (Algorithm 1) ===\n";

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
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
