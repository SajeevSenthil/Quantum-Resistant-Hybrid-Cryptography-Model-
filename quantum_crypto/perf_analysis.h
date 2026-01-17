#ifndef PERF_ANALYSIS_H
#define PERF_ANALYSIS_H

#include <vector>

// Structure to store performance metrics
struct PerfMetrics {
    double keygen_time_ms;
    double encrypt_time_ms;
    double decrypt_time_ms;
};

// Algorithm-1: Performance Evaluation
PerfMetrics performance_analysis(
    const std::vector<unsigned char>& plaintext
);

#endif
