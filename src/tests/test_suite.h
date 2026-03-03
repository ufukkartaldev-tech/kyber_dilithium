#ifndef TEST_SUITE_H
#define TEST_SUITE_H

#include <stdint.h>
#include <Arduino.h>
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

namespace PQC {
namespace Test {

class TestSuite {
public:
    static void run_all_tests();

private:
    // Ünite Testleri
    static bool test_keccak();
    static bool test_ntt_symmetry();
    static bool test_poly_serialization();
    static bool test_kyber_kem_vectors();
    static bool test_decaps_failure();
    static bool test_ntt_edge_cases();
    static bool test_randomness_entropy();
    static bool test_dilithium_malleability();
    
    // Yardımcılar
    static void log_test(const char* name, bool result);
    static bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len);
};

} // namespace Test
} // namespace PQC

#endif // ENABLE_PQC_TESTS

#endif

