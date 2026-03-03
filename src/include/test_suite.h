#ifndef TEST_SUITE_H
#define TEST_SUITE_H

#include <stdint.h>
#include <Arduino.h>

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
    
    // Yardımcılar
    static void log_test(const char* name, bool result);
    static bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len);
};

} // namespace Test
} // namespace PQC

#endif
