#ifndef TEST_SUITE_H
#define TEST_SUITE_H

#include <stdint.h>

#ifdef ARDUINO
  #include <Arduino.h>
#else
  #include <stdio.h>
  #include <string.h>
  #include <time.h>
#endif
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

namespace PQC {
namespace Test {

class TestSuite {
public:
    static void run_all_tests();
    static void run_stress_test(); // Stress Test Modu (Gümüşhane Dayanıklılık Testi)

private:
    // Ünite Testleri
    static bool test_keccak();
    static bool test_ntt_symmetry();
    static bool test_poly_serialization();
    static bool test_kyber_kem_vectors();
    static bool test_decaps_failure();
    static bool test_ntt_edge_cases();
    static bool test_randomness_entropy();
    static bool test_memory_leaks();
    static bool test_poly_compression_noise();
    static bool test_timing_consistency();
    static uint32_t test_stack_usage();
    static void test_power_efficiency();
    static bool test_multicore_safety();
    static bool test_chacha20();
    static bool test_dilithium_malleability();
    
    // Adversary (Hacker) Testleri
    static bool test_replay_attack();
    static bool test_fragment_flooding();
    static bool test_rng_failure_lock();
    static bool test_counter_overflow();
    static bool test_flash_integrity_violation();
    static bool test_power_cycle_resilience();
    static bool test_trng_entropy_drop();
    static bool test_multi_device_stress();
    
    // Yardımcılar
    static void log_test(const char* name, bool result);
    static bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len);
};

} // namespace Test
} // namespace PQC

#endif // ENABLE_PQC_TESTS

#endif

