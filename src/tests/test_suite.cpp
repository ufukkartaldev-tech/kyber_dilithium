#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include <string.h>

namespace PQC {
namespace Test {

// Test Loglama Altyapısı
void TestSuite::log_test(const char* name, bool result) {
    Serial.print("[TEST] ");
    Serial.print(name);
    if (result) {
        Serial.println(" -> BASARILI (OK)");
    } else {
        Serial.println(" -> HATALI (FAIL) !!!");
    }
}

// Bayt bazlı karşılaştırma yardımcısı
bool TestSuite::compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

// ANA TEST YÖNETİCİSİ (Orchestrator)
void TestSuite::run_all_tests() {
    Serial.println("\n--- PQC UNIT TEST SUITE BASLATILIYOR ---");
    
    // 1. Temel Matematiksel ve Kriptografik Fonksiyonlar
    log_test("Keccak (SHA3-256) KAT", test_keccak());
    log_test("NTT/InvNTT Symmetry", test_ntt_symmetry());
    log_test("NTT Edge Cases (Q values)", test_ntt_edge_cases());
    log_test("Poly Serialization", test_poly_serialization());
    
    // 2. Kyber KEM Güvenlik ve Kararlılık
    log_test("Kyber-512 Stability", test_kyber_kem_vectors());
    log_test("Kyber Implicit Rejection", test_decaps_failure());
    log_test("Randomness Entropy (100 Keypairs)", test_randomness_entropy());
    
    // 3. Dilithium DSA Güvenlik
    log_test("Dilithium Malleability", test_dilithium_malleability());
    
    Serial.println("--- UNIT TESTLER TAMAMLANDI ---\n");
}

} // namespace Test
} // namespace PQC

#endif
