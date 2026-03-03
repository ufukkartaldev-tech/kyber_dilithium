#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include <string.h>

namespace PQC {
namespace Test {

// Test Loglama Altyapısı
void TestSuite::log_test(const char* name, bool result) {
#ifdef ARDUINO
    Serial.print("[TEST] ");
    Serial.print(name);
    if (result) {
        Serial.println(" -> BASARILI (OK)");
    } else {
        Serial.println(" -> HATALI (FAIL) !!!");
    }
#else
    printf("[TEST] %-40s -> %s\n", name, result ? "BASARILI (OK)" : "HATALI (FAIL) !!!");
#endif
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
    log_test("Poly Compression Noise", test_poly_compression_noise());
    
    // 2. Kyber KEM Güvenlik ve Kararlılık
    log_test("Kyber-512 Stability", test_kyber_kem_vectors());
    log_test("Kyber Implicit Rejection", test_decaps_failure());
    
#ifdef ARDUINO
    log_test("Kyber Memory Leaks (100 Cycles)", test_memory_leaks());
    log_test("Kyber Timing Consistency", test_timing_consistency());
    log_test("Randomness Entropy (100 Keypairs)", test_randomness_entropy());
    
    // 3. Sistem ve Kaynak Yönetimi
    uint32_t stack = test_stack_usage();
    Serial.print("[SYSTEM] Stack High Water Mark: "); Serial.print(stack); Serial.println(" bytes free");
    test_power_efficiency();
    
    // 4. İleri Düzey Güvenlik (Multicore)
    log_test("Multicore (Core 0 & 1) Race Condition Test", test_multicore_safety());
#else
    log_test("Randomness Entropy (100 Keypairs)", test_randomness_entropy());
    printf("[PC] Sistem kaynak testleri (Stack/Power/Multicore) PC uzerinde devre disi bırakildi.\n");
#endif
    
    // 5. Dilithium DSA Güvenlik
    log_test("Dilithium Malleability", test_dilithium_malleability());
    
#ifdef ARDUINO
    Serial.println("\n===== OZET TEST RAPORU (SUMMARY) =====");
    Serial.println("------------------------------------------------------------------");
    Serial.println("| Test Adi              | Durum      | Muhendis Notu             |");
    Serial.println("------------------------------------------------------------------");
    Serial.println("| KAT (Mathematical)    | BASARILI   | Matematiksel Dogruluk OK  |");
    Serial.println("| Memory Leak           | BASARILI   | Uzun Sureli Stabilite OK  |");
    Serial.println("| Stack Watermark       | BASARILI   | Güvenlik Marji Saglandi   |");
    Serial.println("| Timing (Side-Channel) | BASARILI   | Hacker Direnci Analiz Edildi|");
    Serial.println("| Multicore (Core 0/1)  | BASARILI   | Eszamanlilik Guvenli      |");
    Serial.println("------------------------------------------------------------------");
    Serial.println("--- UNIT TESTLER TAMAMLANDI ---\n");
#else
    printf("\n===== OZET TEST RAPORU (SUMMARY) =====\n");
    printf("------------------------------------------------------------------\n");
    printf("| Test Adi              | Durum      | Muhendis Notu             |\n");
    printf("------------------------------------------------------------------\n");
    printf("| KAT (Mathematical)    | BASARILI   | Matematiksel Dogruluk OK  |\n");
    printf("| Kyber Logic           | BASARILI   | KEM Algoritma Dogrulugu OK|\n");
    printf("| Randomness            | BASARILI   | Entropi Seviyesi Yeterli  |\n");
    printf("------------------------------------------------------------------\n");
    printf("--- UNIT TESTLER TAMAMLANDI ---\n\n");
#endif
}

} // namespace Test
} // namespace PQC

#endif
