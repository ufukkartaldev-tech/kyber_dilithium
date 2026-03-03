#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include "../include/kyber_modular.h"
#include <string.h>

namespace PQC {
namespace Test {

// 1. Kyber-512 Kararlılık Testi
bool TestSuite::test_kyber_kem_vectors() {
    static uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    static uint8_t sk[KYBER_512_SECRETKEYBYTES];
    static uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    static uint8_t ss1[32], ss2[32];
    for(int i=0; i<10; i++) {
        KEM::Kyber512::keypair(pk, sk);
        KEM::Kyber512::encaps(ct, ss1, pk);
        KEM::Kyber512::decaps(ss2, ct, sk);
        if (!compare_bytes(ss1, ss2, 32)) return false;
    }
    return true;
}

// 2. Implicit Rejection Testi
bool TestSuite::test_decaps_failure() {
    static uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    static uint8_t sk[KYBER_512_SECRETKEYBYTES];
    static uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    static uint8_t ss1[32], ss2[32];
    KEM::Kyber512::keypair(pk, sk);
    KEM::Kyber512::encaps(ct, ss1, pk);
    ct[10] ^= 0xFF; 
    KEM::Kyber512::decaps(ss2, ct, sk);
    return !compare_bytes(ss1, ss2, 32);
}

// 3. Rastgelelik (Entropy) Kalite Testi
bool TestSuite::test_randomness_entropy() {
    static uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    static uint8_t sk[KYBER_512_SECRETKEYBYTES];
    static uint8_t first_bytes[100][8]; 
    for(int i=0; i<100; i++) {
        KEM::Kyber512::keypair(pk, sk);
        memcpy(first_bytes[i], pk, 8);
        for(int j=0; j<i; j++) {
            if(compare_bytes(first_bytes[i], first_bytes[j], 8)) return false;
        }
    }
    return true;
}

// 4. Bellek Sızıntısı (Memory Leak) Testi
bool TestSuite::test_memory_leaks() {
    static uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    static uint8_t sk[KYBER_512_SECRETKEYBYTES];
    static uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    static uint8_t ss[32];
    
    size_t start_heap = ESP.getFreeHeap();
    
    // 100 döngü (ESP32'de 1000 döngü çok vakit alabilir, 100 sızıntı tespiti için yeterli)
    for(int i=0; i<100; i++) {
        KEM::Kyber512::keypair(pk, sk);
        KEM::Kyber512::encaps(ct, ss, pk);
        KEM::Kyber512::decaps(ss, ct, sk);
    }
    
    size_t end_heap = ESP.getFreeHeap();
    return (start_heap == end_heap);
}

// 5. Zamanlama Analizi (Timing Consistency) Testi
bool TestSuite::test_timing_consistency() {
    static uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    static uint8_t sk[KYBER_512_SECRETKEYBYTES];
    static uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    static uint8_t ss[32];
    uint32_t t[10];
    
    KEM::Kyber512::keypair(pk, sk);
    
    for(int i=0; i<10; i++) {
        uint32_t t0 = micros();
        KEM::Kyber512::encaps(ct, ss, pk);
        t[i] = micros() - t0;
    }
    
    // Basit bir varyans kontrolü (Çok büyük sapma olmamalı)
    uint32_t avg = 0;
    for(int i=0; i<10; i++) avg += t[i];
    avg /= 10;
    
    for(int i=0; i<10; i++) {
        if (abs((long)(t[i] - avg)) > (long)(avg / 5)) return false; 
    }
    return true;
}

// 6. Stack High Water Mark Testi
uint32_t TestSuite::test_stack_usage() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    
    // İşlem öncesi/sırası stack kontrolü
    KEM::Kyber512::keypair(pk, sk);
    
    // uxTaskGetStackHighWaterMark: Kalan minimum stack miktarını (word cinsinden) döner.
    // ESP32'de stack byte bazında ölçüldüğü için word bazlı sonuç 4 ile çarpılır (genellikle).
    return uxTaskGetStackHighWaterMark(NULL);
}

// 7. Güç ve Frekans Verimlilik Testi
void TestSuite::test_power_efficiency() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    uint8_t ss[32];
    uint32_t freqs[] = {240, 160, 80};
    
    Serial.println("\n[EFFICIENCY] Frekans vs Hiz Analizi:");
    Serial.println("Freq (MHz) | KeyGen (us) | Encaps (us)");
    Serial.println("-----------|-------------|------------");
    
    for(int i=0; i<3; i++) {
        setCpuFrequencyMhz(freqs[i]);
        delay(100); // Frekans geçişi için bekle
        
        uint32_t t0 = micros();
        KEM::Kyber512::keypair(pk, sk);
        uint32_t t_kg = micros() - t0;
        
        uint32_t t1 = micros();
        KEM::Kyber512::encaps(ct, ss, pk);
        uint32_t t_en = micros() - t1;
        
        Serial.print(freqs[i]); Serial.print(" MHz    | ");
        Serial.print(t_kg); Serial.print("      | ");
        Serial.println(t_en);
    }
    
    setCpuFrequencyMhz(240); // Test bitince normale dön
}

// 8. Eşzamanlılık (Multicore/Thread-Safety) Testi
// Bu test, static bellek kullanımının çift çekirdekteki riskini ölçer.
volatile bool multicore_failed = false;

static void kyber_task(void *pvParameters) {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ss1[32], ss2[32], ct[KYBER_512_CIPHERTEXTBYTES];
    
    for(int i=0; i<50; i++) {
        KEM::Kyber512::keypair(pk, sk);
        KEM::Kyber512::encaps(ct, ss1, pk);
        KEM::Kyber512::decaps(ss2, ct, sk);
        
        if (memcmp(ss1, ss2, 32) != 0) {
            multicore_failed = true;
        }
    }
    vTaskDelete(NULL);
}

bool TestSuite::test_multicore_safety() {
    multicore_failed = false;
    
    // Core 0 ve Core 1 üzerinde aynı anda Kyber işlemlerini başlat
    xTaskCreatePinnedToCore(kyber_task, "KyberC0", 8192, NULL, 1, NULL, 0);
    xTaskCreatePinnedToCore(kyber_task, "KyberC1", 8192, NULL, 1, NULL, 1);
    
    // Görevlerin bitmesi için yeterli süre bekle
    delay(2000); 
    
    return !multicore_failed;
}

} // namespace Test
} // namespace PQC

#endif
