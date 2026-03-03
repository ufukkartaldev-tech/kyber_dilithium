#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include "../include/kyber_modular.h"
#include <string.h>

namespace PQC {
namespace Test {

// 1. Kyber-512 Kararlılık Testi
bool TestSuite::test_kyber_kem_vectors() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    uint8_t ss1[32], ss2[32];
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
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    uint8_t ss1[32], ss2[32];
    KEM::Kyber512::keypair(pk, sk);
    KEM::Kyber512::encaps(ct, ss1, pk);
    ct[10] ^= 0xFF; 
    KEM::Kyber512::decaps(ss2, ct, sk);
    return !compare_bytes(ss1, ss2, 32);
}

// 3. Rastgelelik (Entropy) Kalite Testi
bool TestSuite::test_randomness_entropy() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t first_bytes[100][8]; 
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
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    uint8_t ss[32];
    
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
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    uint8_t ss[32];
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
        if (abs((long)(t[i] - avg)) > (long)(avg / 5)) return false; // %20 sapma limiti
    }
    return true;
}

} // namespace Test
} // namespace PQC

#endif
