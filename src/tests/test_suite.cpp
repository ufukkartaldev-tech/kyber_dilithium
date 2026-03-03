#include "test_suite.h"
#include "../include/fips202.h"
#include "../include/ntt.h"
#include "../include/poly.h"
#include "../include/kyber_modular.h"
#include "../include/dilithium.h"
#include <string.h>

namespace PQC {
namespace Test {

void TestSuite::log_test(const char* name, bool result) {
    Serial.print("[TEST] ");
    Serial.print(name);
    if (result) {
        Serial.println(" -> BASARILI (OK)");
    } else {
        Serial.println(" -> HATALI (FAIL) !!!");
    }
}

bool TestSuite::compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

// 1. Keccak (SHA3-256) Testi
// Boş string için SHA3-256 Hash değeri kontrolü
bool TestSuite::test_keccak() {
    uint8_t out[32];
    uint8_t expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0x43, 0x73, 0x04, 0xb8, 0x83, 0x9b, 0x8a, 0x92, 0x07, 0x3e, 0x81, 0x10
    };
    
    sha3_256(out, (const uint8_t*)"", 0);
    return compare_bytes(out, expected, 32);
}

// 2. NTT Simetri Testi
// ntt -> invntt bir polinomun orijinal halini vermeli
bool TestSuite::test_ntt_symmetry() {
    int16_t r[256];
    int16_t original[256];
    
    for(int i=0; i<256; i++) {
        r[i] = (i * 13) % 3329;
        original[i] = r[i];
    }
    
    ntt(r);
    invntt(r); // invntt_tomont değil, standart invntt (normalization içerir)
    
    for(int i=0; i<256; i++) {
        // Katsayılar [0, 3328] arasına normalize edilmeli
        int16_t c = (r[i] % 3329 + 3329) % 3329;
        if (c != original[i]) return false;
    }
    return true;
}

// 3. Polinom Paketleme (Serialization) Testi
bool TestSuite::test_poly_serialization() {
    poly p, p2;
    uint8_t buf[KYBER_POLYBYTES];
    
    for(int i=0; i<256; i++) p.coeffs[i] = (i * 7) % 3329;
    
    poly_tobytes(buf, &p);
    poly_frombytes(&p2, buf);
    
    for(int i=0; i<256; i++) {
        if ((p.coeffs[i] % 3329) != (p2.coeffs[i] % 3329)) return false;
    }
    return true;
}

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

// 5. Implicit Rejection Testi
// Ciphertext bozulursa shared secret rastgele (farklı) olmalı
bool TestSuite::test_decaps_failure() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
    uint8_t ss1[32], ss2[32];
    
    KEM::Kyber512::keypair(pk, sk);
    KEM::Kyber512::encaps(ct, ss1, pk);
    
    // Ciphertext'i boz (Implicit Rejection testi)
    ct[10] ^= 0xFF; 
    
    KEM::Kyber512::decaps(ss2, ct, sk);
    
    // ss1 ve ss2 farklı olmalı
    return !compare_bytes(ss1, ss2, 32);
}

// 6. NTT Sınır Durum (Edge Case) Testi
bool TestSuite::test_ntt_edge_cases() {
    int16_t r[256];
    for(int i=0; i<256; i++) r[i] = 3329; // Q değeri (mod Q = 0 olmalı)
    
    ntt(r);
    invntt(r);
    
    for(int i=0; i<256; i++) {
        int16_t c = (r[i] % 3329 + 3329) % 3329;
        if (c != 0) return false;
    }
    return true;
}

// 7. Rastgelelik (Entropy) Kalite Testi
bool TestSuite::test_randomness_entropy() {
    uint8_t pk[KYBER_512_PUBLICKEYBYTES];
    uint8_t sk[KYBER_512_SECRETKEYBYTES];
    uint8_t first_bytes[100][8]; // ESP32 RAM limitlerine uygun sayı
    
    for(int i=0; i<100; i++) {
        KEM::Kyber512::keypair(pk, sk);
        memcpy(first_bytes[i], pk, 8);
        
        // Öncekilerle karşılaştır
        for(int j=0; j<i; j++) {
            if(compare_bytes(first_bytes[i], first_bytes[j], 8)) return false;
        }
    }
    return true;
}

// 8. Dilithium Malleability Testi
bool TestSuite::test_dilithium_malleability() {
    uint8_t d_pk[2048];
    uint8_t d_sk[4096];
    uint8_t sig[2420]; 
    size_t siglen;
    const uint8_t msg[] = "Test Message";
    
    DSA::Dilithium2::keypair(d_pk, d_sk);
    DSA::Dilithium2::sign(sig, &siglen, msg, sizeof(msg), d_sk);
    
    // İmzayı boz
    sig[20] ^= 0x01;
    
    // Verify başarısız olmalı (0 dönmeli veya hata kodu)
    int res = DSA::Dilithium2::verify(sig, siglen, msg, sizeof(msg), d_pk);
    return (res != 0); 
}

void TestSuite::run_all_tests() {
    Serial.println("\n--- PQC UNIT TEST SUITE BASLATILIYOR ---");
    
    log_test("Keccak (SHA3-256) KAT", test_keccak());
    log_test("NTT/InvNTT Symmetry", test_ntt_symmetry());
    log_test("Poly Serialization", test_poly_serialization());
    log_test("Kyber-512 Stability", test_kyber_kem_vectors());
    log_test("Kyber Implicit Rejection", test_decaps_failure());
    log_test("NTT Edge Cases (Q values)", test_ntt_edge_cases());
    log_test("Randomness Entropy (100 Keypairs)", test_randomness_entropy());
    log_test("Dilithium Malleability (Signature)", test_dilithium_malleability());
    
    Serial.println("--- UNIT TESTLER TAMAMLANDI ---\n");
}

} // namespace Test
} // namespace PQC
