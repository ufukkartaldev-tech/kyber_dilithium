#include "../include/test_suite.h"
#include "../include/fips202.h"
#include "../include/ntt.h"
#include "../include/poly.h"
#include "../include/kyber_modular.h"
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

// 4. Kyber-512 KEM Döngü Testi (10 Iterasyon)
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

void TestSuite::run_all_tests() {
    Serial.println("\n--- PQC UNIT TEST SUITE BASLATILIYOR ---");
    
    log_test("Keccak (SHA3-256) KAT", test_keccak());
    log_test("NTT/InvNTT Symmetry", test_ntt_symmetry());
    log_test("Poly Serialization", test_poly_serialization());
    log_test("Kyber-512 KEM Stability (10 Iteration)", test_kyber_kem_vectors());
    
    Serial.println("--- UNIT TESTLER TAMAMLANDI ---\n");
}

} // namespace Test
} // namespace PQC
