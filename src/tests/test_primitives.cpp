#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include "../include/fips202.h"
#include "../include/ntt.h"
#include "../include/poly.h"
#include <string.h>

namespace PQC {
namespace Test {

// 1. Keccak (SHA3-256) Testi
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
bool TestSuite::test_ntt_symmetry() {
    int16_t r[256];
    int16_t original[256];
    for(int i=0; i<256; i++) {
        r[i] = (i * 13) % 3329;
        original[i] = r[i];
    }
    ntt(r);
    invntt(r);
    for(int i=0; i<256; i++) {
        int16_t c = (r[i] % 3329 + 3329) % 3329;
        if (c != original[i]) return false;
    }
    return true;
}

// 3. NTT Sınır Durum (Edge Case) Testi
bool TestSuite::test_ntt_edge_cases() {
    int16_t r[256];
    for(int i=0; i<256; i++) r[i] = 3329;
    ntt(r);
    invntt(r);
    for(int i=0; i<256; i++) {
        int16_t c = (r[i] % 3329 + 3329) % 3329;
        if (c != 0) return false;
    }
    return true;
}

// 4. Polinom Paketleme (Serialization) Testi
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

// 5. Sıkıştırma ve Hata Payı (Compression & Noise) Testi
bool TestSuite::test_poly_compression_noise() {
    poly p, p2;
    uint8_t buf[320]; // du=10 için 320 byte
    
    // Rastgele değerler ata
    for(int i=0; i<256; i++) p.coeffs[i] = (i * 123) % 3329;
    
    // Sıkıştır ve geri aç
    poly_compress(buf, &p, 10);
    poly_decompress(&p2, buf, 10);
    
    for(int i=0; i<256; i++) {
        // Kyber katsayı farkı: du=10 için (Q/2^10)/2 ~ 1.6
        // Yuvarlama hatası 2'den büyük olmamalı.
        int16_t diff = abs(p.coeffs[i] - p2.coeffs[i]);
        if(diff > 3329/2) diff = 3329 - diff; // Modüler fark
        
        if (diff > 2) return false; 
    }
    return true;
}

} // namespace Test
} // namespace PQC

#endif
