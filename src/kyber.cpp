#include "kyber.h"
#include "poly.h"
#include "fips202.h"
#include <string.h>

// ESP32 Random Generator (Eğer Arduino/ESP-IDF ortamındaysak)
#ifdef ARDUINO
#include <Arduino.h>
#define GET_RANDOM(ptr, len) do { uint8_t* _p = (uint8_t*)(ptr); for(size_t _i=0; _i<len; _i++) _p[_i] = (uint8_t)esp_random(); } while(0)
#else
#include <stdlib.h>
#define GET_RANDOM(ptr, len) do { uint8_t* _p = (uint8_t*)(ptr); for(size_t _i=0; _i<len; _i++) _p[_i] = (uint8_t)rand(); } while(0)
#endif

// Yardımcı Fonksiyonlar
static void gen_matrix(polyvec *a, const uint8_t seed[32], int k, int transposed) {
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            if (transposed)
                poly_uniform(&a[i].vec[j], seed, (uint8_t)((i << 4) + j));
            else
                poly_uniform(&a[i].vec[j], seed, (uint8_t)((j << 4) + i));
        }
    }
}

// IND-CPA Key Generation
// Kuantum bilgisayarlar, klasik şifreleme yöntemlerini (RSA, ECC) çok hızlı çözebilir. 
// Kyber (ML-KEM), "Lattices" (Kafes Yapıları) kullanarak kuantum sonrası dönemde güvenliği sağlar.
// Bu adımda, rastgele bir matris ve hata vektörleri kullanılarak açık anahtar (pk) ve gizli anahtar (sk) üretilir.
static void indcpa_keypair(uint8_t *pk, uint8_t *sk, int k) {
    uint8_t buf[64];
    uint8_t public_seed[32];
    uint8_t noise_seed[32];
    static polyvec a[4]; 
    static polyvec skpv, e, pkpv;
    uint8_t nonce = 0;

    // Önemli: Statik bellek kullanıldığı için her seferinde sıfırlanmalıdır.
    memset(a, 0, sizeof(a));
    memset(&skpv, 0, sizeof(skpv));
    memset(&e, 0, sizeof(e));
    memset(&pkpv, 0, sizeof(pkpv));

    GET_RANDOM(buf, 32);
    sha3_512(buf, buf, 32);
    memcpy(public_seed, buf, 32);
    memcpy(noise_seed, buf + 32, 32);

    gen_matrix(a, public_seed, k, 0);

    for (int i = 0; i < k; i++)
        poly_getnoise_eta1(&skpv.vec[i], noise_seed, nonce++, k);
    for (int i = 0; i < k; i++)
        poly_getnoise_eta1(&e.vec[i], noise_seed, nonce++, k);

    polyvec_ntt(&skpv, k);
    polyvec_ntt(&e, k);

    for (int i = 0; i < k; i++) {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv, k);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        poly_reduce(&pkpv.vec[i]);
    }

    // Paketleme
    for (int i = 0; i < k; i++)
        poly_tobytes(pk + i * KYBER_POLYBYTES, &pkpv.vec[i]);
    memcpy(pk + k * KYBER_POLYBYTES, public_seed, 32);

    for (int i = 0; i < k; i++)
        poly_tobytes(sk + i * KYBER_POLYBYTES, &skpv.vec[i]);
}

// IND-CPA Encryption (Temel Şifreleme)
static void indcpa_enc(uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t seed[32], int k) {
    static polyvec a[4], pkpv, sp, e1, bp;
    static poly v, k_poly, e2;
    uint8_t public_seed[32];
    uint8_t nonce = 0;

    memset(a, 0, sizeof(a));
    memset(&pkpv, 0, sizeof(pkpv));
    memset(&sp, 0, sizeof(sp));
    memset(&e1, 0, sizeof(e1));
    memset(&bp, 0, sizeof(bp));
    memset(&v, 0, sizeof(v));
    memset(&k_poly, 0, sizeof(k_poly));
    memset(&e2, 0, sizeof(e2));

    for (int i = 0; i < k; i++)
        poly_frombytes(&pkpv.vec[i], pk + i * KYBER_POLYBYTES);
    memcpy(public_seed, pk + k * KYBER_POLYBYTES, 32);

    gen_matrix(a, public_seed, k, 1); // Transposed

    for (int i = 0; i < k; i++)
        poly_getnoise_eta1(&sp.vec[i], seed, nonce++, k);
    for (int i = 0; i < k; i++)
        poly_getnoise_eta2(&e1.vec[i], seed, nonce++);
    poly_getnoise_eta2(&e2, seed, nonce++);

    polyvec_ntt(&sp, k);

    // bp = A^T * s + e1
    for (int i = 0; i < k; i++) {
        polyvec_basemul_acc_montgomery(&bp.vec[i], &a[i], &sp, k);
        poly_tomont(&bp.vec[i]);
        poly_add(&bp.vec[i], &bp.vec[i], &e1.vec[i]);
        poly_reduce(&bp.vec[i]);
    }

    // v = pk^T * s + e2 + Decompress(msg)
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, k);
    poly_tomont(&v);
    poly_add(&v, &v, &e2);
    
    poly_frommsg(&k_poly, msg);
    poly_add(&v, &v, &k_poly);
    poly_reduce(&v);

    // Ciphertext paketleme (Sıkıştırma uygulanır)
    for (int i = 0; i < k; i++)
        poly_compress(ct + i * 320, &bp.vec[i], 10); // du=10
    poly_compress(ct + k * 320, &v, 4); // dv=4
}

// IND-CPA Decryption (Temel Çözme)
static void indcpa_dec(uint8_t *msg, const uint8_t *ct, const uint8_t *sk, int k) {
    static polyvec bp, skpv;
    static poly v, mp;

    for (int i = 0; i < k; i++)
        poly_decompress(&bp.vec[i], ct + i * 320, 10);
    poly_decompress(&v, ct + k * 320, 4);

    for (int i = 0; i < k; i++)
        poly_frombytes(&skpv.vec[i], sk + i * KYBER_POLYBYTES);

    polyvec_ntt(&bp, k);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp, k);
    poly_invntt_tomont(&mp);
    
    // mp şu an R^-1 ölçekli, onu normal domain'e çekiyoruz.
    poly_tomont(&mp); 
    poly_reduce(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(msg, &mp);
}

// CCA Safe KEM Functions (Level 1 & 2)
int kyber512_keypair(uint8_t *pk, uint8_t *sk) {
    int k = 2;
    indcpa_keypair(pk, sk, k);
    memcpy(sk + k * KYBER_POLYBYTES, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_512_SECRETKEYBYTES - 2 * 32, pk, KYBER_512_PUBLICKEYBYTES);
    GET_RANDOM(sk + KYBER_512_SECRETKEYBYTES - 32, 32);
    return 0;
}

int kyber512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[64], kr[64], msg[32];
    int k = 2;
    GET_RANDOM(msg, 32);
    sha3_256(msg, msg, 32);
    
    memcpy(buf, msg, 32);
    sha3_256(buf + 32, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);
    
    indcpa_enc(ct, msg, pk, kr + 32, k);
    
    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int kyber512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[64], kr[64], msg[32], cmp_ct[KYBER_512_CIPHERTEXTBYTES];
    int k = 2;
    const uint8_t *pk = sk + k * KYBER_POLYBYTES;
    const uint8_t *hpk = sk + KYBER_512_SECRETKEYBYTES - 64;
    const uint8_t *z = sk + KYBER_512_SECRETKEYBYTES - 32;

    indcpa_dec(msg, ct, sk, k);
    
    memcpy(buf, msg, 32);
    memcpy(buf + 32, hpk, 32);
    sha3_512(kr, buf, 64);
    
    indcpa_enc(cmp_ct, msg, pk, kr + 32, k);
    
    int fail = memcmp(ct, cmp_ct, KYBER_512_CIPHERTEXTBYTES);
    
    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    
    if (fail) {
        // Rejection durumunda z parametresi kullanılarak yalancı rastgele çıktı üretilir (Safe Reject)
        uint8_t reject_buf[64];
        memcpy(reject_buf, z, 32);
        memcpy(reject_buf + 32, ct, 32); // Ciphertext'in bir kısmını ekle
        sha3_256(ss, reject_buf, 64);
    } else {
        sha3_256(ss, kr, 64);
    }
    return 0;
}

// Kyber-768 Implementasyonu (Hemen hemen aynı, sadece parametreler farklı)
int kyber768_keypair(uint8_t *pk, uint8_t *sk) {
    int k = 3;
    indcpa_keypair(pk, sk, k);
    memcpy(sk + k * KYBER_POLYBYTES, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_768_SECRETKEYBYTES - 2 * 32, pk, KYBER_768_PUBLICKEYBYTES);
    GET_RANDOM(sk + KYBER_768_SECRETKEYBYTES - 32, 32);
    return 0;
}

int kyber768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[64], kr[64], msg[32];
    int k = 3;
    GET_RANDOM(msg, 32);
    sha3_256(msg, msg, 32);
    
    memcpy(buf, msg, 32);
    sha3_256(buf + 32, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);
    
    indcpa_enc(ct, msg, pk, kr + 32, k);
    
    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int kyber768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[64], kr[64], msg[32], cmp_ct[KYBER_768_CIPHERTEXTBYTES];
    int k = 3;
    const uint8_t *pk = sk + k * KYBER_POLYBYTES;
    const uint8_t *hpk = sk + KYBER_768_SECRETKEYBYTES - 64;
    const uint8_t *z = sk + KYBER_768_SECRETKEYBYTES - 32;

    indcpa_dec(msg, ct, sk, k);
    
    memcpy(buf, msg, 32);
    memcpy(buf + 32, hpk, 32);
    sha3_512(kr, buf, 64);
    
    indcpa_enc(cmp_ct, msg, pk, kr + 32, k);
    
    int fail = memcmp(ct, cmp_ct, KYBER_768_CIPHERTEXTBYTES);
    
    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    
    if (fail) {
        uint8_t reject_buf[64];
        memcpy(reject_buf, z, 32);
        memcpy(reject_buf + 32, ct, 32);
        sha3_256(ss, reject_buf, 64);
    } else {
        sha3_256(ss, kr, 64);
    }
    return 0;
}
