#include "../include/kyber_modular.h"
#include "../include/fips202.h"
#include "../include/ntt.h"
#include "../include/workspace.h"
#include <string.h>

using namespace PQC::Memory;

namespace PQC {
namespace KEM {

// ESP32 Random
#ifdef ARDUINO
#include <Arduino.h>
#define KEM_RANDOM(ptr, len) do { uint8_t* _p = (uint8_t*)(ptr); for(size_t _i=0; _i<len; _i++) _p[_i] = (uint8_t)esp_random(); } while(0)
#else
#include <stdlib.h>
#define KEM_RANDOM(ptr, len) do { uint8_t* _p = (uint8_t*)(ptr); for(size_t _i=0; _i<len; _i++) _p[_i] = (uint8_t)rand(); } while(0)
#endif

void KyberBase::gen_matrix_row(polyvec *a_row, const uint8_t seed[32], int row_idx, int k, int transposed) {
    for (int j = 0; j < k; j++) {
        if (transposed)
            poly_uniform(&a_row->vec[j], seed, (uint8_t)((row_idx << 4) + j));
        else
            poly_uniform(&a_row->vec[j], seed, (uint8_t)((j << 4) + row_idx));
    }
}

// Kyber512 Implementation
int Kyber512::keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t buf[64];
    uint8_t public_seed[32], noise_seed[32];
    polyvec &a_row = workspace.maths.kv1;
    polyvec &skpv = workspace.maths.kv2;
    polyvec &e = workspace.maths.kv3;
    polyvec &pkpv = workspace.maths.kv4;
    uint8_t nonce = 0;

    memset(&skpv, 0, sizeof(skpv)); memset(&e, 0, sizeof(e)); memset(&pkpv, 0, sizeof(pkpv));

    KEM_RANDOM(buf, 32);
    sha3_512(buf, buf, 32);
    memcpy(public_seed, buf, 32);
    memcpy(noise_seed, buf + 32, 32);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&skpv.vec[i], noise_seed, nonce++, K);
    for (int i = 0; i < K; i++) poly_getnoise_eta1(&e.vec[i], noise_seed, nonce++, K);

    polyvec_ntt(&skpv, K); polyvec_ntt(&e, K);

    // Matrix multiplication (Row-by-Row)
    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, public_seed, i, K, 0); // i. satırı üret
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a_row, &skpv, K);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        poly_reduce(&pkpv.vec[i]);
    }

    for (int i = 0; i < K; i++) poly_tobytes(pk + i * KYBER_POLYBYTES, &pkpv.vec[i]);
    memcpy(pk + K * KYBER_POLYBYTES, public_seed, 32);
    for (int i = 0; i < K; i++) poly_tobytes(sk + i * KYBER_POLYBYTES, &skpv.vec[i]);
    memcpy(sk + K * KYBER_POLYBYTES, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_512_SECRETKEYBYTES - 64, pk, KYBER_512_PUBLICKEYBYTES);
    KEM_RANDOM(sk + KYBER_512_SECRETKEYBYTES - 32, 32);
    return 0;
}

int Kyber512::encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[64], kr[64], msg[32];
    polyvec &a_row = workspace.maths.kv1;
    polyvec &pkpv = workspace.maths.kv2;
    polyvec &sp = workspace.maths.kv3;
    polyvec &e1 = workspace.maths.kv4;
    polyvec &bp = workspace.maths.kv5;
    poly &v = workspace.maths.kp1;
    poly &k_poly = workspace.maths.kp2;
    poly &e2 = workspace.maths.kp3;
    uint8_t nonce = 0;

    memset(&pkpv, 0, sizeof(pkpv)); memset(&sp, 0, sizeof(sp));
    memset(&e1, 0, sizeof(e1)); memset(&bp, 0, sizeof(bp)); memset(&v, 0, sizeof(v));
    memset(&k_poly, 0, sizeof(k_poly)); memset(&e2, 0, sizeof(e2));

    KEM_RANDOM(msg, 32); sha3_256(msg, msg, 32);
    memcpy(buf, msg, 32); sha3_256(buf + 32, pk, KYBER_512_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);

    for (int i = 0; i < K; i++) poly_frombytes(&pkpv.vec[i], pk + i * KYBER_POLYBYTES);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&sp.vec[i], kr + 32, nonce++, K);
    for (int i = 0; i < K; i++) poly_getnoise_eta2(&e1.vec[i], kr + 32, nonce++);
    poly_getnoise_eta2(&e2, kr + 32, nonce++);

    polyvec_ntt(&sp, K);
    
    // Matrix multiplication (Row-by-Row, Transposed)
    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, pk + K * KYBER_POLYBYTES, i, K, 1);
        polyvec_basemul_acc_montgomery(&bp.vec[i], &a_row, &sp, K);
        poly_tomont(&bp.vec[i]); poly_add(&bp.vec[i], &bp.vec[i], &e1.vec[i]); poly_reduce(&bp.vec[i]);
    }
    
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, K);
    poly_tomont(&v); poly_add(&v, &v, &e2);
    poly_frommsg(&k_poly, msg); poly_add(&v, &v, &k_poly); poly_reduce(&v);

    for (int i = 0; i < K; i++) poly_compress(ct + i * 320, &bp.vec[i], 10);
    poly_compress(ct + K * 320, &v, 4);

    sha3_256(kr + 32, ct, KYBER_512_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int Kyber512::decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[64], kr[64], msg[32];
    polyvec &bp = workspace.maths.kv1;
    polyvec &skpv = workspace.maths.kv2;
    poly &v = workspace.maths.kp1;
    poly &mp = workspace.maths.kp2;

    memset(&bp, 0, sizeof(bp)); memset(&skpv, 0, sizeof(skpv)); memset(&v, 0, sizeof(v)); memset(&mp, 0, sizeof(mp));

    for (int i = 0; i < K; i++) poly_decompress(&bp.vec[i], ct + i * 320, 10);
    poly_decompress(&v, ct + K * 320, 4);
    for (int i = 0; i < K; i++) poly_frombytes(&skpv.vec[i], sk + i * KYBER_POLYBYTES);

    polyvec_ntt(&bp, K);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp, K);
    poly_invntt_tomont(&mp);
    poly_tomont(&mp); poly_reduce(&mp);
    poly_sub(&mp, &v, &mp); poly_reduce(&mp);
    poly_tomsg(msg, &mp);

    memcpy(buf, msg, 32);
    memcpy(buf + 32, sk + KYBER_512_SECRETKEYBYTES - 64, 32);
    sha3_512(kr, buf, 64);

    sha3_256(ss, kr, 64); 
    return 0;
}

// Kyber768 Implementation
int Kyber768::keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t buf[64];
    uint8_t public_seed[32], noise_seed[32];
    polyvec &a_row = workspace.maths.kv1;
    polyvec &skpv = workspace.maths.kv2;
    polyvec &e = workspace.maths.kv3;
    polyvec &pkpv = workspace.maths.kv4;
    uint8_t nonce = 0;

    memset(&skpv, 0, sizeof(skpv)); memset(&e, 0, sizeof(e)); memset(&pkpv, 0, sizeof(pkpv));

    KEM_RANDOM(buf, 32);
    sha3_512(buf, buf, 32);
    memcpy(public_seed, buf, 32);
    memcpy(noise_seed, buf + 32, 32);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&skpv.vec[i], noise_seed, nonce++, KYBER_768_ETAl);
    for (int i = 0; i < K; i++) poly_getnoise_eta1(&e.vec[i], noise_seed, nonce++, KYBER_768_ETAl);

    polyvec_ntt(&skpv, K); polyvec_ntt(&e, K);

    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, public_seed, i, K, 0); 
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a_row, &skpv, K);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        poly_reduce(&pkpv.vec[i]);
    }

    for (int i = 0; i < K; i++) poly_tobytes(pk + i * KYBER_POLYBYTES, &pkpv.vec[i]);
    memcpy(pk + K * KYBER_POLYBYTES, public_seed, 32);
    for (int i = 0; i < K; i++) poly_tobytes(sk + i * KYBER_POLYBYTES, &skpv.vec[i]);
    memcpy(sk + K * KYBER_POLYBYTES, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_768_SECRETKEYBYTES - 64, pk, KYBER_768_PUBLICKEYBYTES);
    KEM_RANDOM(sk + KYBER_768_SECRETKEYBYTES - 32, 32);
    return 0;
}

int Kyber768::encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[64], kr[64], msg[32];
    polyvec &a_row = workspace.maths.kv1;
    polyvec &pkpv = workspace.maths.kv2;
    polyvec &sp = workspace.maths.kv3;
    polyvec &e1 = workspace.maths.kv4;
    polyvec &bp = workspace.maths.kv5;
    poly &v = workspace.maths.kp1;
    poly &k_poly = workspace.maths.kp2;
    poly &e2 = workspace.maths.kp3;
    uint8_t nonce = 0;

    memset(&pkpv, 0, sizeof(pkpv)); memset(&sp, 0, sizeof(sp));
    memset(&e1, 0, sizeof(e1)); memset(&bp, 0, sizeof(bp)); memset(&v, 0, sizeof(v));
    memset(&k_poly, 0, sizeof(k_poly)); memset(&e2, 0, sizeof(e2));

    KEM_RANDOM(msg, 32); sha3_256(msg, msg, 32);
    memcpy(buf, msg, 32); sha3_256(buf + 32, pk, KYBER_768_PUBLICKEYBYTES);
    sha3_512(kr, buf, 64);

    for (int i = 0; i < K; i++) poly_frombytes(&pkpv.vec[i], pk + i * KYBER_POLYBYTES);

    for (int i = 0; i < K; i++) poly_getnoise_eta1(&sp.vec[i], kr + 32, nonce++, KYBER_768_ETAl);
    for (int i = 0; i < K; i++) poly_getnoise_eta2(&e1.vec[i], kr + 32, nonce++);
    poly_getnoise_eta2(&e2, kr + 32, nonce++);

    polyvec_ntt(&sp, K);
    
    for (int i = 0; i < K; i++) {
        gen_matrix_row(&a_row, pk + K * KYBER_POLYBYTES, i, K, 1);
        polyvec_basemul_acc_montgomery(&bp.vec[i], &a_row, &sp, K);
        poly_tomont(&bp.vec[i]); poly_add(&bp.vec[i], &bp.vec[i], &e1.vec[i]); poly_reduce(&bp.vec[i]);
    }
    
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, K);
    poly_tomont(&v); poly_add(&v, &v, &e2);
    poly_frommsg(&k_poly, msg); poly_add(&v, &v, &k_poly); poly_reduce(&v);

    for (int i = 0; i < K; i++) poly_compress(ct + i * 320, &bp.vec[i], 10);
    poly_compress(ct + K * 320, &v, 4);

    sha3_256(kr + 32, ct, KYBER_768_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 64);
    return 0;
}

int Kyber768::decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[64], kr[64], msg[32];
    polyvec &bp = workspace.maths.kv1;
    polyvec &skpv = workspace.maths.kv2;
    poly &v = workspace.maths.kp1;
    poly &mp = workspace.maths.kp2;

    memset(&bp, 0, sizeof(bp)); memset(&skpv, 0, sizeof(skpv)); memset(&v, 0, sizeof(v)); memset(&mp, 0, sizeof(mp));

    for (int i = 0; i < K; i++) poly_decompress(&bp.vec[i], ct + i * 320, 10);
    poly_decompress(&v, ct + K * 320, 4);
    for (int i = 0; i < K; i++) poly_frombytes(&skpv.vec[i], sk + i * KYBER_POLYBYTES);

    polyvec_ntt(&bp, K);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp, K);
    poly_invntt_tomont(&mp);
    poly_tomont(&mp); poly_reduce(&mp);
    poly_sub(&mp, &v, &mp); poly_reduce(&mp);
    poly_tomsg(msg, &mp);

    memcpy(buf, msg, 32);
    memcpy(buf + 32, sk + KYBER_768_SECRETKEYBYTES - 64, 32);
    sha3_512(kr, buf, 64);

    sha3_256(ss, kr, 64); 
    return 0;
}

} // namespace KEM
} // namespace PQC
