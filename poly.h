#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
    int16_t coeffs[256];
} poly;

typedef struct {
    poly vec[KYBER_768_K]; // En büyük K seviyesine göre (static allocation)
} polyvec;

void poly_getnoise_eta1(poly *r, const uint8_t seed[32], uint8_t nonce, int k);
void poly_getnoise_eta2(poly *r, const uint8_t seed[32], uint8_t nonce);
void poly_uniform(poly *a, const uint8_t seed[32], uint8_t nonce);

void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void poly_reduce(poly *r);
void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

void poly_frombytes(poly *r, const uint8_t *a);
void poly_tobytes(uint8_t *r, const poly *a);

void poly_frommsg(poly *r, const uint8_t msg[32]);
void poly_tomsg(uint8_t msg[32], const poly *r);

void poly_compress(uint8_t *r, const poly *a, int du);
void poly_decompress(poly *r, const uint8_t *a, int du);

// Vector functions
void polyvec_ntt(polyvec *r, int k);
void polyvec_invntt_tomont(polyvec *r, int k);
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, int k);
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b, int k);

#endif
