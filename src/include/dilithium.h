#ifndef DILITHIUM_H
#define DILITHIUM_H

#include <stdint.h>
#include <stddef.h>
#include "dilithium_params.h"

namespace PQC {
namespace DSA {

typedef struct {
    int32_t coeffs[256];
} poly;

typedef struct {
    poly vec[DILITHIUM2_K];
} polyveck;

typedef struct {
    poly vec[DILITHIUM2_L];
} polyvecl;

// Compact (Packed) Types - RAM Armor
typedef struct {
    uint8_t bits[768]; // 256 * 24 bit (3 bytes per coeff) = 768 bytes
} packed_poly;

typedef struct {
    packed_poly vec[DILITHIUM2_K];
} packed_polyveck;

typedef struct {
    packed_poly vec[DILITHIUM2_L];
} packed_polyvecl;

class Dilithium2 {
public:
    // API
    static int keypair(uint8_t *pk, uint8_t *sk);
    static int sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
    static int verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

private:
    // Dahili matematiksel fonksiyonlar (Modular architecture)
    static void poly_ntt(poly *a);
    static void poly_invntt(poly *a);
    static void polyvecl_ntt(polyvecl *v);
    static void polyvecl_invntt(polyvecl *v);
    static void polyveck_ntt(polyveck *v);
    static void polyveck_invntt(polyveck *v);
    
    // Yardımcılar
    static void challenge(poly *c, const uint8_t seed[DILITHIUM_SEEDBYTES]);
};

} // namespace DSA
} // namespace PQC

#endif
