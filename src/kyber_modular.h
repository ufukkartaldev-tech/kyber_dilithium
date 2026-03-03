#ifndef KYBER_MODULAR_H
#define KYBER_MODULAR_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "poly.h"

namespace PQC {
namespace KEM {

class KyberBase {
protected:
    // Ortak yardımcı matematik fonksiyonları
    static void gen_matrix(polyvec *a, const uint8_t seed[32], int k, int transposed);
};

class Kyber512 : public KyberBase {
public:
    static const int K = 2;
    static int keypair(uint8_t *pk, uint8_t *sk);
    static int encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    static int decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
};

class Kyber768 : public KyberBase {
public:
    static const int K = 3;
    static int keypair(uint8_t *pk, uint8_t *sk);
    static int encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    static int decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
};

} // namespace KEM
} // namespace PQC

#endif
