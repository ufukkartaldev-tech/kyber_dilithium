#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

// Montgomery reduction sabitleri
#define MONT 2285 // 2^16 % 3329
#define QINV 62209 // q^-1 mod 2^16

void ntt(int16_t poly[256]);
void invntt(int16_t poly[256]);
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);
int16_t montgomery_reduce(int32_t a);
// Barrett Reduction: a mod 3329
// Sayıyı her zaman [0, 3328] arasına hapseder.
int16_t barrett_reduce(int16_t a);

extern const int16_t zetas[128];

#endif
