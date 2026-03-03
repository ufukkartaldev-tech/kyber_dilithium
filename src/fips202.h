#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>
#include <stddef.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const uint8_t *input, size_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(uint8_t *output, size_t outlen, keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *input, size_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(uint8_t *output, size_t outlen, keccak_state *state);

void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);

#endif
