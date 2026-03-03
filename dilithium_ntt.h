#ifndef DILITHIUM_NTT_H
#define DILITHIUM_NTT_H

#include <stdint.h>
#include "dilithium_params.h"

void dilithium_ntt(int32_t a[256]);
void dilithium_invntt(int32_t a[256]);

#endif
