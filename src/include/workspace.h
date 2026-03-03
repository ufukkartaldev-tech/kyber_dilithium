#ifndef PQC_WORKSPACE_H
#define PQC_WORKSPACE_H

#include <stdint.h>
#include "params.h"
#include "dilithium_params.h"
#include "poly.h"

namespace PQC {
namespace Memory {

/**
 * PQC_Workspace (Gümüşhane Usulü Bellek Geri Dönüşümü)
 * Kyber ve Dilithiumoperasyonları aynı anda çalışmaz. 
 */
union SharedWorkspace {
    // 1. Yazılım Veri Katmanı (Keys, Ciphertexts)
    struct {
        uint8_t pk[3000];
        uint8_t sk[4500];
        uint8_t sig[DILITHIUM2_SIGNBYTES];
        uint8_t ct[1500];
        uint8_t ss[64];
    } data;

    // 2. Matematiksel Geri Dönüşüm Katmanı (Math Workspace)
    struct {
        // Kyber (16-bit coeffs)
        polyvec kv1, kv2, kv3, kv4, kv5;
        poly    kp1, kp2, kp3;
        // Dilithium (32-bit coeffs)
        PQC::DSA::polyvecl dvl;
        PQC::DSA::polyveck dvk1, dvk2, dvk3;
        PQC::DSA::poly dp1, dp2;
    } maths;

    // Ortak büyük çalışma alanı (Total Scratchpad)
    uint8_t raw[16384]; // 16 KB total static allocated
};

// Global tek bir workspace
extern SharedWorkspace workspace;

} // namespace Memory
} // namespace PQC

#endif
