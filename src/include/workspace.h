#ifndef PQC_WORKSPACE_H
#define PQC_WORKSPACE_H

#include <stdint.h>
#include "params.h"
#include "dilithium_params.h"
#include "poly.h"
#include "bitpack.h"

namespace PQC {
namespace Memory {

/**
 * PQC_Workspace (Gümüşhane Usulü Bellek Geri Dönüşümü)
 * Bit-packing teknolojisi ile RAM kullanımında %40-50 tasarruf hedefler.
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

    // 2. Matematiksel Ham Katman (Active Calc - Unpacked)
    struct {
        polyvec kv1, kv2, kv3, kv4, kv5;
        poly    kp1, kp2, kp3;
        PQC::DSA::polyvecl dvl;
        PQC::DSA::polyveck dvk1, dvk2, dvk3;
        PQC::DSA::poly dp1, dp2;
    } maths;

    // 3. Matematiksel Sıkıştırılmış Katman (Deep Sleep Storage - Packed)
    // Sadece saklanacak (arada bekleyecek) veriler için %25-40 kar sağlar.
    struct {
        packed_polyvec kv1, kv2, kv3, kv4, kv5;
        PQC::DSA::packed_polyvecl dvl;
        PQC::DSA::packed_polyveck dvk1, dvk2;
    } compact;

    uint8_t raw[16384]; 
};

extern SharedWorkspace workspace;

} // namespace Memory
} // namespace PQC

#endif
