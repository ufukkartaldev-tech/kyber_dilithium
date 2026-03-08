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
 * Core 0 (Ağ) ve Core 1 (Kriptografi) için ayrı bellek alanları.
 * Bellek çakışmalarını ve kitlenmeleri önler.
 */

// Core 1 - Kriptografik Matematik için 16KB Union (sadece Core 1 kullanır)
union CryptoWorkspace {
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

// Core 0 - Ağ verileri için ayrı buffer (Ring Buffer dışında kalanlar)
struct NetworkWorkspace {
    uint8_t temp_buffer[4096];  // Geçici ağ verileri
    uint8_t encryption_buffer[2048];  // Şifreleme için geçici alan
    uint8_t packet_buffer[512];  // Paket oluşturma için
};

extern CryptoWorkspace crypto_workspace;  // Sadece Core 1 erişir
extern NetworkWorkspace network_workspace;  // Sadece Core 0 erişir

} // namespace Memory
} // namespace PQC

#endif
