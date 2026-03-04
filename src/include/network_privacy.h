#ifndef PQC_NETWORK_PRIVACY_H
#define PQC_NETWORK_PRIVACY_H

#include <stdint.h>
#include <stddef.h>
#include "network.h"

namespace PQC {
namespace Network {

/**
 * NetworkPrivacy (Stealth Katmanı)
 * Tüm paket başlıklarını ve içeriğini ortak bir ağ anahtarıyla 
 * şifreleyerek trafik analizini (Sniffing) engeller.
 */
class NetworkPrivacy {
public:
    // Paketi gürültüye dönüştür (Obfuscate)
    static void wrap(fragment_packet_t* out, const packet_header_t* header, const uint8_t* payload, size_t payload_len);

    // Gürültüden veriyi çıkar (De-obfuscate)
    static bool unwrap(packet_header_t* header, uint8_t* payload, const fragment_packet_t* in);

    // Ağ gizlilik anahtarını (Master) ayarla
    static void set_network_master_key(const uint8_t key[32]);

    // Belirli bir Epoch (Dönem) için anahtarı güncelle
    static void update_epoch_key(uint32_t epoch_id);

private:
    static uint8_t network_master_key[32]; // Ana Gizlilik Sırrı
    static uint8_t current_epoch_key[32];   // O anki aktif şifreleme anahtarı
    static uint32_t last_epoch_id;
    static bool key_set;
};

} // namespace Network
} // namespace PQC

#endif
