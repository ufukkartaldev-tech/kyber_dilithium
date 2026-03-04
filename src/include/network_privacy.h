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

    // Ağ gizlilik anahtarını ayarla
    static void set_privacy_key(const uint8_t key[32]);

private:
    static uint8_t privacy_key[32];
    static bool key_set;
};

} // namespace Network
} // namespace PQC

#endif
