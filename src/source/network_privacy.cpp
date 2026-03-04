#include "../include/network_privacy.h"
#include "../include/encryption.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace Network {

uint8_t NetworkPrivacy::privacy_key[32];
bool NetworkPrivacy::key_set = false;

void NetworkPrivacy::set_privacy_key(const uint8_t key[32]) {
    memcpy(privacy_key, key, 32);
    key_set = true;
}

void NetworkPrivacy::wrap(fragment_packet_t* out, const packet_header_t* header, const uint8_t* payload, size_t payload_len) {
    if (!key_set) return;

    // IV üret
    #ifdef ARDUINO
    for(int i=0; i<12; i++) out->iv[i] = (uint8_t)esp_random();
    #else
    for(int i=0; i<12; i++) out->iv[i] = (uint8_t)rand();
    #endif

    // Header ve Payload'u birleştir
    uint8_t plain[sizeof(packet_header_t) + 210]; // Max size
    size_t header_len = sizeof(packet_header_t);
    memcpy(plain, header, header_len);
    if (payload && payload_len > 0) {
        memcpy(plain + header_len, payload, payload_len);
    }

    // Şifrele (Header + Payload)
    PQC::Symmetric::AES256GCM::encrypt(out->data, out->auth_tag, plain, header_len + payload_len, privacy_key, out->iv);
}

bool NetworkPrivacy::unwrap(packet_header_t* header, uint8_t* payload, const fragment_packet_t* in) {
    if (!key_set) return false;

    uint8_t plain[250];
    // Max data size = 222
    int res = PQC::Symmetric::AES256GCM::decrypt(plain, in->data, 222, in->auth_tag, privacy_key, in->iv);
    
    if (res == 0) {
        memcpy(header, plain, sizeof(packet_header_t));
        if (header->payload_len > 0) {
            memcpy(payload, plain + sizeof(packet_header_t), header->payload_len);
        }
        return true;
    }
    return false;
}

} // namespace Network
} // namespace PQC
