#include "../include/ota.h"
#include "../include/dilithium.h"
#include "../include/security.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace System {

uint8_t OTAGuard::root_public_key[1312];
bool OTAGuard::pk_set = false;

void OTAGuard::set_root_pk(const uint8_t* pk) {
    memcpy(root_public_key, pk, 1312);
    pk_set = true;
}

bool OTAGuard::verify_update(const uint8_t* update_data, size_t total_len) {
    if (!pk_set) {
        #ifndef PQC_SILENT_MODE
        Serial.println("OTA ERROR: Root Public Key not set! Cannot verify.");
        #endif
        return false;
    }

    if (total_len <= 2420) return false; // Sadece imza veya boş veri

    const uint8_t* signature = update_data;
    const uint8_t* firmware = update_data + 2420;
    size_t firmware_len = total_len - 2420;

    #ifndef PQC_SILENT_MODE
    Serial.println("OTA: Guncelleme paketi Dilithium (DSA) ile dogrulaniyor...");
    #endif

    // Dilithium doğrulaması
    int res = PQC::DSA::Dilithium2::verify(signature, 2420, firmware, firmware_len, root_public_key);

    if (res == 0) {
        #ifndef PQC_SILENT_MODE
        Serial.println("OTA SUCCESS: Guncelleme imzasi gecerli. Yazilim orijinaldir.");
        #endif
        return true;
    } else {
        #ifndef PQC_SILENT_MODE
        Serial.println("!!! OTA SECURITY ALERT: GECERSIZ IMZA! Sahte guncelleme paketi tespit edildi.");
        #endif
        Security::SecurityOfficer::report_signature_result(false);
        return false;
    }
}

} // namespace System
} // namespace PQC
