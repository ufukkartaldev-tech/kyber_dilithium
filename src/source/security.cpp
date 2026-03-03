#include "../include/security.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace Security {

int SecurityOfficer::failed_attempts = 0;
bool SecurityOfficer::system_locked = false;

void SecurityOfficer::init() {
    failed_attempts = 0;
    system_locked = false;
}

void SecurityOfficer::report_signature_result(bool success) {
    if (system_locked) return;

    if (success) {
        failed_attempts = 0; // Başarılı girişte sayacı sıfırla
    } else {
        failed_attempts++;
        #ifdef ARDUINO
        Serial.print("!!! GÜVENLİK UYARISI: Yanlış İmza Denemesi "); 
        Serial.print(failed_attempts); Serial.print("/"); Serial.println(MAX_ATTEMPTS);
        #endif
        
        if (failed_attempts >= MAX_ATTEMPTS) {
            panic_wipe();
        }
    }
}

void SecurityOfficer::panic_wipe() {
    system_locked = true;
    #ifdef ARDUINO
    Serial.println("\n#############################################");
    Serial.println("# !!! PANIK MODU: GUVENLIK IHLALI TESPITI !!! #");
    Serial.println("# TUM ANAHTARLAR BELLEKTEN SILINIYOR...      #");
    Serial.println("#############################################");
    #endif
    
    // Not: Gerçek uygulamada burada NVS/Flash bölgeleri de temizlenmelidir.
    // Bu fonksiyon çağrıldığında üst katman (main sketch) tüm bufferları sıfırlamalıdır.
}

bool SecurityOfficer::is_system_locked() {
    return system_locked;
}

} // namespace Security
} // namespace PQC
