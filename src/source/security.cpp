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

// Constant-Time Comparison (Timing Attack Koruması)
// Bir baytı kontrol edip hemen 'yanlış' dönmez; tüm baytları tarar.
bool SecurityOfficer::verify_const_time(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    // diff == 0 ise veriler aynıdır.
    return (diff == 0);
}

// Fault Injection / Glitch Koruması
// İşlemi iki kez yapar, araya minik bir bekleme (veya dummy op) koyar.
// Eğer bir saldırgan tek bir anı 'glitch' ile atlatsa bile ikinci kontrol yakalar.
bool SecurityOfficer::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    bool res1 = verify_const_time(a, b, len);
    
    // Minik bir dummy döngü (Saldırganın zamanlama tahminini bozar)
    volatile int dummy = 0;
    for(int i=0; i<10; i++) dummy++;

    bool res2 = verify_const_time(a, b, len);

    // İki sonuç da aynı olmalı. Eğer biri doğru biri yanlışsa müdahale vardır!
    if (res1 != res2) {
        #ifdef ARDUINO
        Serial.println("!!! GÜVENLİK İHLALİ: Hata Verdirme (Fault Injection) Algılandı !!!");
        #endif
        panic_wipe();
        return false;
    }

    return res1;
}

} // namespace Security
} // namespace PQC
