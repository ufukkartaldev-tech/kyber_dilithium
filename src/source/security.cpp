#include "../include/security.h"
#include "../include/health.h"
#include "../include/storage.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace Security {

volatile int SecurityOfficer::failed_attempts = 0;
volatile uint32_t SecurityOfficer::last_fail_time = 0;
volatile bool SecurityOfficer::system_locked_1 = false;
volatile uint32_t SecurityOfficer::system_locked_2 = 0;

void SecurityOfficer::init() {
    failed_attempts = 0;
    last_fail_time = 0;
    system_locked_1 = false;
    system_locked_2 = 0;
}

void SecurityOfficer::check_entropy_lock() {
    using PQC::System::HealthMonitor;
    float quality = HealthMonitor::check_rng_entropy();
    
    // Esik deger: %75 (%100 normalize uzerinden 0.75)
    if (quality < 0.75f) {
        #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
        Serial.print("!!! KRITIK GUVENLIK ACIGI: RNG Entropisi cok dusuk: %");
        Serial.println(quality * 100.0);
        #endif
        panic_wipe();
    }
}

void SecurityOfficer::report_signature_result(bool success) {
    if (is_system_locked()) return;

    uint32_t now = 0;
    #ifdef ARDUINO
    now = millis();
    #endif

    if (success) {
        failed_attempts = 0; 
    } else {
        failed_attempts++;
        
        // Brute-force flood protection (User Request: 30sn window)
        if (now - last_fail_time < 30000) {
           if (failed_attempts > FLOOD_THRESHOLD) {
               #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
               Serial.println("\n!!! GUVENLIK IHLALI: Seri Imza Hatasi (Flood Attack) Algilandi !!!");
               #endif
               panic_wipe();
               return;
           }
        } else {
           // 30 saniye gectiyse sayaci yariya indir (decay)
           failed_attempts /= 2;
        }
        last_fail_time = now;

        #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
        Serial.print("!!! GUVENLIK UYARISI: Yanlis Imza Denemesi "); 
        Serial.print(failed_attempts); Serial.print("/"); Serial.println(MAX_ATTEMPTS);
        #endif
        
        if (failed_attempts >= MAX_ATTEMPTS) {
            panic_wipe();
        }
    }
}

void SecurityOfficer::panic_wipe() {
    system_locked_1 = true;
    system_locked_2 = LOCK_MAGIC_VAL;
    
    #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
    Serial.println("\n#############################################");
    Serial.println("# !!! PANIK MODU: GUVENLIK IHLALI TESPITI !!! #");
    Serial.println("# Tüm Anahtarlar NVS Bellekten Siliniyor!     #");
    Serial.println("###############################################");
    #endif

    // Fiziksel İmha (KeyVault Wipe)
    PQC::System::KeyVault::destroy_vault();
}

bool SecurityOfficer::is_system_locked() {
    // Redundant Check: İki kontrol de geçmeli (Fault Injection Koruması)
    return (system_locked_1 == true) || (system_locked_2 == LOCK_MAGIC_VAL);
}

// Constant-Time Comparison (Timing Attack Koruması)
bool SecurityOfficer::verify_const_time(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return (diff == 0);
}

// Fault Injection / Glitch Koruması
bool SecurityOfficer::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    bool res1 = verify_const_time(a, b, len);
    
    volatile int dummy = 0;
    for(int i=0; i<10; i++) dummy++;

    bool res2 = verify_const_time(a, b, len);

    if (res1 != res2) {
        #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
        Serial.println("!!! GUVENLIK IHLALI: Hata Verdirme (Fault Injection) Algilandi !!!");
        #endif
        panic_wipe();
        return false;
    }

    return res1;
}

} // namespace Security
} // namespace PQC
