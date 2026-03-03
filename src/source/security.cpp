#include "../include/security.h"
#include "../include/health.h"
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
    if (system_locked) return;

    if (success) {
        failed_attempts = 0; // Basarili giriste sayaci sifirla
    } else {
        #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
        failed_attempts++;
        Serial.print("!!! GUVENLIK UYARISI: Yanlis Imza Denemesi "); 
        Serial.print(failed_attempts); Serial.print("/"); Serial.println(MAX_ATTEMPTS);
        #else
        failed_attempts++;
        #endif
        
        if (failed_attempts >= MAX_ATTEMPTS) {
            panic_wipe();
        }
    }
}

void SecurityOfficer::panic_wipe() {
    system_locked = true;
    #if defined(ARDUINO) && !defined(PQC_SILENT_MODE)
    Serial.println("\n#############################################");
    Serial.println("# !!! PANIK MODU: GUVENLIK IHLALI TESPITI !!! #");
    #endif
}

bool SecurityOfficer::is_system_locked() {
    return system_locked;
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
