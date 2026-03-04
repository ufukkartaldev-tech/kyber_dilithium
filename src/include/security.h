#ifndef PQC_SECURITY_H
#define PQC_SECURITY_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace Security {

/**
 * SecurityOfficer Sınıfı
 * Aktif savunma mekanizmalarını yönetir. Yanlış imza denemelerini takip eder
 * ve tehlike anında anahtarları bellekten siler (Panic Button/Anti-Tamper).
 */
class SecurityOfficer {
public:
    static void init();
    
    // İmza doğruluğunu bildir
    static void report_signature_result(bool success);
    
    // Bellekteki tüm hassas verileri anında sil (Panic Mode)
    static void panic_wipe();
    
    // Sistem kilitlendi mi?
    static bool is_system_locked();

    // Sabit Zamanlı Karşılaştırma (Timing Attack Koruması)
    // Veriler farklı olsa bile her zaman aynı sürede çalışır.
    static bool verify_const_time(const uint8_t* a, const uint8_t* b, size_t len);

    // Hata Saldırısı Korumalı Karşılaştırma (Fault Injection/Glitch Koruması)
    // İşlemi iki kez yapıp tutarlılığı kontrol eder.
    static bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len);

    // Entropi Kontrolü (Kalitesiz zarla oyun oynanmaz)
    static void check_entropy_lock();

private:
    static volatile int failed_attempts;
    static volatile uint32_t last_fail_time;
    static const int MAX_ATTEMPTS = 5;
    static const int FLOOD_THRESHOLD = 50; // 30 sn'de 50 hata = Panic
    
    // Redundant Lock Flags (Hardware Glitch/Fault Injection Koruması)
    static volatile bool system_locked_1;
    static volatile uint32_t system_locked_2; 
    static const uint32_t LOCK_MAGIC_VAL = 0xACE0BEEF;
};

} // namespace Security
} // namespace PQC

#endif
