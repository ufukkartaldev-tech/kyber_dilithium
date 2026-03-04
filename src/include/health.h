#ifndef PQC_HEALTH_H
#define PQC_HEALTH_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace System {

/**
 * HealthMonitor Sınıfı
 * Sistemin RAM kullanımı, CPU yükü ve PQC operasyon sürelerini takip eder.
 */
class HealthMonitor {
public:
    static void report_state(const char* operation_name, uint32_t duration_us);
    
    // RAM analizi
    static size_t get_free_ram();
    static size_t get_min_free_ram();
    
    // CPU analizi (ESP32 için)
    static float get_cpu_usage();

    // Entropi (RNG) Analizi
    static float check_rng_entropy(); // [0.0, 1.0] arası kalite puanı

    // Raporlama Aracı
    static void print_performance_table();

    // Hardware Security Status
    static bool is_flash_encrypted();
    static bool is_secure_boot_active();

private:
    static float calculate_shannon_entropy(const uint8_t* data, size_t len);
    static uint32_t last_idle_time;
    static uint32_t last_report_time;
};

} // namespace System
} // namespace PQC

#endif
