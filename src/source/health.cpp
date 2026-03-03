#include "../include/health.h"
#include "../include/pqc_config.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#include <cmath> // log2 için

namespace PQC {
namespace System {

void HealthMonitor::report_state(const char* operation_name, uint32_t duration_us) {
    size_t free_ram = ESP.getFreeHeap();
    size_t min_ever_ram = ESP.getMinFreeHeap();
    #ifndef PQC_SILENT_MODE
    Serial.println("\n--- [HEALTH MONITOR] ---");
    Serial.print("Operasyon: "); Serial.println(operation_name);
    Serial.print("Sure     : "); Serial.print(duration_us); Serial.println(" us");
    Serial.print("RAM Bos  : "); Serial.print(free_ram / 1024.0); Serial.println(" KB");
    Serial.print("RAM Min  : "); Serial.print(min_ever_ram / 1024.0); Serial.println(" KB (Sistem Stresi)");
    Serial.print("CPU Freq : "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
    Serial.println("------------------------");
    #endif
}

size_t HealthMonitor::get_free_ram() {
    return ESP.getFreeHeap();
}

size_t HealthMonitor::get_min_free_ram() {
    return ESP.getMinFreeHeap();
}

void HealthMonitor::print_performance_table() {
    #ifndef PQC_SILENT_MODE
    Serial.println("\n===== GUMUSDIL PQC SYSTEM REPORT =====");
    Serial.println("| Metric               | Value        | Unit |");
    Serial.println("|----------------------|--------------|------|");
    Serial.print("| Total SRAM           | 520          | KB   |\n");
    Serial.print("| Current Free RAM     | "); Serial.print(ESP.getFreeHeap()/1024.0); Serial.println("        | KB   |");
    Serial.print("| Max Recorded Stress  | "); Serial.print((520.0 - (ESP.getMinFreeHeap()/1024.0))); Serial.println("        | KB   |");
    Serial.print("| RNG Entropy Quality  | "); Serial.print(check_rng_entropy() * 100.0); Serial.println("         | %    |");
    Serial.print("| System Uptime        | "); Serial.print(millis()/1000); Serial.println("           | sec  |");
    Serial.println("======================================");
    #endif
}

// Shannon Entropisi: Rastgelelik Kalite Testi (Gümüshane Usulü Zar Kontrolü)
float HealthMonitor::check_rng_entropy() {
    uint8_t buffer[128]; // 1024 bit örneklem
    for(int i=0; i<32; i++) {
        uint32_t r = esp_random();
        memcpy(buffer + (i*4), &r, 4);
    }
    
    float entropy = calculate_shannon_entropy(buffer, 128);
    // Maksimum entropi 8.0 bit/byte'dır. 0.0-1.0 arasına normalize ederken 8'e bölüyoruz.
    return (entropy / 8.0f); 
}

float HealthMonitor::calculate_shannon_entropy(const uint8_t* data, size_t len) {
    uint32_t freq[256] = {0};
    for(size_t i=0; i<len; i++) freq[data[i]]++;
    
    float ent = 0;
    for(int i=0; i<256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / (float)len;
            ent -= p * log2f(p);
        }
    }
    return ent;
}

} // namespace System
} // namespace PQC

#else
// PC Mock Implementation
namespace PQC {
namespace System {
void HealthMonitor::report_state(const char* n, uint32_t d) { printf("[PC HEALTH] %s: %u us\n", n, d); }
size_t HealthMonitor::get_free_ram() { return 0; }
size_t HealthMonitor::get_min_free_ram() { return 0; }
void HealthMonitor::print_performance_table() { printf("[PC] System report only available on ESP32 hardware.\n"); }
}
}
#endif
