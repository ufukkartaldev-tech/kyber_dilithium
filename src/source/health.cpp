#include "../include/health.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>

namespace PQC {
namespace System {

void HealthMonitor::report_state(const char* operation_name, uint32_t duration_us) {
    size_t free_ram = ESP.getFreeHeap();
    size_t min_ever_ram = ESP.getMinFreeHeap();
    
    Serial.println("\n--- [HEALTH MONITOR] ---");
    Serial.print("Operasyon: "); Serial.println(operation_name);
    Serial.print("Sure     : "); Serial.print(duration_us); Serial.println(" us");
    Serial.print("RAM Bos  : "); Serial.print(free_ram / 1024.0); Serial.println(" KB");
    Serial.print("RAM Min  : "); Serial.print(min_ever_ram / 1024.0); Serial.println(" KB (Sistem Stresi)");
    
    // CPU Frekansı
    Serial.print("CPU Freq : "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
    Serial.println("------------------------");
}

size_t HealthMonitor::get_free_ram() {
    return ESP.getFreeHeap();
}

size_t HealthMonitor::get_min_free_ram() {
    return ESP.getMinFreeHeap();
}

void HealthMonitor::print_performance_table() {
    Serial.println("\n===== GUMUSDIL PQC SYSTEM REPORT =====");
    Serial.println("| Metric               | Value        | Unit |");
    Serial.println("|----------------------|--------------|------|");
    Serial.print("| Total SRAM           | 520          | KB   |\n");
    Serial.print("| Current Free RAM     | "); Serial.print(ESP.getFreeHeap()/1024.0); Serial.println("        | KB   |");
    Serial.print("| Max Recorded Stress  | "); Serial.print((520.0 - (ESP.getMinFreeHeap()/1024.0))); Serial.println("        | KB   |");
    Serial.print("| System Uptime        | "); Serial.print(millis()/1000); Serial.println("           | sec  |");
    Serial.println("======================================");
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
