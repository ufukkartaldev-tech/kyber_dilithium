#include "../include/blackbox.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#include <FS.h>
#include <LittleFS.h>

namespace PQC {
namespace System {

const char* BlackBox::LOG_PATH = "/GumusLog.txt";

bool BlackBox::init() {
    // LittleFS'i başlat (FORMAT_LITTLEFS_IF_FAILED parametresi true)
    if (!LittleFS.begin(true)) {
        Serial.println("BLACKBOX ERROR: LittleFS initialization failed!");
        return false;
    }
    return true;
}

void BlackBox::log_error(const char* operation, uint32_t iteration, size_t leak_amount) {
    File log = LittleFS.open(LOG_PATH, FILE_APPEND);
    if (!log) {
        Serial.println("BLACKBOX ERROR: Failed to open log file for writing!");
        return;
    }

    log.print("[FATAL ERROR] ");
    log.print("Operation: "); log.print(operation);
    log.print(" | Iteration: "); log.print(iteration);
    log.print(" | Leak: "); log.print(leak_amount);
    log.println(" bytes");
    
    log.close();
    Serial.println("BLACKBOX: Error successfully written to Flash (Persistent Log).");
}

void BlackBox::print_saved_logs() {
    if (!LittleFS.exists(LOG_PATH)) {
        Serial.println("\n[BLACKBOX] No past error logs found. System Clean.");
        return;
    }

    Serial.println("\n===== BLACKBOX (KARA KUTU) GEÇMİŞ HATALAR =====");
    File log = LittleFS.open(LOG_PATH, FILE_READ);
    if (log) {
        while (log.available()) {
            Serial.write(log.read());
        }
        log.close();
    }
    Serial.println("==============================================");
}

void BlackBox::clear_logs() {
    if (LittleFS.remove(LOG_PATH)) {
        Serial.println("BLACKBOX: Persistent logs cleared.");
    }
}

bool BlackBox::has_past_errors() {
    return LittleFS.exists(LOG_PATH);
}

} // namespace System
} // namespace PQC

#else
// PC Mock Implementation
namespace PQC {
namespace System {
const char* BlackBox::LOG_PATH = "";
bool BlackBox::init() { return true; }
void BlackBox::log_error(const char* op, uint32_t it, size_t l) { printf("[BLACKBOX MOCK] Error: %s at %u leak %zu\n", op, it, l); }
void BlackBox::print_saved_logs() { printf("[BLACKBOX MOCK] No hardware logs on PC.\n"); }
void BlackBox::clear_logs() {}
bool BlackBox::has_past_errors() { return false; }
}
}
#endif
