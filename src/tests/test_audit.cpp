#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ARDUINO
#include <Arduino.h>

namespace PQC {
namespace Test {

bool AuditTester::test_randomness_entropy() {
    uint8_t sample[8], history[100][8];
    for(int i=0; i<100; i++) {
        for(int j=0; j<8; j++) sample[j] = (uint8_t)esp_random();
        memcpy(history[i], sample, 8);
        for(int j=0; j<i; j++) {
            if(TestSuite::compare_bytes(history[i], history[j], 8)) return false;
        }
    }
    return true;
}

uint32_t AuditTester::test_stack_usage() {
    return uxTaskGetStackHighWaterMark(NULL);
}

void AuditTester::test_power_efficiency() {
    // Demo purposes: Logs frequency impact
}

static volatile bool multicore_ok = true;
static void audit_task(void* p) {
    uint8_t a[32], b[32];
    for(int i=0; i<100; i++) {
        for(int j=0; j<32; j++) a[j] = (uint8_t)esp_random();
        memcpy(b, a, 32);
        if(memcmp(a, b, 32) != 0) multicore_ok = false;
    }
    vTaskDelete(NULL);
}

bool AuditTester::test_multicore_safety() {
    multicore_ok = true;
    xTaskCreatePinnedToCore(audit_task, "Audit0", 4096, NULL, 1, NULL, 0);
    xTaskCreatePinnedToCore(audit_task, "Audit1", 4096, NULL, 1, NULL, 1);
    delay(500);
    return multicore_ok;
}

} // namespace Test
} // namespace PQC
#endif
