/*
  MODERN PQC (Post-Quantum Cryptography) ESP32 DEMO
  -----------------------------------------------
  Bu proje, Kyber (KEM) ve Dilithium (DSA) algoritmalarını modular bir C++ 
  yapısında (Namespace/Class) ESP32 üzerinde sıfırdan çalıştırır.
*/

#include <Arduino.h>
#include "src/include/kyber_modular.h"
#include "src/include/dilithium.h"

using namespace PQC::KEM;
using namespace PQC::DSA;

// Bellek tamponları (Statik)
static uint8_t pk[2048];
static uint8_t sk[4096];
static uint8_t sig[DILITHIUM2_SIGNBYTES];
static uint8_t ct[KYBER_512_CIPHERTEXTBYTES];
static uint8_t ss_enc[32], ss_dec[32];

void test_kyber() {
    uint32_t t0, t1;
    Serial.println("\n--- [MODULAR] KYBER-512 TEST ---");
    
    t0 = micros();
    Kyber512::keypair(pk, sk);
    t1 = micros();
    Serial.print("KeyGen: "); Serial.print(t1 - t0); Serial.println(" us");

    Kyber512::encaps(ct, ss_enc, pk);
    Kyber512::decaps(ss_dec, ct, sk);

    if (memcmp(ss_enc, ss_dec, 32) == 0) Serial.println("DURUM: KYBER BASARILI!");
    else Serial.println("DURUM: KYBER HATA!");
}

void test_dilithium() {
    uint32_t t0, t1;
    Serial.println("\n--- [MODULAR] DILITHIUM-2 TEST ---");
    
    const uint8_t message[] = "GumusDil PQC Security Test";
    size_t siglen;

    t0 = micros();
    Dilithium2::keypair(pk, sk); // pk:rho+t1, sk:rho+K+tr+s1+s2+t0
    t1 = micros();
    Serial.print("KeyGen: "); Serial.print(t1 - t0); Serial.println(" us");

    t0 = micros();
    Dilithium2::sign(sig, &siglen, message, sizeof(message), sk);
    t1 = micros();
    Serial.print("Sign: "); Serial.print(t1 - t0); Serial.println(" us");
    
    Serial.println("DURUM: DILITHIUM TASLAK HAZIR!");
}

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n===== ESP32 POST-QUANTUM SUITE (KYBER & DILITHIUM) =====");
    
    test_kyber();
    test_dilithium();
}

void loop() {
    delay(15000);
    test_kyber();
    test_dilithium();
}
