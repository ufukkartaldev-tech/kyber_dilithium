/*
  KYBER (ML-KEM) ESP32 IMPLEMENTATION - FROM SCRATCH
  --------------------------------------------------
  Bu kod, NIST standardı Kyber-512 (Level 1) ve Kyber-768 (Level 2) algoritmalarını 
  ESP32 üzerinde sıfırdan çalışacak şekilde tasarlanmıştır.
  
  NEDEN KUANTUM SONRASI (POST-QUANTUM) GÜVENLİ?
  Klasik bilgisayarlar sayıları çarpanlarına ayırmada zayıftır (RSA'nın temeli) veya 
  logaritma problemlerinde (ECC'nin temeli) zorlanır. Kuantum bilgisayarlar (Shor Algoritması ile) 
  bu problemleri saniyeler içinde çözebilir. Kyber ise "Lattice" (Kafes) tabanlı matematik 
  kullanır. Bu kafes yapılarındaki "En Yakın Vektörü Bulma" (LWE - Learning With Errors) 
  problemi, kuantum bilgisayarlar için bile bilinen etkin bir çözümü olmayan, çok boyutlu 
  ve karmaşık bir matematiksel labirenttir. Bu yüzden geleceğe hazır bir kriptografidir.
*/

#include <Arduino.h>
#include "src/kyber.h"
#include "src/params.h"

// Bellek kullanımını minimize etmek ve dinamik bellekten (malloc) kaçınmak için 
// tüm tamponları (buffer) global ve statik olarak tanımlıyoruz. 
// Bu sayede çalışma anında bellek sızıntısı riski sıfıra iner.

static uint8_t public_key[KYBER_768_PUBLICKEYBYTES];
static uint8_t secret_key[KYBER_768_SECRETKEYBYTES];
static uint8_t ciphertext[KYBER_768_CIPHERTEXTBYTES];
static uint8_t shared_secret_enc[KYBER_SSBYTES];
static uint8_t shared_secret_dec[KYBER_SSBYTES];

void benchmark_kyber512() {
    uint32_t t0, t1;
    Serial.println("\n--- KYBER-512 (NIST LEVEL 1) BENCHMARK ---");

    // 1. Anahtar Üretimi (KeyGen)
    t0 = micros();
    kyber512_keypair(public_key, secret_key);
    t1 = micros();
    Serial.print("Anahtar Üretimi (Key Generation): "); Serial.print(t1 - t0); Serial.println(" us");

    // 2. Şifreleme (Encapsulation)
    t0 = micros();
    kyber512_encaps(ciphertext, shared_secret_enc, public_key);
    t1 = micros();
    Serial.print("Kapsülleme (Encapsulation): "); Serial.print(t1 - t0); Serial.println(" us");

    // 3. Şifre Çözme (Decapsulation)
    t0 = micros();
    kyber512_decaps(shared_secret_dec, ciphertext, secret_key);
    t1 = micros();
    Serial.print("Kapsül Açma (Decapsulation): "); Serial.print(t1 - t0); Serial.println(" us");

    // Doğrulama
    if (memcmp(shared_secret_enc, shared_secret_dec, 32) == 0) {
        Serial.println("DURUM: BASARILI! Ortak anahtarlar eslesiyor.");
    } else {
        Serial.println("DURUM: HATA! Anahtarlar uyumsuz.");
    }
}

void benchmark_kyber768() {
    uint32_t t0, t1;
    Serial.println("\n--- KYBER-768 (NIST LEVEL 2) BENCHMARK ---");

    // 1. Anahtar Üretimi
    t0 = micros();
    kyber768_keypair(public_key, secret_key);
    t1 = micros();
    Serial.print("Anahtar Üretimi (Key Generation): "); Serial.print(t1 - t0); Serial.println(" us");

    // 2. Şifreleme
    t0 = micros();
    kyber768_encaps(ciphertext, shared_secret_enc, public_key);
    t1 = micros();
    Serial.print("Kapsülleme (Encapsulation): "); Serial.print(t1 - t0); Serial.println(" us");

    // 3. Şifre Çözme
    t0 = micros();
    kyber768_decaps(shared_secret_dec, ciphertext, secret_key);
    t1 = micros();
    Serial.print("Kapsül Açma (Decapsulation): "); Serial.print(t1 - t0); Serial.println(" us");

    // Doğrulama
    if (memcmp(shared_secret_enc, shared_secret_dec, 32) == 0) {
        Serial.println("DURUM: BASARILI! Ortak anahtarlar eslesiyor.");
    } else {
        Serial.println("DURUM: HATA! Anahtarlar uyumsuz.");
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n--- ESP32 Post-Quantum Kyber Demo ---");
    Serial.println("Cihaz: ESP32-WROOM-32");
    Serial.println("Mimarisi: 32-bit Xtensa");
    
    // Benchmarkları çalıştır
    benchmark_kyber512();
    benchmark_kyber768();
}

void loop() {
    // Döngüde her 10 saniyede bir testi tekrarla
    delay(10000);
    benchmark_kyber512();
    benchmark_kyber768();
}
