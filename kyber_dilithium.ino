/*
  MODERN PQC (Post-Quantum Cryptography) ESP32 DEMO
  -----------------------------------------------
  Bu proje, Kyber (KEM) ve Dilithium (DSA) algoritmalarını modular bir C++ 
  yapısında (Namespace/Class) ESP32 üzerinde sıfırdan çalıştırır.
*/

#include "src/include/pqc_config.h"
#include "src/include/kyber_modular.h"
#include "src/include/dilithium.h"
#include "src/include/encryption.h"
#include "src/include/network.h"

#ifdef ENABLE_PQC_TESTS
  #include "src/tests/test_suite.h"
  using namespace PQC::Test;
#endif

using namespace PQC::KEM;
using namespace PQC::DSA;
using namespace PQC::Symmetric;
using namespace PQC::Network;

const uint8_t PEER_MAC[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};

// Bellek tamponları (Statik)
static uint8_t pk[2048];
static uint8_t sk[4096];
static uint8_t sig[DILITHIUM2_SIGNBYTES];
static uint8_t ct[2048]; // Kyber-768 için yeterli
static uint8_t ss_enc[32], ss_dec[32];

void test_authenticated_encryption() {
    Serial.println("\n--- KIMLIK DOGRULAMALI SIFRELEME (KYBER + DILITHIUM + CHACHA20) ---");
    
    // 1. Anahtar Hazirliklari
    uint8_t d_pk[DILITHIUM2_PUBLICKEYBYTES];
    uint8_t d_sk[DILITHIUM2_SECRETKEYBYTES];
    size_t sig_len;
    
    // Kyber ve Dilithium anahtar çiftlerini üret
    Kyber512::keypair(pk, sk);
    Dilithium2::keypair(d_pk, d_sk);
    
    // 2. Mesaj ve Kimlik Doğrulama (İmzalama)
    const char* original_msg = "GumusDil PQC: Kuantum Guvenli ve Kimlik Dogrulamali Veri Paketi!";
    size_t msg_len = strlen(original_msg);
    uint8_t encrypted[128];
    uint8_t decrypted[128];
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    
    Serial.print("Orijinal Mesaj : "); Serial.println(original_msg);
    
    // Orijinal mesajı Dilithium ile imzala (Gönderen doğrulaması)
    Dilithium2::sign(sig, &sig_len, (const uint8_t*)original_msg, msg_len, d_sk);
    Serial.println("DURUM: Mesaj Dilithium (DSA) ile imzalandi.");
    
    // 3. Anahtar Değişimi ve Şifreleme (Privacy)
    Kyber512::encaps(ct, ss_enc, pk);
    ChaCha20::process(encrypted, (const uint8_t*)original_msg, msg_len, ss_enc, nonce);
    Serial.println("DURUM: Mesaj Kyber (KEM) + ChaCha20 ile sifrelendi.");
    
    // 4. KABLOSUZ GÖNDERİM (Reliable fragmentation)
    Serial.println("--- KABLOSUZ TRANSFER BASLATILIYOR (Reliable) ---");
    bool send_success = Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
    if(send_success) Serial.println("DURUM: Sifreli veri havadan basariyla gonderildi.");
    
    // Dilithium imzasını parçalı gönder (Büyük veri testi)
    send_success &= Messenger::send_reliable(PEER_MAC, sig, sig_len);
    if(send_success) Serial.println("DURUM: Dilithium Imzasi (2.4KB) parcali olarak gonderildi.");

    // 5. ALICI TARAFI (Verification & Decryption)
    Serial.println("--- ALICI ISLEMLERI ---");
    
    // A. Önce İmza Doğrulaması (Kim bu gönderen?)
    int verify_res = Dilithium2::verify(sig, sig_len, (const uint8_t*)original_msg, msg_len, d_pk);
    
    if (verify_res == 0) {
        Serial.println("DURUM: Dilithium Imzasi GEÇERLİ! (Gonderen Dogrulandi)");
        
        // B. Anahtarı Çöz ve Mesajı Oku
        Kyber512::decaps(ss_dec, ct, sk);
        ChaCha20::process(decrypted, encrypted, msg_len, ss_dec, nonce);
        decrypted[msg_len] = '\0';
        
        Serial.print("Cozulmus Mesaj : "); Serial.println((char*)decrypted);
        Serial.println("SONUC: Tam Guvenlik Saglandi! (Gizlilik + Butunluk + Kimlik)");
    } else {
        Serial.println("HATA: Gecersiz Imza! Veri sahte veya bozulmus.");
    }
}

void test_adaptive_authenticated_encryption() {
    Serial.println("\n--- ADAPTIVE PQC HANDSHAKE (KYBER SENSING) ---");
    
    // 1. Link Kalitesini Ölçmek için Prob Gönder
    uint8_t probe = 0xA5;
    Messenger::send_reliable(PEER_MAC, &probe, 1);
    int retries = Messenger::get_last_retry_count();
    
    bool high_security = (retries == 0); // Hiç hata yoksa 768 kullan
    
    uint8_t d_pk[DILITHIUM2_PUBLICKEYBYTES];
    uint8_t d_sk[DILITHIUM2_SECRETKEYBYTES];
    size_t sig_len;
    const char* msg = "GumusDil Adaptive PQC Packet";
    size_t msg_len = strlen(msg);
    uint8_t encrypted[64], decrypted[64];
    uint8_t nonce[12] = {0};

    if (high_security) {
        Serial.println("SENSING: Baglanti mukemmel. Kyber-768 (High Sec) moduna geciliyor.");
        Kyber768::keypair(pk, sk);
        Kyber768::encaps(ct, ss_enc, pk);
        ChaCha20::process(encrypted, (const uint8_t*)msg, msg_len, ss_enc, nonce);
        Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
        Kyber768::decaps(ss_dec, ct, sk);
    } else {
        Serial.println("SENSING: Gurultulu kanal! Kyber-512 (Small/Robust) moduna geciliyor.");
        Kyber512::keypair(pk, sk);
        Kyber512::encaps(ct, ss_enc, pk);
        ChaCha20::process(encrypted, (const uint8_t*)msg, msg_len, ss_enc, nonce);
        Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
        Kyber512::decaps(ss_dec, ct, sk);
    }
    
    ChaCha20::process(decrypted, encrypted, msg_len, ss_dec, nonce);
    decrypted[msg_len] = '\0';
    Serial.print("SONUC: Cozulen Mesaj: "); Serial.println((char*)decrypted);
}

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
    
    // Ağ ve ESP-NOW Katmanını başlat
    Messenger::init();
    
    // Uygulama başlamadan önce birim testleri (Unit Tests) çalıştır
    #ifdef ENABLE_PQC_TESTS
      TestSuite::run_all_tests();
    #endif
    
    test_kyber();
    test_dilithium();
    test_authenticated_encryption();
    test_adaptive_authenticated_encryption();
}

void loop() {
    delay(15000);
    test_kyber();
    test_dilithium();
    test_authenticated_encryption();
    test_adaptive_authenticated_encryption();
}
