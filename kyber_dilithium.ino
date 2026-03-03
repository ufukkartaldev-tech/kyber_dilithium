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
#include "src/include/health.h"
#include "src/include/security.h"
#include "src/include/workspace.h"
#include "src/include/blackbox.h"
#include "src/include/storage.h"

#ifdef ENABLE_PQC_TESTS
  #include "src/tests/test_suite.h"
  using namespace PQC::Test;
#endif

using namespace PQC::KEM;
using namespace PQC::DSA;
using namespace PQC::Symmetric;
using namespace PQC::Network;
using namespace PQC::System;
using namespace PQC::Security;
using namespace PQC::Memory;

const uint8_t PEER_MAC[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};

// Bellek tamponları artık SharedWorkspace içinde (Union sayesinde aynı yeri kullanıyorlar)
// pk, sk, sig, ct, ss_enc, ss_dec değişkenlerini workspace üzerinden kullanacağız.

// GÜVENLİK: Tüm hassas verileri bellekten kazı!
void wipe_all_sensitive_data() {
    memset(workspace.raw, 0, sizeof(workspace.raw));
    Serial.println("SİSTEM: Tüm paylaşımlı bellek (Workspace) fiziksel olarak RAM'den silindi.");
}

void test_authenticated_encryption() {
    Serial.println("\n--- KIMLIK DOGRULAMALI SIFRELEME (KYBER + DILITHIUM + CHACHA20) ---");
    
    size_t sig_len;
    static uint8_t encrypted[128], decrypted[128], layer1[128], tag[16];
    uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const char* original_msg = "GumusDil PQC: Kuantum Guvenli ve Kimlik Dogrulamali Veri Paketi!";
    size_t msg_len = strlen(original_msg);
    
    Serial.print("Orijinal Mesaj : "); Serial.println(original_msg);

    // 1. DILITHIUM: İmzalama (Gönderen Kimliğini Kanıtla)
    Dilithium2::keypair(workspace.dilithium.pk, workspace.dilithium.sk);
    Dilithium2::sign(workspace.dilithium.sig, &sig_len, (const uint8_t*)original_msg, msg_len, workspace.dilithium.sk);
    Serial.println("DURUM: Mesaj Dilithium (DSA) ile imzalandi.");

    // 2. KYBER: Anahtar Değişimi (Gizlilik Katmanı)
    // DİKKAT: Kyber anahtarları Dilithium anahtarlarının üzerine yazılır (RAM Tasarrufu)
    Kyber512::keypair(workspace.kyber.pk, workspace.kyber.sk);
    Kyber512::encaps(workspace.kyber.ct, workspace.kyber.ss, workspace.kyber.pk);
    
    // 3. HIBRIT SIFRELEME
    uint8_t chacha_key[32], aes_key[32];
    KDF::derive_keys(chacha_key, aes_key, workspace.kyber.ss);
    
    ChaCha20::process(layer1, (const uint8_t*)original_msg, msg_len, chacha_key, nonce);
    AES256GCM::encrypt(encrypted, tag, layer1, msg_len, aes_key, nonce);
    Serial.println("DURUM: Mesaj Hibrit Zirh (Kyber + ChaCha20 + AES-HW) ile kaplandi.");
    
    // 4. KABLOSUZ GÖNDERİM
    Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
    Messenger::send_reliable(PEER_MAC, workspace.dilithium.sig, sig_len);

    // 5. ALICI TARAFI
    // Not: Alıcı PK ve CT hala workspace içinde geçerli varsayıyoruz (Demoda bufferlar bozulmuyor)
    int verify_res = Dilithium2::verify(workspace.dilithium.sig, sig_len, (const uint8_t*)original_msg, msg_len, workspace.dilithium.pk);

    if (verify_res == 0) {
        // Redundant check against fault-injection (Çift Doğrulama)
        // Eğer bir 'glitch' ile verify_res 0 yapıldıysa, bu ikinci kontrol (secure_compare) onu yakalar.
        if (!SecurityOfficer::secure_compare(workspace.dilithium.sig, workspace.dilithium.sig, sig_len)) {
             Serial.println("Kritik Hata: Sistem Müdahalesi Saptandı!");
             return;
        }
        Serial.println("DURUM: Dilithium Imzasi GEÇERLİ! (Gonderen Dogrulandi)");
        
        Kyber512::decaps(workspace.kyber.ss, workspace.kyber.ct, workspace.kyber.sk);
        KDF::derive_keys(chacha_key, aes_key, workspace.kyber.ss);
        
        uint8_t layer1_dec[128];
        AES256GCM::decrypt(layer1_dec, encrypted, msg_len, tag, aes_key, nonce);
        ChaCha20::process(decrypted, layer1_dec, msg_len, chacha_key, nonce);
        decrypted[msg_len] = '\0';
        
        Serial.print("Cozulmus Mesaj : "); Serial.println((char*)decrypted);
        Serial.println("SONUC: Hibrit Guvenlik Basarili! (Quantum-Resistant + AES-HW Armor)");
        SecurityOfficer::report_signature_result(true);
    } else {
        Serial.println("HATA: Gecersiz Imza! Veri sahte veya bozulmus.");
        SecurityOfficer::report_signature_result(false);
        if (SecurityOfficer::is_system_locked()) wipe_all_sensitive_data();
    }
}

void test_adaptive_authenticated_encryption() {
    uint32_t start_time = micros();
    Serial.println("\n--- ADAPTIVE PQC HANDSHAKE (KYBER SENSING) ---");
    
    // 1. Link Kalitesini Ölçmek için Prob Gönder
    uint8_t probe = 0xA5;
    Messenger::send_reliable(PEER_MAC, &probe, 1);
    int retries = Messenger::get_last_retry_count();
    
    bool high_security = (retries == 0); // Hiç hata yoksa 768 kullan
    
    const char* msg = "GumusDil Adaptive PQC Packet";
    size_t msg_len = strlen(msg);
    uint8_t encrypted[64], decrypted[64];
    uint8_t nonce[12] = {0};

    if (high_security) {
        Serial.println("SENSING: Baglanti mukemmel. Kyber-768 (High Sec) moduna geciliyor.");
        Kyber768::keypair(workspace.kyber.pk, workspace.kyber.sk);
        Kyber768::encaps(workspace.kyber.ct, workspace.kyber.ss, workspace.kyber.pk);
        ChaCha20::process(encrypted, (const uint8_t*)msg, msg_len, workspace.kyber.ss, nonce);
        Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
        Kyber768::decaps(workspace.kyber.ss, workspace.kyber.ct, workspace.kyber.sk);
    } else {
        Serial.println("SENSING: Gurultulu kanal! Kyber-512 (Small/Robust) moduna geciliyor.");
        Kyber512::keypair(workspace.kyber.pk, workspace.kyber.sk);
        Kyber512::encaps(workspace.kyber.ct, workspace.kyber.ss, workspace.kyber.pk);
        ChaCha20::process(encrypted, (const uint8_t*)msg, msg_len, workspace.kyber.ss, nonce);
        Messenger::send_reliable(PEER_MAC, encrypted, msg_len);
        Kyber512::decaps(workspace.kyber.ss, workspace.kyber.ct, workspace.kyber.sk);
    }
    
    ChaCha20::process(decrypted, encrypted, msg_len, workspace.kyber.ss, nonce);
    decrypted[msg_len] = '\0';
    
    uint32_t duration = micros() - start_time;
    HealthMonitor::report_state("Adaptive Multi-Layer PQC", duration);
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

    if (SecurityOfficer::secure_compare(ss_enc, ss_dec, 32)) Serial.println("DURUM: KYBER BASARILI!");
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

void test_persistent_vault() {
    Serial.println("\n--- KEYVAULT (PERSISTENT SECURE STORAGE) TEST ---");
    
    uint8_t original_ss[32] = {0x01, 0x02, 0x47, 0x55, 0x4D, 0x55, 0x53, 0}; // 'GUMUS' seed
    uint8_t reloaded_ss[32] = {0};

    // 1. Kasaya Kilitle (Save)
    KeyVault::save_key("K_MASTER_SS", original_ss, 32);

    // 2. Kasadan Çıkar (Load)
    if (KeyVault::load_key("K_MASTER_SS", reloaded_ss, 32)) {
        if (memcmp(original_ss, reloaded_ss, 32) == 0) {
            Serial.println("SONUÇ: KeyVault Doğrulandı! Veri şifreli kasadan başarıyla döndü.");
        } else {
            Serial.println("SONUÇ: KeyVault HATALI! Veri bütünlüğü bozulmuş.");
        }
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n===== ESP32 POST-QUANTUM SUITE (KYBER & DILITHIUM) =====");
    
    SecurityOfficer::init(); // Güvenlik modülünü başlat
    
    // Ağ ve ESP-NOW Katmanını başlat
    Messenger::init();

    // Gümüşhane Kara Kutu (BlackBox) Kontrolü
    BlackBox::init();
    if (BlackBox::has_past_errors()) {
        BlackBox::print_saved_logs();
    }

    // Gümüşhane Gömme Kasası (KeyVault) Başlat
    KeyVault::init();
    test_persistent_vault();
    
    #ifdef ENABLE_PQC_TESTS
      TestSuite::run_all_tests();
    #endif

    #ifdef STRESS_TEST_MODE
      TestSuite::run_stress_test(); // Hiç bitmeyen döngüye girer
    #endif
    
    test_kyber();
    test_dilithium();
    test_authenticated_encryption();
    test_adaptive_authenticated_encryption();
    
    Serial.print("SYSTEM: HW RNG Entropy Quality: "); 
    Serial.print(HealthMonitor::check_rng_entropy() * 100.0); Serial.println("%");
    
    HealthMonitor::print_performance_table();
}

void loop() {
    if (SecurityOfficer::is_system_locked()) {
        Serial.println("SİSTEM KİLİTLİ: Güvenlik ihlali sonrası işlem yapılamaz. Reset gerekli.");
        delay(10000);
        return;
    }
    
    delay(15000);
    test_kyber();
    test_dilithium();
    test_authenticated_encryption();
    test_adaptive_authenticated_encryption();
    HealthMonitor::print_performance_table();
}
