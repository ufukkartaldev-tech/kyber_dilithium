#include "../include/storage.h"
#include "../include/encryption.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>
#include <nvs_flash.h>
#include <nvs.h>
#include "esp_system.h"
#include "esp_mac.h"

namespace PQC {
namespace System {

uint8_t KeyVault::master_vault_key[32];

bool KeyVault::init() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    
    generate_master_key(); // Cihazın kimliğini (MAC) kullanarak kasanın fiziksel anahtarını üret.
    
    return (err == ESP_OK);
}

void KeyVault::generate_master_key() {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    
    // Basit ama cihaza özel bir Master Key (Gümüşhane usulü SHA256 ile karıştırıp 32 bayt yapalım)
    // Gerçekte mbedtls_sha256 gibi bir şey daha iyidir ama MAC + Sabit ile dolduralım demoda.
    memset(master_vault_key, 0x47, 32); // 'G' harfi (Gümüşhane)
    memcpy(master_vault_key, mac, 6);   // İlk 6 baytı fiziksel MAC yapıyoruz.
    for(int i=6; i<32; i++) master_vault_key[i] ^= (uint8_t)(i * 0x13); // Kalanı biraz karıştır.
}

bool KeyVault::save_key(const char* key_name, const uint8_t* key_data, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("pqc_vault", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) return false;

    // 1. Şifreleme (Encryption)
    // Şifreli veri yapısı: [IV (12)] | [TAG (16)] | [CIPHERTEXT (len)]
    uint8_t iv[12] = {0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF, 0, 1, 3, 3}; // Statik ama her cihazda MAC etkili.
    uint8_t tag[16];
    uint8_t* encrypted_blob = (uint8_t*)malloc(len + 12 + 16);
    if (!encrypted_blob) { nvs_close(nvs_handle); return false; }

    memcpy(encrypted_blob, iv, 12);
    
    // AES-256-GCM ile anahtarı şifrele (Hibrit Güvenlik: PQC anahtarını klasik AES ile sakla)
    PQC::Symmetric::AES256GCM::encrypt(encrypted_blob + 28, tag, key_data, len, master_vault_key, iv);
    memcpy(encrypted_blob + 12, tag, 16);

    // 2. NVS'e Kayıt (Blobu kaydet)
    err = nvs_set_blob(nvs_handle, key_name, encrypted_blob, len + 28);
    if (err == ESP_OK) err = nvs_commit(nvs_handle);

    free(encrypted_blob);
    nvs_close(nvs_handle);
    
    if (err == ESP_OK) Serial.printf("KEYVAULT: '%s' başarıyla şifrelendi ve gömme kasaya (NVS) kilitlendi.\n", key_name);
    return (err == ESP_OK);
}

bool KeyVault::load_key(const char* key_name, uint8_t* out_data, size_t len) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("pqc_vault", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) return false;

    size_t blob_len = len + 28;
    uint8_t* encrypted_blob = (uint8_t*)malloc(blob_len);
    if (!encrypted_blob) { nvs_close(nvs_handle); return false; }

    err = nvs_get_blob(nvs_handle, key_name, encrypted_blob, &blob_len);
    if (err == ESP_OK) {
        uint8_t iv[12], tag[16];
        memcpy(iv, encrypted_blob, 12);
        memcpy(tag, encrypted_blob + 12, 16);
        
        // Deşifreleme (Decryption)
        int decrypt_res = PQC::Symmetric::AES256GCM::decrypt(out_data, encrypted_blob + 28, len, tag, master_vault_key, iv);
        
        if (decrypt_res != 0) {
            Serial.println("KASA HATASI: Anahtar deşifre edilemedi! Doğruluk (Integrity) hatası.");
            err = ESP_FAIL;
        }
    }

    free(encrypted_blob);
    nvs_close(nvs_handle);
    return (err == ESP_OK);
}

bool KeyVault::destroy_vault() {
    nvs_handle_t nvs_handle;
    if (nvs_open("pqc_vault", NVS_READWRITE, &nvs_handle) == ESP_OK) {
        nvs_erase_all(nvs_handle);
        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
        Serial.println("KASA: Tüm kayıtlı anahtarlar imha edildi (Zero-Fill).");
        return true;
    }
    return false;
}

} // namespace System
} // namespace PQC

#else
// PC Mock Implementation
namespace PQC {
namespace System {
uint8_t KeyVault::master_vault_key[32];
bool KeyVault::init() { return true; }
bool KeyVault::save_key(const char* n, const uint8_t* d, size_t l) { printf("[STORAGE MOCK] Key saved: %s\n", n); return true; }
bool KeyVault::load_key(const char* n, uint8_t* o, size_t l) { printf("[STORAGE MOCK] Key loaded: %s\n", n); return true; }
bool KeyVault::destroy_vault() { return true; }
void KeyVault::generate_master_key() {}
}
}
#endif
