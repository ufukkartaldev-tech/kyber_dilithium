#include "../include/network.h"
#include "../include/encryption.h"
#include "../include/dilithium.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>

namespace PQC {
namespace Network {

// Paket Yapısı (ESP-NOW sınırı 250 byte olduğu için küçük parçalarla çalışıyoruz)
typedef struct {
    uint8_t encrypted_data[128];
    uint8_t signature[2420]; // DILITHIUM2_SIGNBYTES (Bu kısım parçalı gönderilmeli veya büyük paket desteği olan çiplerde kullanılmalı)
    size_t payload_len;
} pqc_packet_t;

bool Messenger::init() {
    WiFi.mode(WIFI_STA);
    if (esp_now_init() != ESP_OK) {
        Serial.println("HATA: ESP-NOW baslatilamadi!");
        return false;
    }
    Serial.println("SISTEM: ESP-NOW Modu Aktif (PQC Hazir)");
    return true;
}

// MAC Adresi Formatlayıcı
void Messenger::format_mac(const uint8_t* mac, char* buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * Not: ESP-NOW paket sınırı (250 byte) Dilithium imzaları için çok küçüktür.
 * Gerçek senaryoda imza parçalı (fragmented) gönderilmeli veya imza gönderilmeden 
 * önce el sıkışma (Handshake) tamamlanmalıdır.
 * Bu sınıfta mimari yapı kurulmuştur.
 */
bool Messenger::send_pqc_packet(const uint8_t* peer_mac, const uint8_t* data, size_t len, 
                               const uint8_t* kyber_ss, const uint8_t* dilithium_sk) {
    if (len > 128) return false;

    uint8_t encrypted[128];
    uint8_t nonce[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    // 1. Veriyi Şifrele (Kyber Key + ChaCha20)
    Symmetric::ChaCha20::process(encrypted, data, len, kyber_ss, nonce);

    // 2. Paketi Gönder
    esp_err_t result = esp_now_send(peer_mac, encrypted, len);
    
    return (result == ESP_OK);
}

void Messenger::on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len) {
    char macStr[18];
    Messenger::format_mac(mac, macStr);
    Serial.print("\n[WIRELESS] Paket alindi den: "); Serial.println(macStr);
    Serial.print("[WIRELESS] Uzunluk: "); Serial.println(len);
}

} // namespace Network
} // namespace PQC

#endif
