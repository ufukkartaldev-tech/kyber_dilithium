#include "../include/network.h"
#include "../include/encryption.h"
#include "../include/dilithium.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>

namespace PQC {
namespace Network {

// Statik Bufferlar (RAM Dostu - Gümüşhane Usulü)
static uint8_t RECV_BUFFER[4096]; // Dilithium imzası için geniş yer
static size_t recv_pos = 0;
static volatile bool last_send_ok = false;
static volatile bool ack_received = false;
static int last_retry_val = 0;

int Messenger::get_last_retry_count() {
    return last_retry_val;
}

bool Messenger::init() {
    WiFi.mode(WIFI_STA);
    if (esp_now_init() != ESP_OK) {
        Serial.println("HATA: ESP-NOW baslatilamadi!");
        return false;
    }
    
    esp_now_register_recv_cb(Messenger::on_data_recv);
    esp_now_register_send_cb(Messenger::on_data_sent);
    
    Serial.println("SISTEM: ESP-NOW Modu Aktif (Reliable PQC Hazir)");
    return true;
}

void Messenger::on_data_sent(const uint8_t* mac, esp_now_send_status_t status) {
    last_send_ok = (status == ESP_NOW_SEND_SUCCESS);
}

bool Messenger::wait_for_ack() {
    uint32_t start = millis();
    while (millis() - start < 500) { // 500ms timeout
        if (ack_received) {
            ack_received = false;
            return true;
        }
        delay(1);
    }
    return false;
}

bool Messenger::send_reliable(const uint8_t* peer_mac, const uint8_t* data, size_t len) {
    fragment_packet_t pkt;
    uint8_t total = (len + PQC_PAYLOAD_SIZE - 1) / PQC_PAYLOAD_SIZE;
    last_retry_val = 0;
    
    for (uint8_t i = 0; i < total; i++) {
        size_t current_len = (len - (i * PQC_PAYLOAD_SIZE) < PQC_PAYLOAD_SIZE) ? 
                              len - (i * PQC_PAYLOAD_SIZE) : PQC_PAYLOAD_SIZE;
        
        pkt.type = MSG_DATA;
        pkt.seq = i;
        pkt.total = total;
        pkt.payload_len = current_len;
        memcpy(pkt.payload, data + (i * PQC_PAYLOAD_SIZE), current_len);
        
        int retry = 0;
        bool success = false;
        while (retry < 3 && !success) {
            ack_received = false;
            esp_now_send(peer_mac, (uint8_t*)&pkt, sizeof(pkt) - (PQC_PAYLOAD_SIZE - current_len));
            
            if (wait_for_ack()) {
                success = true;
            } else {
                retry++;
                last_retry_val++;
                Serial.print("WARN: Paket "); Serial.print(i); Serial.println(" kayboldu, tekrar deneniyor...");
                delay(50);
            }
        }
        if (!success) return false;
    }
    return true;
}

void Messenger::on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len) {
    if (len < 4) return;
    fragment_packet_t* pkt = (fragment_packet_t*)incomingData;
    
    if (pkt->type == MSG_ACK) {
        ack_received = true;
        return;
    }
    
    if (pkt->type == MSG_DATA) {
        // ACK Gönder (Sıranın geldiğini onayla)
        fragment_packet_t ack_pkt;
        ack_pkt.type = MSG_ACK;
        ack_pkt.seq = pkt->seq;
        esp_now_send(mac, (uint8_t*)&ack_pkt, 4); // Sadece başlığı gönder
        
        // Birleştirme (Sequence kontrolü)
        if (pkt->seq == 0) recv_pos = 0; // Yeni mesaj başlangıcı
        
        // Basitlik için sırayla geldiğini varsayıyoruz (Reliable send garantiler)
        if (recv_pos + pkt->payload_len <= sizeof(RECV_BUFFER)) {
            memcpy(RECV_BUFFER + recv_pos, pkt->payload, pkt->payload_len);
            recv_pos += pkt->payload_len;
        }
        
        if (pkt->seq == pkt->total - 1) {
            Serial.print("\n[WIRELESS] Buyuk Veri Alindi ("); 
            Serial.print(recv_pos); Serial.println(" bytes)");
        }
    }
}

} // namespace Network
} // namespace PQC

#endif
