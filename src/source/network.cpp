#include "../include/network.h"
#include "../include/encryption.h"
#include "../include/dilithium.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>

namespace PQC {
namespace Network {

// Statik Bufferlar (DMA Uygunluğu için 32-bit aligned)
static uint8_t RECV_BUFFER[4096] __attribute__((aligned(32))); 
static size_t recv_pos = 0;
static volatile bool last_send_ok = false;
static volatile bool ack_received = false;
static int last_retry_val = 0;
static volatile bool messenger_busy = false;

// Async Queue
static QueueHandle_t network_queue = NULL;

struct network_msg_t {
    uint8_t mac[6];
    uint8_t data[4096]; // Maksimum paket boyutu (Dilithium Sig)
    size_t len;
};

void network_task(void* pvParameters);

int Messenger::get_last_retry_count() {
    return last_retry_val;
}

bool Messenger::is_busy() {
    return messenger_busy;
}

bool Messenger::init() {
    WiFi.mode(WIFI_STA);
    if (esp_now_init() != ESP_OK) {
        Serial.println("HATA: ESP-NOW baslatilamadi!");
        return false;
    }
    
    esp_now_register_recv_cb(Messenger::on_data_recv);
    esp_now_register_send_cb(Messenger::on_data_sent);

    // Network Task ve Queue oluştur (Pro-Core / DMA Offload)
    network_queue = xQueueCreate(2, sizeof(network_msg_t));
    xTaskCreatePinnedToCore(network_task, "NetTask", 4096, NULL, 5, NULL, 0); // Core 0: Networking
    
    Serial.println("SISTEM: ESP-NOW Async (Core 0) + DMA Alignment Aktif");
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
    if (len > 4096) return false;
    
    network_msg_t msg;
    memcpy(msg.mac, peer_mac, 6);
    memcpy(msg.data, data, len);
    msg.len = len;

    if (xQueueSend(network_queue, &msg, 0) == pdPASS) {
        return true;
    }
    return false;
}

// Background Task handle all retries and DMA-like transfer
void network_task(void* pvParameters) {
    network_msg_t msg;
    static fragment_packet_t pkt; // DMA Aligned via attribute in header

    while (true) {
        if (xQueueReceive(network_queue, &msg, portMAX_DELAY) == pdPASS) {
            messenger_busy = true;
            uint8_t total = (msg.len + PQC_PAYLOAD_SIZE - 1) / PQC_PAYLOAD_SIZE;
            
            for (uint8_t i = 0; i < total; i++) {
                size_t current_len = (msg.len - (i * PQC_PAYLOAD_SIZE) < PQC_PAYLOAD_SIZE) ? 
                                      msg.len - (i * PQC_PAYLOAD_SIZE) : PQC_PAYLOAD_SIZE;
                
                pkt.type = MSG_DATA;
                pkt.seq = i;
                pkt.total = total;
                pkt.payload_len = (uint8_t)current_len;
                memcpy(pkt.payload, msg.data + (i * PQC_PAYLOAD_SIZE), current_len);
                
                int retry = 0;
                bool success = false;
                while (retry < 3 && !success) {
                    ack_received = false;
                    esp_now_send(msg.mac, (uint8_t*)&pkt, sizeof(pkt) - (PQC_PAYLOAD_SIZE - current_len));
                    
                    // Blocking wait inside dedicated network task (doesn't hurt PQC CPU)
                    uint32_t start = millis();
                    while (millis() - start < 200) {
                        if (ack_received) { success = true; break; }
                        vTaskDelay(1);
                    }
                    if (!success) {
                        retry++;
                        Serial.print("ASYNC WARN: Packet retry "); Serial.println(retry);
                    }
                }
            }
            messenger_busy = false;
        }
    }
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
        static fragment_packet_t ack_pkt; // Stack tasarrufu
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
