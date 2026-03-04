#include "../include/network_privacy.h"
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
#define PQC_MAX_DATA_FRAGMENT 200

static QueueHandle_t network_queue = NULL;
static uint32_t global_msg_id = 1; // Artan mesaj kimliği
static uint32_t last_received_msg_id = 0; // Anti-Replay takibi (Tek kanal için basitleştirilmiş)

static int tx_save_counter = 0;
static int rx_save_counter = 0;
static uint32_t last_tx_save_time = 0;
static uint32_t last_rx_save_time = 0;
#define PQC_NVS_SAVE_INTERVAL 50
#define PQC_NVS_SAVE_TIME_MS 60000

struct network_msg_t {
    uint8_t target_mac[6]; // Şuradaki (Immediate) hedef
    uint8_t final_mac[6];  // Nihai (Endpoint) hedef
    uint8_t data[4096]; 
    size_t len;
};

static uint8_t LOCAL_MAC[6];

void network_task(void* pvParameters);

int Messenger::get_last_retry_count() {
    return last_retry_val;
}

bool Messenger::is_busy() {
    return messenger_busy;
}

bool Messenger::init() {
    WiFi.mode(WIFI_STA);
    esp_read_mac(LOCAL_MAC, ESP_MAC_WIFI_STA); // Kendi kimliğimizi öğrenelim (Mesh için)

    if (esp_now_init() != ESP_OK) {
        Serial.println("HATA: ESP-NOW baslatilamadi!");
        return false;
    }
    
    esp_now_register_recv_cb(Messenger::on_data_recv);
    esp_now_register_send_cb(Messenger::on_data_sent);

    // Persistansdan son ID'leri yukle (Anti-Reset-Replay)
    using PQC::System::KeyVault;
    if (!KeyVault::load_config_uint32("tx_msg_id", &global_msg_id)) global_msg_id = 100;
    if (!KeyVault::load_config_uint32("rx_msg_id", &last_received_msg_id)) last_received_msg_id = 0;

    // Privacy Key'i ayarla (Demo için sabit, gerçekte KeyVault'tan gelir)
    uint8_t privacy_key[32];
    memset(privacy_key, 0x54, 32); 
    NetworkPrivacy::set_privacy_key(privacy_key);

    // Network Task ve Queue oluştur (Pro-Core / DMA Offload)
    network_queue = xQueueCreate(2, sizeof(network_msg_t));
    xTaskCreatePinnedToCore(network_task, "NetTask", 4096, NULL, 5, NULL, 0); 
    
    Serial.println("SISTEM: ESP-NOW Stealth (Obfuscation) Katmani Aktif");
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
    memcpy(msg.target_mac, peer_mac, 6); // Point-to-Point
    memcpy(msg.final_mac, peer_mac, 6);  // Mesh Layer (Endpoint)
    memcpy(msg.data, data, len);
    msg.len = len;

    global_msg_id++; // Her yeni mesajda kimliği artır

    if (xQueueSend(network_queue, &msg, 0) == pdPASS) {
        return true;
    }
    return false;
}

// Background Task handle all retries and DMA-like transfer
void network_task(void* pvParameters) {
    network_msg_t msg;
    static fragment_packet_t wrapped_pkt;
    static packet_header_t header;

    while (true) {
        if (xQueueReceive(network_queue, &msg, portMAX_DELAY) == pdPASS) {
            messenger_busy = true;
            int total = (msg.len + PQC_MAX_DATA_FRAGMENT - 1) / PQC_MAX_DATA_FRAGMENT;
            
            for (uint8_t i = 0; i < total; i++) {
                size_t current_len = (msg.len - (i * PQC_MAX_DATA_FRAGMENT) < PQC_MAX_DATA_FRAGMENT) ? 
                                      msg.len - (i * PQC_MAX_DATA_FRAGMENT) : PQC_MAX_DATA_FRAGMENT;
                
                header.type = MSG_DATA;
                memcpy(header.final_dest, msg.final_mac, 6); 
                header.msg_id = global_msg_id;
                header.seq = i;
                header.total = total;
                header.payload_len = (uint8_t)current_len;
                
                // Stealth Wrap: Header ve Payload'u gürültüye dönüştür
                NetworkPrivacy::wrap(&wrapped_pkt, &header, msg.data + (i * PQC_MAX_DATA_FRAGMENT), current_len);

                int retry = 0;
                bool success = false;
                while (retry < 3 && !success) {
                    ack_received = false;
                    esp_now_send(msg.target_mac, (uint8_t*)&wrapped_pkt, sizeof(wrapped_pkt));
                    
                    uint32_t start = millis();
                    while (millis() - start < 150) {
                        if (ack_received) { success = true; break; }
                        vTaskDelay(1);
                    }
                    if (!success) retry++;
                }
            }

            // tx_id'yi yedekle (Flash Wear-Leveling: 50 paket veya 60sn'de bir)
            tx_save_counter++;
            if (tx_save_counter >= PQC_NVS_SAVE_INTERVAL || (millis() - last_tx_save_time > PQC_NVS_SAVE_TIME_MS)) {
                PQC::System::KeyVault::save_config_uint32("tx_msg_id", global_msg_id);
                tx_save_counter = 0;
                last_tx_save_time = millis();
            }
            
            messenger_busy = false;
        }
    }
}

void Messenger::on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len) {
    if (len < sizeof(fragment_packet_t)) return;
    
    static packet_header_t header;
    static uint8_t payload[250];
    
    // Stealth Unwrap: Gürültüden gerçek başlığı ve veriyi çıkar
    if (!NetworkPrivacy::unwrap(&header, payload, (const fragment_packet_t*)incomingData)) {
        return; // Geçersiz anahtar veya bozuk veri
    }

    if (header.type == MSG_ACK) {
        ack_received = true;
        return;
    }

    // 0.1 HANDSHAKE & TRUST MANTIĞI (Obfuscated)
    if (header.type == MSG_HANDSHAKE_REQ) {
        #ifndef PQC_SILENT_MODE
        Serial.println("\n[TRUST] Stealth Handshake Req alindi.");
        #endif
        return;
    }

    if (header.type == MSG_DATA) {
        // Anti-Replay: Wrap-around korumalı imzalı karşılaştırma
        if ((int32_t)(header.msg_id - last_received_msg_id) <= 0) return;
        
        static uint8_t current_session_mac[6] = {0};
        if (header.seq == 0) {
            last_received_msg_id = header.msg_id;
            memcpy(current_session_mac, mac, 6);
            recv_pos = 0;
        }

        // Birleştirme (Simple demo mode)
        if (recv_pos + header.payload_len <= sizeof(RECV_BUFFER)) {
            memcpy(RECV_BUFFER + recv_pos, payload, header.payload_len);
            recv_pos += header.payload_len;
        }

        // ACK gönder (Bu da obfuscated olmalı ama basitlik için direkt data cevabı gibi düşünülebilir)
        // Gerçek implementasyonda ACK da wrap edilmeli.
        
        if (header.seq == header.total - 1) {
            #ifndef PQC_SILENT_MODE
            Serial.print("\n[STEALTH] Obfuscated Veri Cozuldu ("); 
            Serial.print(recv_pos); Serial.println(" bytes)");
            #endif
        }
    }
}

} // namespace Network
} // namespace PQC

#endif
