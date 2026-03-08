#include "../include/network_privacy.h"
#include <string.h>

#ifdef ARDUINO
#include <Arduino.h>

namespace PQC {
namespace Network {

// Ring Buffer (Core 0 - Ağ verileri için)
static ring_buffer_t network_ring_buffer = {0};

// Fragment tracking (Anti-Replay için)
static fragment_info_t fragments[MAX_FRAGMENTS];
static uint8_t current_session_mac[6] = {0};
static uint32_t active_msg_id = 0;
static bool session_active = false;

// FreeRTOS Mutex (Core 1 koruması için)
static SemaphoreHandle_t ring_buffer_mutex = NULL;

// Statik Bufferlar (DMA Uygunluğu için 32-bit aligned)
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
void crypto_task(void* pvParameters);

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

    // Mutex oluştur (Core 1 koruması için)
    ring_buffer_mutex = xSemaphoreCreateMutex();
    if (ring_buffer_mutex == NULL) {
        Serial.println("HATA: Ring Buffer mutex olusturulamadi!");
        return false;
    }

    // Persistansdan son ID'leri yukle (Anti-Reset-Replay)
    using PQC::System::KeyVault;
    if (!KeyVault::load_config_uint32("tx_msg_id", &global_msg_id)) global_msg_id = 100;
    if (!KeyVault::load_config_uint32("rx_msg_id", &last_received_msg_id)) last_received_msg_id = 0;

    // Privacy Master Key'i ayarla (Demo için sabit, gerçekte onboard sırasında anlaşılır)
    uint8_t privacy_master[32];
    memset(privacy_master, 0x47, 32); // Gizlilik Kök Anahtarı
    NetworkPrivacy::set_network_master_key(privacy_master);

    // Network Task ve Queue oluştur (Pro-Core / DMA Offload)
    network_queue = xQueueCreate(2, sizeof(network_msg_t));
    xTaskCreatePinnedToCore(network_task, "NetTask", 4096, NULL, 5, NULL, 0); // Core 0
    
    // Core 1 için kriptografi task'ı oluştur
    xTaskCreatePinnedToCore(crypto_task, "CryptoTask", 4096, NULL, 4, NULL, 1); // Core 1 
    
    Serial.println("SISTEM: ESP-NOW Stealth (Obfuscation) Katmani Aktif");
    Serial.println("SISTEM: Ring Buffer ve Mutex korumasi aktif (Core 0/1 ayrıldı)");
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
    static uint8_t missing_seq_retry = 0;

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
                missing_seq_retry = 0;
                
                while (retry < 3 && !success) {
                    ack_received = false;
                    esp_now_send(msg.target_mac, (uint8_t*)&wrapped_pkt, sizeof(wrapped_pkt));
                    
                    uint32_t start = millis();
                    while (millis() - start < 150) {
                        if (ack_received) { 
                            success = true; 
                            break; 
                        }
                        vTaskDelay(1);
                    }
                    if (!success) retry++;
                }
                
                // Eğer 3 denemede başarısız olduysa, bir sonraki parçaya geçme
                if (!success) {
                    #ifndef PQC_SILENT_MODE
                    Serial.print("[ERROR] Parca ");
                    Serial.print(i);
                    Serial.println(" gönderilemedi. Mesaj iptal edildi.");
                    #endif
                    break;
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

// Core 1 Task - Ring Buffer işleme
void crypto_task(void* pvParameters) {
    uint8_t data_buffer[4096];
    size_t data_len;
    
    while (true) {
        // Ring Buffer'dan veri var mı kontrol et
        if (Messenger::ring_buffer_has_data()) {
            data_len = sizeof(data_buffer);
            
            // Mutex ile korumalı okuma
            if (Messenger::ring_buffer_read(data_buffer, &data_len)) {
                #ifndef PQC_SILENT_MODE
                Serial.print("[CRYPTO] Ring Buffer'dan veri işleniyor: ");
                Serial.print(data_len);
                Serial.println(" byte");
                #endif
                
                // Burada kriptografik işlemler yapılabilir
                // Örnek: Veriyi deşifre et, imzayı doğrula, etc.
                
                // Simülasyon: Veriyi işledik sonra temizle
                memset(data_buffer, 0, data_len);
            }
        }
        
        // 10ms bekle (Core 1'i meşgul etmemek için)
        vTaskDelay(10 / portTICK_PERIOD_MS);
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

    if (header.type == MSG_NACK) {
        // NACK alındı, eksik paketi yeniden gönder
        // Bu kısım gönderici tarafında handle edilecek
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
        // Anti-Replay: msg_id kontrolü sadece seq==0'da yapılır
        if (header.seq == 0) {
            // Yeni mesaj başlangıcı
            if ((int32_t)(header.msg_id - last_received_msg_id) <= 0) {
                // Eski mesaj, ignore et
                return;
            }
            
            // Yeni session başlat
            handle_new_session(header.msg_id, mac, header.total);
            last_received_msg_id = header.msg_id;
        } else {
            // Devam paketleri için session kontrolü
            if (!session_active || header.msg_id != active_msg_id) {
                return; // Yanlış session, ignore et
            }
        }

        // Fragment işle
        handle_fragment(&header, payload, mac);
    }
}

// Ring Buffer yazma fonksiyonu (Core 0)
bool Messenger::ring_buffer_write(const uint8_t* data, size_t len) {
    if (len > RING_BUFFER_SIZE) return false;
    
    uint32_t next_head = (network_ring_buffer.head + len) & RING_BUFFER_MASK;
    
    // Buffer dolu mu kontrolü
    if (next_head == network_ring_buffer.tail) {
        return false; // Buffer dolu
    }
    
    // Veriyi yaz (circular)
    if (next_head > network_ring_buffer.head) {
        // Tek parça yazma
        memcpy(network_ring_buffer.buffer + network_ring_buffer.head, data, len);
    } else {
        // İki parça yazma (buffer sonu ve başı)
        size_t first_part = RING_BUFFER_SIZE - network_ring_buffer.head;
        memcpy(network_ring_buffer.buffer + network_ring_buffer.head, data, first_part);
        memcpy(network_ring_buffer.buffer, data + first_part, len - first_part);
    }
    
    network_ring_buffer.head = next_head;
    return true;
}

// Ring Buffer okuma fonksiyonu (Core 1, Mutex korumalı)
bool Messenger::ring_buffer_read(uint8_t* data, size_t* len) {
    if (ring_buffer_mutex == NULL) return false;
    
    if (xSemaphoreTake(ring_buffer_mutex, portMAX_DELAY) == pdTRUE) {
        if (network_ring_buffer.head == network_ring_buffer.tail) {
            xSemaphoreGive(ring_buffer_mutex);
            return false; // Buffer boş
        }
        
        // Mesaj uzunluğunu oku (ilk 2 byte)
        uint16_t msg_len;
        uint32_t tail = network_ring_buffer.tail;
        
        if (tail + 2 > RING_BUFFER_SIZE) {
            // Buffer sonu ve başı
            memcpy(&msg_len, network_ring_buffer.buffer + tail, RING_BUFFER_SIZE - tail);
            memcpy(((uint8_t*)&msg_len) + (RING_BUFFER_SIZE - tail), network_ring_buffer.buffer, 2 - (RING_BUFFER_SIZE - tail));
            tail = 2 - (RING_BUFFER_SIZE - tail);
        } else {
            memcpy(&msg_len, network_ring_buffer.buffer + tail, 2);
            tail += 2;
        }
        
        if (msg_len > *len || msg_len > (RING_BUFFER_SIZE - 2)) {
            xSemaphoreGive(ring_buffer_mutex);
            return false; // Buffer çok küçük veya geçersiz uzunluk
        }
        
        // Mesaj verisini oku
        if (tail + msg_len > RING_BUFFER_SIZE) {
            // Buffer sonu ve başı
            size_t first_part = RING_BUFFER_SIZE - tail;
            memcpy(data, network_ring_buffer.buffer + tail, first_part);
            memcpy(data + first_part, network_ring_buffer.buffer, msg_len - first_part);
            tail = msg_len - first_part;
        } else {
            memcpy(data, network_ring_buffer.buffer + tail, msg_len);
            tail += msg_len;
        }
        
        network_ring_buffer.tail = tail;
        *len = msg_len;
        
        xSemaphoreGive(ring_buffer_mutex);
        return true;
    }
    
    return false;
}

// Ring Buffer dolu mu kontrolü
bool Messenger::ring_buffer_has_data() {
    return (network_ring_buffer.head != network_ring_buffer.tail);
}

// ACK gönderme fonksiyonu
void Messenger::send_ack(const uint8_t* mac, uint32_t msg_id, uint8_t seq) {
    packet_header_t ack_header;
    ack_header.type = MSG_ACK;
    memcpy(ack_header.final_dest, mac, 6);
    ack_header.msg_id = msg_id;
    ack_header.seq = seq;
    ack_header.total = 1;
    ack_header.payload_len = 0;
    
    fragment_packet_t ack_packet;
    NetworkPrivacy::wrap(&ack_packet, &ack_header, NULL, 0);
    
    esp_now_send((uint8_t*)mac, (uint8_t*)&ack_packet, sizeof(ack_packet));
}

// NACK gönderme fonksiyonu
void Messenger::send_nack(const uint8_t* mac, uint32_t msg_id, uint8_t missing_seq) {
    packet_header_t nack_header;
    nack_header.type = MSG_NACK;
    memcpy(nack_header.final_dest, mac, 6);
    nack_header.msg_id = msg_id;
    nack_header.seq = missing_seq;
    nack_header.total = 1;
    nack_header.payload_len = 0;
    
    fragment_packet_t nack_packet;
    NetworkPrivacy::wrap(&nack_packet, &nack_header, NULL, 0);
    
    esp_now_send((uint8_t*)mac, (uint8_t*)&nack_packet, sizeof(nack_packet));
}

// Yeni session başlatma
void Messenger::handle_new_session(uint32_t msg_id, const uint8_t* mac, uint8_t total_fragments) {
    // Eski session temizle
    memset(fragments, 0, sizeof(fragments));
    
    // Yeni session başlat
    active_msg_id = msg_id;
    network_ring_buffer.total_fragments = total_fragments;
    network_ring_buffer.expected_seq = 0;
    network_ring_buffer.active_msg_id = msg_id;
    network_ring_buffer.session_active = true;
    memcpy(current_session_mac, mac, 6);
    session_active = true;
    
    #ifndef PQC_SILENT_MODE
    Serial.print("[SESSION] Yeni mesaj basladi: ID=");
    Serial.print(msg_id);
    Serial.print(", Toplam parca=");
    Serial.println(total_fragments);
    #endif
}

// Fragment işleme
void Messenger::handle_fragment(const packet_header_t* header, const uint8_t* payload, const uint8_t* mac) {
    // Beklenen seq kontrolü
    if (header->seq == network_ring_buffer.expected_seq) {
        // Doğru sıradaki parça geldi
        
        // Ring Buffer'a yaz (uzunluk bilgisi ile birlikte)
        uint16_t len = header->payload_len;
        ring_buffer_write((uint8_t*)&len, 2); // Uzunluk bilgisi
        ring_buffer_write(payload, header->payload_len); // Veri
        
        // ACK gönder
        send_ack(mac, header->msg_id, header->seq);
        
        network_ring_buffer.expected_seq++;
        
        #ifndef PQC_SILENT_MODE
        Serial.print("[FRAGMENT] Parca ");
        Serial.print(header->seq);
        Serial.print("/");
        Serial.print(header->total);
        Serial.println(" alindi ve Ring Buffer'a yazildi.");
        #endif
        
        // Son parça mı?
        if (header->seq == header->total - 1) {
            #ifndef PQC_SILENT_MODE
            Serial.println("[COMPLETE] Tum parcalar alindi. Mesaj Ring Buffer'da bekliyor.");
            #endif
            session_active = false;
        }
    } else if (header->seq > network_ring_buffer.expected_seq) {
        // Atlama var, NACK gönder
        send_nack(mac, header->msg_id, network_ring_buffer.expected_seq);
        
        #ifndef PQC_SILENT_MODE
        Serial.print("[MISSING] Parca ");
        Serial.print(network_ring_buffer.expected_seq);
        Serial.print(" eksik. NACK gonderildi.");
        #endif
    } else {
        // Eski parça, sadece ACK gönder
        send_ack(mac, header->msg_id, header->seq);
    }
}

} // namespace Network
} // namespace PQC

#endif
