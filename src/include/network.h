#ifndef PQC_NETWORK_H
#define PQC_NETWORK_H

#include <stdint.h>
#include <stddef.h>

#ifdef ARDUINO
#include <esp_now.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#endif

namespace PQC {
namespace Network {

/**
 * PQC_Messenger Sınıfı
 * Kyber ve Dilithium verilerini ESP-NOW üzerinden taşımak için 
 * kısıtlı sistemlerde (RAM/Hız) optimize edilmiş haberleşme katmanı.
 */
#define PQC_MAX_PACKET_SIZE 250
#define PQC_PAYLOAD_SIZE    234 // Mesh Başlığı (6 byte) düştü.

// Ring Buffer için sabitler
#define RING_BUFFER_SIZE 16384  // 16KB
#define RING_BUFFER_MASK (RING_BUFFER_SIZE - 1)
#define MAX_FRAGMENTS 32         // Maksimum parça sayısı

namespace PQC {
namespace Network {

enum PacketType { MSG_DATA = 0, MSG_ACK = 1, MSG_HANDSHAKE_REQ = 2, MSG_HANDSHAKE_CERT = 3, MSG_AUTH = 4, MSG_NACK = 5 };

typedef struct {
    uint8_t type;
    uint8_t final_dest[6];
    uint32_t msg_id;
    uint8_t seq;
    uint8_t total;
    uint8_t payload_len;
} __attribute__((packed)) packet_header_t;

typedef struct {
    uint8_t iv[12]; 
    uint8_t auth_tag[16];
    uint8_t data[222]; // Encrypted (Header + Payload)
} __attribute__((packed, aligned(4))) fragment_packet_t; // 250 Bytes limit compatible

// Ring Buffer yapısı (Core 0 için)
typedef struct {
    uint8_t buffer[RING_BUFFER_SIZE];
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t active_msg_id;
    uint8_t expected_seq;
    uint8_t total_fragments;
    bool session_active;
} ring_buffer_t;

// Fragment tracking yapısı
typedef struct {
    uint32_t msg_id;
    uint8_t seq;
    uint8_t total;
    uint8_t data[200];
    uint8_t data_len;
    bool received;
} fragment_info_t;

class Messenger {
public:
    static bool init();
    
    // Asenkron ve DMA destekli gönderim
    static bool send_reliable(const uint8_t* peer_mac, const uint8_t* data, size_t len);
    
    // Transfer durumunu sorgula (Non-blocking)
    static bool is_busy();

#ifdef ARDUINO
    static void on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len);
    static void on_data_sent(const uint8_t* mac, esp_now_send_status_t status);
#endif

    // Link Kalitesi İzleme
    static int get_last_retry_count();

    // Core 1 için Ring Buffer erişim fonksiyonları
    static bool ring_buffer_read(uint8_t* data, size_t* len);
    static bool ring_buffer_has_data();

private:
    static void format_mac(const uint8_t* mac, char* buf);
    static bool wait_for_ack();
    
    // Ring Buffer yönetimi (Core 0)
    static bool ring_buffer_write(const uint8_t* data, size_t len);
    static void send_ack(const uint8_t* mac, uint32_t msg_id, uint8_t seq);
    static void send_nack(const uint8_t* mac, uint32_t msg_id, uint8_t missing_seq);
    
    // Anti-Replay ve fragment yönetimi
    static void handle_new_session(uint32_t msg_id, const uint8_t* mac, uint8_t total_fragments);
    static void handle_fragment(const packet_header_t* header, const uint8_t* payload, const uint8_t* mac);
};

} // namespace Network
} // namespace PQC

#endif
