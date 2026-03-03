#ifndef PQC_NETWORK_H
#define PQC_NETWORK_H

#include <stdint.h>
#include <stddef.h>

#ifdef ARDUINO
#include <esp_now.h>
#include <WiFi.h>
#endif

namespace PQC {
namespace Network {

/**
 * PQC_Messenger Sınıfı
 * Kyber ve Dilithium verilerini ESP-NOW üzerinden taşımak için 
 * kısıtlı sistemlerde (RAM/Hız) optimize edilmiş haberleşme katmanı.
 */
#define PQC_MAX_PACKET_SIZE 250
#define PQC_PAYLOAD_SIZE    240

namespace PQC {
namespace Network {

enum PacketType { MSG_DATA = 0, MSG_ACK = 1 };

typedef struct {
    uint8_t type;        // PacketType
    uint8_t seq;         // Sequence number
    uint8_t total;       // Total fragments
    uint8_t payload_len; // Content length
    uint8_t payload[PQC_PAYLOAD_SIZE];
} __attribute__((packed)) fragment_packet_t;

class Messenger {
public:
    static bool init();
    
    // Güvenli ve Parçalı Gönderim (Dilithium/Kyber için)
    static bool send_reliable(const uint8_t* peer_mac, const uint8_t* data, size_t len);

#ifdef ARDUINO
    static void on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len);
    static void on_data_sent(const uint8_t* mac, esp_now_send_status_t status);
#endif

    // Link Kalitesi İzleme
    static int get_last_retry_count();

private:
    static void format_mac(const uint8_t* mac, char* buf);
    static bool wait_for_ack();
};

} // namespace Network
} // namespace PQC

#endif
