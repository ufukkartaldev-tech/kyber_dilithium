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
class Messenger {
public:
    static bool init();
    
    // Veri Paket Gönderme (Şifreli ve İmzalı)
    static bool send_pqc_packet(const uint8_t* peer_mac, const uint8_t* data, size_t len, 
                               const uint8_t* kyber_ss, const uint8_t* dilithium_sk);

#ifdef ARDUINO
    // Alma Callback'i (Gelen paketleri işler)
    static void on_data_recv(const uint8_t* mac, const uint8_t* incomingData, int len);
#endif

private:
    static void format_mac(const uint8_t* mac, char* buf);
};

} // namespace Network
} // namespace PQC

#endif
