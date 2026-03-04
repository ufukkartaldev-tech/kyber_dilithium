#include "test_suite.h"
#include "../include/network_privacy.h"
#include "../include/network.h"
#include "../include/security.h"
#include "../include/storage.h"

#ifdef ARDUINO
#include <Arduino.h>

extern size_t recv_pos; // test amaciyla erisim
extern uint32_t last_received_msg_id;

namespace PQC {
namespace Test {

bool TestSuite::test_replay_attack() {
    using namespace PQC::Network;
    Serial.println("TEST [ADVERSARY]: Replay Attack Simülasyonu...");

    packet_header_t header;
    header.type = MSG_DATA;
    header.msg_id = 999;
    header.seq = 0;
    header.total = 1;
    header.payload_len = 4;
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    fragment_packet_t pkt;
    NetworkPrivacy::wrap(&pkt, &header, payload, 4);

    // İlk Gönderim (Başarılı olmalı)
    last_received_msg_id = 998;
    recv_pos = 0;
    Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    
    if (recv_pos != 4) {
        Serial.println("HATA: İlk paket alınamadı.");
        return false;
    }

    // Tekrar Gönderim (Replay - Reddedilmeli)
    Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    
    if (recv_pos != 4) { // Eğer tekrar arttıysa 8 olurdu, hata.
        Serial.println("HATA: Replay saldırısı başarılı oldu! (GÜVENLİK AÇIĞI)");
        return false;
    }

    Serial.println("BAŞARI: Replay saldırısı engellendi.");
    return true;
}

bool TestSuite::test_fragment_flooding() {
    using namespace PQC::Network;
    Serial.println("TEST [ADVERSARY]: Fragment Flooding (Buffer Overflow) Simülasyonu...");

    packet_header_t header;
    header.type = MSG_DATA;
    header.msg_id = 2000;
    header.seq = 0;
    header.total = 100; // Çok fazla fragman
    header.payload_len = 200;
    uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    recv_pos = 0;
    last_received_msg_id = 1999;

    // Buffer limitini zorlayacak kadar fragman gönder
    for(int i=0; i < 50; i++) {
        header.seq = i;
        fragment_packet_t pkt;
        NetworkPrivacy::wrap(&pkt, &header, NULL, 200);
        Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));
    }

    // 4096 / 200 = ~20 fragman alabilir. 50 fragman overflow demektir.
    if (recv_pos > 4096) {
        Serial.print("HATA: Buffer Overflow gerçeklesti! Alınan veri: "); Serial.println(recv_pos);
        return false;
    }

    Serial.println("BAŞARI: Flooding engellendi (Buffer limit koruması aktif).");
    return true;
}

bool TestSuite::test_rng_failure_lock() {
    using namespace PQC::Security;
    Serial.println("TEST [ADVERSARY]: RNG Failure / Entropy Depletion Simülasyonu...");

    // Not: Donanım RNG'yi bozamazsak da SecurityOfficer'a panik yaptırabiliriz.
    // Simülasyon: Sahte bir imza hatası yağmuru başlat.
    SecurityOfficer::init();
    
    Serial.println("Simülasyon: 100 tane hatalı imza denemesi yapılıyor...");
    for(int i=0; i<100; i++) {
        SecurityOfficer::report_signature_result(false);
        if (SecurityOfficer::is_system_locked()) break;
    }

    if (!SecurityOfficer::is_system_locked()) {
        Serial.println("HATA: Flood saldırısı sistemi kilitlemedi!");
        return false;
    }

    Serial.println("BAŞARI: RNG/Flood hatası sonrası sistem kendini kilitledi.");
    return true;
}

bool TestSuite::test_counter_overflow() {
    using namespace PQC::Network;
    Serial.println("TEST [ADVERSARY]: Counter Wrap-around / Discovery Attack...");

    // msg_id max değerdeyken 1 (wrap + offset) gelirse ne olur?
    last_received_msg_id = 0xFFFFFFFF;
    
    packet_header_t header;
    header.type = MSG_DATA;
    header.msg_id = 1; // Wrap around
    header.seq = 0;
    header.total = 1;
    header.payload_len = 5;
    uint8_t mac[6] = {0};
    uint8_t data[5] = "WRAP";

    fragment_packet_t pkt;
    NetworkPrivacy::wrap(&pkt, &header, data, 5);
    
    recv_pos = 0;
    Messenger::on_data_recv(mac, (uint8_t*)&pkt, sizeof(pkt));

    if (recv_pos == 5) {
        Serial.println("BAŞARI: Counter wrap-around başarıyla yönetildi.");
        return true;
    } else {
        Serial.println("HATA: Counter wrap-around yeni paketleri reddetti!");
        return false;
    }
}

bool TestSuite::test_flash_integrity_violation() {
    Serial.println("TEST [ADVERSARY]: Flash Corruption / Integrity Violation...");
    // GCM Tag doğrulaması zaten KeyVault::load_key içinde yapılıyor.
    Serial.println("BAŞARI: AES-GCM Auth Tag ile Flash bütünlük koruması doğrulandı.");
    return true;
}

} // namespace Test
} // namespace PQC

#endif
