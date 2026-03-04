#ifndef PQC_STORAGE_H
#define PQC_STORAGE_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace System {

/**
 * KeyVault (Gümüşhane Gömme Kasası)
 * Hassas PQC anahtarlarını ESP32 NVS (Non-Volatile Storage) 
 * içinde donanım/yazılım hibrit şifreleme ile güvenli saklar.
 */
class KeyVault {
public:
    static bool init();
    
    // Anahtar Saklama (NVS + AES-256-GCM Encryption)
    static bool save_key(const char* key_name, const uint8_t* key_data, size_t len);
    
    // Anahtar Yükleme (NVS + AES-256-GCM Decryption)
    static bool load_key(const char* key_name, uint8_t* out_data, size_t len);
    
    // Kasa Temizliği (Tüm anahtarları sil)
    static bool destroy_vault();

    // Sistem Ayarları (Şifresiz, hızlı NVS erişimi)
    static bool save_config_uint32(const char* name, uint32_t value);
    static bool load_config_uint32(const char* name, uint32_t* value);

    // Peer Whitelisting (Trust-Chain)
    static bool is_peer_trusted(const uint8_t* mac);
    static void add_trusted_peer(const uint8_t* mac, const uint8_t* public_key);
    static bool get_peer_public_key(const uint8_t* mac, uint8_t* pk_out);

    // Admin (Root) PK Yönetimi
    static bool save_admin_pk(const uint8_t* pk);
    static bool get_admin_pk(uint8_t* pk_out);

private:
    static uint8_t master_vault_key[32]; // Kasayı kilitleyen ana anahtar
    static void generate_master_key();   // Cihaza özel master key üret (MAC tabanlı)
};

} // namespace System
} // namespace PQC

#endif
