#ifndef PQC_TRUST_MANAGER_H
#define PQC_TRUST_MANAGER_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace Security {

/**
 * TrustManager (Güven Zinciri Yöneticisi)
 * Yeni cihazların ağa katılımı (Handshake) ve sertifika yönetimini yapar.
 */
class TrustManager {
public:
    // Cihazın ağa katılım isteğini Admin'e gönder
    static void request_admission(const uint8_t* admin_mac);

    // Admin olarak gelen isteği doğrula ve sertifika üret
    static bool issue_certificate(uint8_t* cert_out, const uint8_t* device_mac, const uint8_t* device_pk, const uint8_t* admin_sk);

    // Gelen sertifikayı Admin Kamu Anahtarı ile doğrula
    static bool verify_certificate(const uint8_t* cert, const uint8_t* device_mac, const uint8_t* device_pk, const uint8_t* admin_pk);

    // Admin modunda mıyız? (İlk cihaz genellikle admin olur)
    static void set_admin_mode(bool enable);
    static bool is_admin();

private:
    static bool admin_mode;
};

} // namespace Security
} // namespace PQC

#endif
