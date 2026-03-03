#ifndef PQC_ENCRYPTION_H
#define PQC_ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace Symmetric {

/**
 * ChaCha20 Simetrik Şifreleme Sınıfı
 * Kuantum sonrası anahtar değişimi (Kyber) ile elde edilen 32-baytlık 
 * anahtarları kullanarak veriyi yüksek hızda ve güvenli şifreler.
 */
class ChaCha20 {
public:
    // Şifreleme / Deşifreleme (ChaCha20 simetriktir, aynı işlem ikisi için de geçerlidir)
    static void process(uint8_t* out, const uint8_t* in, size_t len, 
                        const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0);

private:
    static uint32_t rotl32(uint32_t x, int n);
    static void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
};

} // namespace Symmetric
} // namespace PQC

#endif
