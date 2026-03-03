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

/**
 * AES-256-GCM Sınıfı
 * Donanım hızlandırıcı desteği ile yüksek performanslı şifreleme sağlar.
 */
class AES256GCM {
public:
    static int encrypt(uint8_t* out, uint8_t tag[16], const uint8_t* in, size_t len,
                       const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad = NULL, size_t aad_len = 0);
    
    static int decrypt(uint8_t* out, const uint8_t* in, size_t len, const uint8_t tag[16],
                       const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad = NULL, size_t aad_len = 0);
};

/**
 * Key Derivation Function (KDF)
 * Kyber'dan gelen 32 baytlık paylaşımlı sırrı (Shared Secret) parçalayarak
 * farklı şifreleme katmanları için bağımsız anahtarlar türetir.
 */
class KDF {
public:
    static void derive_keys(uint8_t chacha_key[32], uint8_t aes_key[32], const uint8_t shared_secret[32]);
};

} // namespace Symmetric
} // namespace PQC

#endif
