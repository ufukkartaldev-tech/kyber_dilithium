# GümüşPQC: ESP32 İçin Optimize Edilmiş Kuantum-Ötesi Kriptografi Kütüphanesi

## Proje Hakkında
GümüşPQC, ESP32 mikrodenetleyici mimarisi için özel olarak geliştirilmiş, yüksek performanslı ve bellek verimli bir Kuantum-Ötesi Kriptografi (PQC) kütüphanesidir. Sistem, NIST tarafından standartlaştırılan Kyber Anahtar Kapsülleme Mekanizması (KEM) ve Dilithium Dijital İmza Algoritması'nı (DSA) temel alarak, sınırlı kaynaklara sahip gömülü sistemlerde üst düzey güvenlik sağlamayı amaçlamaktadır.

## Temel Özellikler
- **Kyber (512/768)**: Kuantum bilgisayar saldırılarına karşı güvenli anahtar değişimi.
- **Dilithium2**: Fiziksel ve teorik saldırılara dirençli dijital imza doğrulama.
- **Hibrit Şifreleme**: AES-256-GCM (Donanım Hızlandırmalı) ve ChaCha20 ile çift katmanlı veri güvenliği.
- **ESP-NOW Entegrasyonu**: Asenkron ve güvenilir veri iletim katmanı.

## Bellek Optimizasyon Stratejileri
Sistemin 520 KB RAM sınırları içerisinde stabil çalışabilmesi için ileri düzey bellek yönetim teknikleri uygulanmıştır:

1. **SharedWorkspace (Evrensel Paylaşımlı Bellek)**: Kyber ve Dilithium operasyonları için tek bir statik tampon (union) kullanılarak, algoritmalar arası %100 bellek geri dönüşümü sağlanmıştır. Bu sayede statik RAM kullanımı yaklaşık 20 KB azaltılmıştır.
2. **Bit-Packing (Bit Seviyesinde Paketleme)**: 
    - Kyber katsayıları 12-bit seviyesinde paketlenerek polinom başına %25 yer tasarrufu sağlanmıştır.
    - Dilithium katsayıları 24-bit seviyesinde paketlenerek matris alanında %25 verimlilik artışı gerçekleştirilmiştir.
3. **Flash Offloading (DROM Yerleşimi)**: NTT (Number Theoretic Transform) zeta tabloları ve Keccak sabitleri, `PQC_FLASH_STORAGE` makrosu ile RAM yerine Flash (RODATA) üzerinde depolanarak heap alanı korunmuştur.
4. **Yalın Yığın (Lean Stack)**: Stack Overflow risklerini bertaraf etmek amacıyla, büyük yerel diziler statik depolama birimlerine taşınmıştır.

## Performans ve Asenkron Mimari
- **Çift Çekirdek Kullanımı**: ESP-NOW ağ trafiği Pro-Core (Core 0) çekirdeğine, kriptografik işlemler ise App-Core (Core 1) çekirdeğine atanarak paralel işlem kabiliyeti artırılmıştır.
- **DMA Uyumluluğu**: Ağ iletim tamponları 4-bayt (32-bit) hizalı (aligned) yapılarak donanım seviyesinde DMA (Doğrudan Bellek Erişimi) hızı optimize edilmiştir.
- **Non-Blocking Yapı**: Veri iletimi asenkron kuyruklar (FreeRTOS Queues) üzerinden yönetilerek işlemci darboğazları önlenmiştir.

## Güvenlik Analizi
- **Constant-Time (Sabit Zamanlı) Algoritmalar**: Veri paketleme ve açma işlemlerinde dallanma (branching) ortadan kaldırılarak zamanlama saldırılarına (timing attacks) karşı tam koruma sağlanmıştır.
- **Güvenli Temizleme (Secure Wipe)**: Hassas veriler operasyon bitiminde bellekten fiziksel olarak (`memset 0`) silinerek iz bırakılmamaktadır.
- **Hardware Acceleration**: AES operasyonları ESP32 donanım hızlandırıcısı üzerinden yürütülerek enerji verimliliği ve hız maksimize edilmiştir.

## Teknik Özellikler
| Parametre | Değer |
|-----------|-------|
| Target MCU | ESP32 (S3/C3/Plain) |
| RAM Footprint | ~16 KB (Static) |
| Stack Usage | < 4 KB |
| Networking | ESP-NOW (Reliable Async) |
| Security Mode | NIST Level 2-3 |

## Proje Yapısı
- `src/include/`: Başlık dosyaları ve parametre konfigürasyonları.
- `src/source/`: Algoritma ve haberleşme katmanı implementasyonları.
- `src/tests/`: Stabilite ve performans test üniteleri.
- `kyber_dilithium.ino`: Ana uygulama ve entegrasyon örneği.

## Lisans ve Kullanım
Bu proje, yüksek güvenlik gereksinimli gömülü sistem projeleri için tasarlanmış açık kaynaklı bir referans uygulamasıdır.
