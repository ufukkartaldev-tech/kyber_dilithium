#ifndef PQC_CONFIG_H
#define PQC_CONFIG_H

/*
  PQC CONFIGURATION SETTINGS
  --------------------------
*/

// Flash bazlı depolama makrosu (ESP32'de RAM yerine Flash kullanmak için)
#ifdef ARDUINO
  #include <esp_attr.h>
  #define PQC_FLASH_STORAGE ICACHE_RODATA_ATTR
#else
  #define PQC_FLASH_STORAGE
#endif

// Geliştirme aşamasında testleri aktif etmek için bu satırı açık bırakın.
// Üretim (Production) moduna geçerken bu satırı yorum satırı yaparsanız 
// test kodları derlenmez ve cihaz hafızasında (Flash) yer kaplamaz.
#define ENABLE_PQC_TESTS

// Stress Test Modu (Süreklilik ve Bellek Sızıntısı Kontrolü)
// Aktif edildiğinde cihaz durmaksızın PQC operasyonları yapar.
// #define STRESS_TEST_MODE 

#endif
