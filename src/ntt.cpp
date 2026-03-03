#include "ntt.h"

// Kyber için önceden hesaplanmış zeta (roots of unity) değerleri
// Bu değerler Montgomery alanındadır (scaled by 2^16 mod 3329)
static const int16_t zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
     573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   711, -1084,  -351,
     364,  -112,  1291,  -972, -1294, -1322,  -126,  -247,
    -304, -1352,   198,  -105,   -81,  -152,  1639,  -425,
    1109,  1513,  1135,   805,   442,  -875,   913,  1330,
     858,  -147,  -552,   -19,  1011, -1122,   957, -1388,
     933,  -302, -1141,   141,  1195,  -384, -1534, -1367,
    -226,  -705,   582,   852,  -278,  -836,  -948,   316,
    -112,  -331,  1224,  1370, -1112,   954, -1382, -1508,
    -455,  -462,  -726,  -521,   818,   122, -1521,   800,
    -910,   560, -1286,  1147,  -895,   474, -1237,   172,
    -200,   125, -1257,  -724,  1328,  -702,  -630,  -862,
    1242,  1457,  -159,  1028,  -834, -1429,  -245,  1142,
    1434,   647,   412,  -532,  -428,  -644, -1620, -1052
};

// Montgomery Reduction: a * 2^-16 mod 3329
// Bu işlem, bilgisayarın zorlandığı 'modül' (bölme) işlemini, 
// çok daha hızlı olan 'kaydırma' (shift) ve 'çarpma' işlemlerine dönüştürür.
static int16_t montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;
    u = (int16_t)(a * QINV);
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

// Barrett Reduction: a mod 3329
// Sayıyı her zaman [0, 3328] arasına hapseder.
static int16_t barrett_reduce(int16_t a) {
    int32_t t;
    const int16_t v = (1 << 26) / KYBER_Q + 1;
    t = v * a;
    t >>= 26;
    t *= KYBER_Q;
    return a - (int16_t)t;
}

static int16_t fqmul(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}

// Forward NTT (Sayı Teorik Dönüşümü)
// Bu fonksiyon, polinom dünyasının 'Süper Gücü'dür. 
// Normalde iki polinomu çarpmak çok uzun sürerken (Lise matematiği gibi), 
// bu dönüşümle sayıları frekans alanına taşıyıp sadece karşılıklı elemanları çarparak 
// devasa hız kazanıyoruz (O(n log n)).
void ntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                // Kelebek (Butterfly) operasyonu: Sayıları birbirine karıştırıp frekansa taşıyoruz.
                int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

// Inverse NTT
// Frekans alanındaki polinomu tekrar zaman (katsayı) alanına döndürür.
void invntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t zeta;

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }

    // Normalizasyon: her katsayıyı 2^-16 * f mod 3329 ile çarpıyoruz
    // f = 1441 (n^-1 mod q'nun Montgomery temsilcisi)
    for (j = 0; j < 256; j++) {
        r[j] = fqmul(r[j], 1441);
    }
}

// Base multiplication in NTT domain
// x^2 - zeta için çarpım
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0]  = fqmul(a[1], b[1]);
    r[0]  = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1]  = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
