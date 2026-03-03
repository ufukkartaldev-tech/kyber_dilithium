#include "../include/encryption.h"
#include <string.h>

namespace PQC {
namespace Symmetric {

uint32_t ChaCha20::rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void ChaCha20::quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

void ChaCha20::process(uint8_t* out, const uint8_t* in, size_t len, 
                        const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16];
    uint32_t working_state[16];
    uint8_t key_stream[64];
    
    // Sabitler (expa nd 3 2-by te k ey)
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key (32 bytes)
    for (int i = 0; i < 8; i++) {
        state[4+i] = ((uint32_t)key[i*4+0]) | ((uint32_t)key[i*4+1] << 8) |
                    ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    
    // Counter + Nonce
    state[12] = counter;
    for (int i = 0; i < 3; i++) {
        state[13+i] = ((uint32_t)nonce[i*4+0]) | ((uint32_t)nonce[i*4+1] << 8) |
                     ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }
    
    size_t in_pos = 0;
    while (in_pos < len) {
        memcpy(working_state, state, sizeof(state));
        
        // 20 Rounds (10 iterations of double-round)
        for (int i = 0; i < 10; i++) {
            // Column rounds
            quarter_round(working_state[0], working_state[4], working_state[8],  working_state[12]);
            quarter_round(working_state[1], working_state[5], working_state[9],  working_state[13]);
            quarter_round(working_state[2], working_state[6], working_state[10], working_state[14]);
            quarter_round(working_state[3], working_state[7], working_state[11], working_state[15]);
            // Diagonal rounds
            quarter_round(working_state[0], working_state[5], working_state[10], working_state[15]);
            quarter_round(working_state[1], working_state[6], working_state[11], working_state[12]);
            quarter_round(working_state[2], working_state[7], working_state[8],  working_state[13]);
            quarter_round(working_state[3], working_state[4], working_state[9],  working_state[14]);
        }
        
        // Add original state
        for (int i = 0; i < 16; i++) {
            uint32_t val = working_state[i] + state[i];
            key_stream[i*4+0] = (uint8_t)(val & 0xFF);
            key_stream[i*4+1] = (uint8_t)((val >> 8) & 0xFF);
            key_stream[i*4+2] = (uint8_t)((val >> 16) & 0xFF);
            key_stream[i*4+3] = (uint8_t)((val >> 24) & 0xFF);
        }
        
        // XOR with input
        size_t block_len = (len - in_pos < 64) ? (len - in_pos) : 64;
        for (size_t i = 0; i < block_len; i++) {
            out[in_pos + i] = in[in_pos + i] ^ key_stream[i];
        }
        
        in_pos += block_len;
        state[12]++; // Increment counter
    }
}

} // namespace Symmetric
} // namespace PQC
