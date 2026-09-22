/* Byte-wise CRC over a fixed polynomial table, written for the tree that
 * documents what this build refuses: SWP-1 has no C grammar, and its lexical
 * fallback is bound to no extension, so `swp protect` declines a file like
 * this one instead of guessing at it. See ../README.md. */

#include <stddef.h>
#include <stdint.h>

#define POLY 0x8408u
#define MAX_LINE 240

static uint16_t crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i += 1) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit += 1) {
            if (crc & 1) {
                crc = (uint16_t)((crc >> 1) ^ POLY);
            } else {
                crc = (uint16_t)(crc >> 1);
            }
        }
    }
    return crc;
}

int frame_write(const uint8_t *payload, size_t len, uint8_t *out, size_t cap) {
    if (len > MAX_LINE) {
        return -1;
    }
    if (cap < len + 3) {
        return -2;
    }
    out[0] = 0xA5;
    for (size_t i = 0; i < len; i += 1) {
        out[1 + i] = payload[i];
    }
    uint16_t crc = crc16(payload, len);
    out[1 + len] = (uint8_t)(crc & 0xFF);
    out[2 + len] = (uint8_t)(crc >> 8);
    return (int)(len + 3);
}

int frame_accepts(const uint8_t *frame, size_t len) {
    if (len < 3) {
        return 0;
    }
    if (frame[0] != 0xA5) {
        return 0;
    }
    uint16_t crc = crc16(frame + 1, len - 3);
    uint16_t want = (uint16_t)(frame[len - 2] | (frame[len - 1] << 8));
    return crc == want;
}
