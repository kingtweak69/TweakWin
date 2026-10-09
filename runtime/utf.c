#include "utf.h"

#include <stddef.h>

int tw_cp_ok(uint32_t cp)
{
    return cp == TW_CP_ACP || cp == TW_CP_UTF8;
}

/* Local bound so a missing NUL cannot walk off a host pointer we already trust. */
static size_t strlen_max(const uint8_t *s, size_t cap)
{
    for (size_t i = 0; i < cap; i++)
        if (s[i] == 0) return i;
    return (size_t)-1;
}

int tw_utf8_decode(const uint8_t *s, size_t n, uint32_t *cp, size_t *used)
{
    if (!s || n == 0 || !cp || !used) return -1;
    uint8_t c0 = s[0];
    if (c0 < 0x80) { *cp = c0; *used = 1; return 0; }
    size_t need = 0;
    uint32_t minv = 0;
    uint32_t v = 0;
    if ((c0 & 0xE0) == 0xC0) { need = 2; v = c0 & 0x1F; minv = 0x80; }
    else if ((c0 & 0xF0) == 0xE0) { need = 3; v = c0 & 0x0F; minv = 0x800; }
    else if ((c0 & 0xF8) == 0xF0) { need = 4; v = c0 & 0x07; minv = 0x10000; }
    else return -1;
    if (n < need) return -1;
    for (size_t i = 1; i < need; i++) {
        if ((s[i] & 0xC0) != 0x80) return -1;
        v = (v << 6) | (s[i] & 0x3F);
    }
    if (v < minv || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) return -1;
    *cp = v;
    *used = need;
    return 0;
}

size_t tw_utf8_encode(uint32_t cp, uint8_t *out, size_t cap)
{
    if (!out) return 0;
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    if (cp < 0x80) {
        if (cap < 1) return 0;
        out[0] = (uint8_t)cp;
        return 1;
    }
    if (cp < 0x800) {
        if (cap < 2) return 0;
        out[0] = (uint8_t)(0xC0 | (cp >> 6));
        out[1] = (uint8_t)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        if (cap < 3) return 0;
        out[0] = (uint8_t)(0xE0 | (cp >> 12));
        out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    }
    if (cap < 4) return 0;
    out[0] = (uint8_t)(0xF0 | (cp >> 18));
    out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

size_t tw_utf16_encode(uint32_t cp, uint16_t *out, size_t cap)
{
    if (!out || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    if (cp < 0x10000) {
        if (cap < 1) return 0;
        out[0] = (uint16_t)cp;
        return 1;
    }
    if (cap < 2) return 0;
    uint32_t u = cp - 0x10000;
    out[0] = (uint16_t)(0xD800 | (u >> 10));
    out[1] = (uint16_t)(0xDC00 | (u & 0x3FF));
    return 2;
}

static int decode16(const uint16_t *s, size_t n, uint32_t *cp, size_t *used)
{
    if (n < 1) return -1;
    uint16_t w = s[0];
    if (w >= 0xDC00 && w <= 0xDFFF) return -1;
    if (w >= 0xD800 && w <= 0xDBFF) {
        if (n < 2) return -1;
        uint16_t lo = s[1];
        if (lo < 0xDC00 || lo > 0xDFFF) return -1;
        *cp = 0x10000 + (((uint32_t)(w - 0xD800) << 10) | (uint32_t)(lo - 0xDC00));
        *used = 2;
        return 0;
    }
    *cp = w;
    *used = 1;
    return 0;
}

int tw_utf8_to_utf16(const uint8_t *src, int src_len, uint16_t *dst, size_t dst_units,
                     size_t *needed, int strict)
{
    if (!src || !needed) return -1;
    int term = src_len < 0;
    size_t n = term ? strlen_max(src, 32768) : (size_t)src_len;
    if (term && n == (size_t)-1) return -1;
    size_t outn = 0;
    size_t i = 0;
    while (i < n) {
        uint32_t cp;
        size_t used;
        if (tw_utf8_decode(src + i, n - i, &cp, &used) != 0) {
            if (strict) return -1;
            cp = 0xFFFD;
            used = 1;
        }
        i += used;
        uint16_t tmp[2];
        size_t u = tw_utf16_encode(cp, tmp, 2);
        if (!u) return -1;
        if (dst && outn + u <= dst_units) {
            dst[outn] = tmp[0];
            if (u == 2) dst[outn + 1] = tmp[1];
        }
        outn += u;
    }
    if (term) outn += 1;
    *needed = outn;
    if (dst_units == 0) return 0;
    if (!dst || outn > dst_units) return -2;
    if (term) dst[outn - 1] = 0;
    return 0;
}

int tw_utf16_to_utf8(const uint16_t *src, int src_units, uint8_t *dst, size_t dst_bytes,
                     size_t *needed, int strict)
{
    if (!src || !needed) return -1;
    int term = src_units < 0;
    size_t n;
    if (term) {
        n = 0;
        while (n < 32768 && src[n] != 0) n++;
        if (n == 32768) return -1;
    } else {
        n = (size_t)src_units;
    }
    size_t outn = 0;
    size_t i = 0;
    while (i < n) {
        uint32_t cp;
        size_t used;
        if (decode16(src + i, n - i, &cp, &used) != 0) {
            if (strict) return -1;
            cp = 0xFFFD;
            used = 1;
        }
        i += used;
        uint8_t tmp[4];
        size_t u = tw_utf8_encode(cp, tmp, 4);
        if (!u) return -1;
        if (dst && outn + u <= dst_bytes)
            for (size_t k = 0; k < u; k++) dst[outn + k] = tmp[k];
        outn += u;
    }
    if (term) outn += 1;
    *needed = outn;
    if (dst_bytes == 0) return 0;
    if (!dst || outn > dst_bytes) return -2;
    if (term) dst[outn - 1] = 0;
    return 0;
}
