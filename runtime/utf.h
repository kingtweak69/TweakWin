#ifndef TWEAKWIN_UTF_H
#define TWEAKWIN_UTF_H

/*
 * M2 ANSI code page is UTF-8 for both CP_ACP and CP_UTF8. No other code
 * page is accepted. This is a documented TweakWin policy, not a claim that
 * Windows ACP is UTF-8.
 */

#include <stddef.h>
#include <stdint.h>

#define TW_CP_ACP  0u
#define TW_CP_UTF8 65001u

int tw_cp_ok(uint32_t cp);

/* Decode one UTF-8 sequence. Returns 0, or -1 if invalid. */
int tw_utf8_decode(const uint8_t *s, size_t n, uint32_t *cp, size_t *used);

/* Encode one code point. Returns bytes written, or 0 if it does not fit. */
size_t tw_utf8_encode(uint32_t cp, uint8_t *out, size_t cap);

/* UTF-16LE code units, including surrogate pairs. Returns units, or 0. */
size_t tw_utf16_encode(uint32_t cp, uint16_t *out, size_t cap);

/*
 * Convert a bounded UTF-8 string. If `src_len` < 0 the source is
 * NUL-terminated and the result includes a NUL. If `dst_units` is 0,
 * *needed is the required unit count and no write is performed.
 * Returns 0 on success, -1 on invalid UTF-8 (when strict), -2 if the
 * destination is too small (*needed still set).
 */
int tw_utf8_to_utf16(const uint8_t *src, int src_len, uint16_t *dst, size_t dst_units,
                     size_t *needed, int strict);

int tw_utf16_to_utf8(const uint16_t *src, int src_units, uint8_t *dst, size_t dst_bytes,
                     size_t *needed, int strict);

#endif
