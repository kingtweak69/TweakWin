#ifndef TWEAKWIN_GUESTSTR_H
#define TWEAKWIN_GUESTSTR_H

/*
 * Read a guest NUL-terminated string without ever loading a byte that has
 * not been checked. `max_units` includes the terminating NUL.
 */

#include <stddef.h>
#include <stdint.h>

struct tw_loaded;

/* On success *len is the byte count without the NUL. */
int tw_guest_cstr(const struct tw_loaded *im, uint64_t addr, size_t max_bytes,
                  const char **out, size_t *len);

/* addr must be 2-byte aligned. *units is the count of uint16_t without the NUL. */
int tw_guest_wstr(const struct tw_loaded *im, uint64_t addr, size_t max_units,
                  const uint16_t **out, size_t *units);

#endif
