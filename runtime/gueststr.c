#include "gueststr.h"

#include "../loader/load.h"

int tw_guest_cstr(const struct tw_loaded *im, uint64_t addr, size_t max_bytes,
                  const char **out, size_t *len)
{
    if (!im || !out || !len || max_bytes == 0) return -1;
    for (size_t i = 0; i < max_bytes; i++) {
        if (addr + i < addr) return -1;
        if (!tw_guest_readable(im, addr + i, 1)) return -1;
        const char *p = (const char *)(uintptr_t)(addr + i);
        if (p[0] == '\0') {
            *out = (const char *)(uintptr_t)addr;
            *len = i;
            return 0;
        }
    }
    return -1;
}

int tw_guest_wstr(const struct tw_loaded *im, uint64_t addr, size_t max_units,
                  const uint16_t **out, size_t *units)
{
    if (!im || !out || !units || max_units == 0) return -1;
    if ((addr & 1u) != 0) return -1;
    for (size_t i = 0; i < max_units; i++) {
        uint64_t a = addr + i * 2;
        if (a < addr) return -1;
        if (!tw_guest_readable(im, a, 2)) return -1;
        const uint16_t *p = (const uint16_t *)(uintptr_t)a;
        if (p[0] == 0) {
            *out = (const uint16_t *)(uintptr_t)addr;
            *units = i;
            return 0;
        }
    }
    return -1;
}
