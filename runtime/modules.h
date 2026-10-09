#ifndef TWEAKWIN_MODULES_H
#define TWEAKWIN_MODULES_H

#include "winapi.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Internal module registry. The loader never patches IAT slots with
 * hard-coded addresses; it asks this resolver for (DLL, name/ordinal).
 */

typedef struct {
    const char *name;   /* NULL if ordinal-only */
    uint16_t ordinal;   /* 0 if the export is name-only */
    uint64_t addr;      /* host function using TW_MS_ABI (bit pattern) */
} tw_export;

typedef struct {
    const char *name;   /* e.g. "kernel32.dll" */
    const tw_export *exports;
    size_t nexports;
} tw_module;

void tw_modules_init(void);

/* Case-insensitive DLL lookup. NULL if the namespace is not registered. */
const tw_module *tw_modules_find(const char *dll);

/*
 * Resolve one import. On failure writes a short reason into `err` and
 * returns NULL. `by_ordinal` uses `ordinal`; otherwise `name` is required.
 */
uint64_t tw_modules_resolve(const char *dll, const char *name, uint16_t ordinal,
                            int by_ordinal, char *err, size_t errlen);

void tw_modules_register_kernel32(void);
void tw_modules_register_ntdll(void);

#endif
