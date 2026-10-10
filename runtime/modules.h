#ifndef TWEAKWIN_MODULES_H
#define TWEAKWIN_MODULES_H

#include "winapi.h"

#include "../loader/load.h"

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

/* ---- M4 dynamic module loader ---------------------------------------- */

/*
 * Bind an import of `dll` for `importer` (an EXE or a DLL being mapped).
 * Built-in modules always succeed. Any other name is found through the
 * Windows namespace search (winfs), mapped with tw_load_dll, and kept
 * alive by a reference owned by the importer. On failure *err describes
 * the problem and the status maps to the loader error classes.
 */
tw_load_status tw_modules_require(struct tw_loaded *importer, const char *dll,
                                  char *err, size_t errlen);

/* True if [addr, addr+len) lies in a mapped DLL region with `need` PROT bits. */
int tw_modules_guest_check(uint64_t addr, uint64_t len, int need);

/* Run DllMain(PROCESS_ATTACH) for mapped-but-not-attached modules
 * (dependencies first). 0 ok, -1 failed (message in err). */
int tw_modules_attach_pending(char *err, size_t errlen);
/* DllMain(PROCESS_DETACH, reserved != NULL) in reverse attach order. */
void tw_modules_process_detach(void);
/* DLL_THREAD_ATTACH (2) / DLL_THREAD_DETACH (3) for every attached module. */
void tw_modules_thread_notify(uint32_t reason);
/* Unmap every DLL without running guest code. Idempotent. */
void tw_modules_unload_all(void);

/* LoadLibrary-level API. Return Win32 error codes (0 = success). */
#define TW_LOAD_WITH_ALTERED_SEARCH_PATH 0x8u
uint32_t tw_dll_load(const char *name, uint32_t flags, uint64_t *handle);
uint32_t tw_dll_free(uint64_t handle);
/* 0 on failure with *err set (ERROR_MOD_NOT_FOUND / ERROR_PROC_NOT_FOUND). */
uint64_t tw_dll_proc(uint64_t handle, const char *name, uint32_t ordinal, int by_ordinal,
                     uint32_t *err);
/* 0 if `name` is not loaded; does not change the reference count. */
uint64_t tw_dll_module_handle(const char *name);
int tw_dll_path(uint64_t handle, char *out, size_t cap); /* 0 ok */
int tw_dll_refcount(uint64_t handle);                    /* -1 unknown */
size_t tw_dll_count(void);

void tw_modules_register_kernel32(void);
void tw_modules_register_advapi32(void);
void tw_modules_register_ntdll(void);

#endif
