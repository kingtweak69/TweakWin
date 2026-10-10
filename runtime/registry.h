#ifndef TWEAKWIN_REGISTRY_H
#define TWEAKWIN_REGISTRY_H

/*
 * Isolated virtual registry (M4). Entirely in memory: nothing here reads or
 * writes the host's registry, and nothing is persisted. HKEY_CURRENT_USER
 * and HKEY_LOCAL_MACHINE are two independent empty trees. Return values are
 * Win32 error codes (ERROR_SUCCESS == 0).
 *
 * Strings are UTF-8 here. Value data is opaque bytes; the advapi32 layer
 * stores REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ as UTF-16LE so the A and W
 * entry points see the same value.
 */

#include <stddef.h>
#include <stdint.h>

#define TW_HKEY_CURRENT_USER  0x80000001u
#define TW_HKEY_LOCAL_MACHINE 0x80000002u

#define TW_REG_NONE      0u
#define TW_REG_SZ        1u
#define TW_REG_EXPAND_SZ 2u
#define TW_REG_BINARY    3u
#define TW_REG_DWORD     4u
#define TW_REG_DWORD_BE  5u
#define TW_REG_MULTI_SZ  7u
#define TW_REG_QWORD     11u

#define TW_REG_CREATED_NEW_KEY     1u
#define TW_REG_OPENED_EXISTING_KEY 2u

#define TW_REG_MAX_NAME  255u
#define TW_REG_MAX_DATA  (1u << 20)

/* `parent` is a predefined key (HKCU / HKLM, sign-extended or not) or an
 * open handle. subkey may be NULL or "" (re-open parent). */
uint32_t tw_reg_open(uint64_t parent, const char *subkey, int create, uint64_t *out, uint32_t *disposition);
uint32_t tw_reg_close(uint64_t key);
uint32_t tw_reg_set(uint64_t key, const char *name, uint32_t type, const void *data, uint32_t len);
/* *data is malloc'd (caller frees); *len its size. */
uint32_t tw_reg_get(uint64_t key, const char *name, uint32_t *type, uint8_t **data, uint32_t *len);
uint32_t tw_reg_delete_value(uint64_t key, const char *name);
size_t tw_reg_open_handles(void);
void tw_reg_reset(void);

#endif
