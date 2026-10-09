#ifndef TWEAKWIN_PROCESS_H
#define TWEAKWIN_PROCESS_H

/*
 * Single guest thread. LastError belongs to that thread, not to the host.
 * The guest environment is not the host environ pointer.
 */

#include "winapi.h"

#include <stddef.h>
#include <stdint.h>

struct tw_loaded;

int tw_runtime_bind(struct tw_loaded *im, const char *exe, int argc, char **argv);
void tw_runtime_unbind(void);
int tw_runtime_bound(void);
struct tw_loaded *tw_runtime_image(void);

void tw_set_last_error(uint32_t err);
uint32_t tw_get_last_error(void);

uint64_t tw_runtime_cmdline_a(void);
uint64_t tw_runtime_cmdline_w(void);
const char *tw_runtime_exe(void);
uint64_t tw_runtime_k32_base(void);
uint64_t tw_runtime_ntdll_base(void);
TW_HANDLE tw_runtime_heap(void);

/* Monotonic nanoseconds since an arbitrary epoch (CLOCK_MONOTONIC). */
uint64_t tw_runtime_mono_ns(void);

/*
 * Guest environment. Names are ASCII. Values are UTF-8.
 * Host variables are copied only when the name starts with
 * TWEAKWIN_GUEST_; the prefix is stripped. Nothing else is inherited.
 */
int tw_env_get_a(const char *name, char *buf, uint32_t cap, uint32_t *needed);
int tw_env_set_a(const char *name, const char *value); /* value NULL deletes */
uint64_t tw_env_block_a(void);
uint64_t tw_env_block_w(void);
int tw_env_block_free(uint64_t addr);

/*
 * tw_env_get_a: 0 found. *needed includes the NUL. A NULL buf or a cap
 *   below *needed does not write; the caller checks cap.
 *   1 not found. -1 invalid name.
 * tw_env_set_a: 0 ok, -1 rejected.
 * tw_env_block_free: 0 freed a block this runtime handed out, -1 otherwise.
 */

#endif
