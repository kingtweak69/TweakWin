/*
 * Glue between the loader/legacy runtime and the rt/ process environment:
 * gather startup facts from an already-bound image, build the PEB/TEB, and
 * apply implicit PE TLS. Kept separate so cli/run.c does not reach into
 * either side's internals.
 */
#include "rt.h"

#include "../loader/load.h"
#include "../loader/pe/pe.h"
#include "../runtime/process.h"
#include "../runtime/winapi.h"
#include "../backend/kb.h"
#include "object.h"

#include <stdint.h>

static uint32_t utf16_bytes(uint64_t p)
{
    if (!p) return 0;
    const uint16_t *s = (const uint16_t *)(uintptr_t)p;
    uint32_t n = 0;
    while (s[n] && n < 0x100000u) n++;
    return n * 2u;
}

int tw_rt_begin(struct tw_loaded *im);
int tw_rt_begin(struct tw_loaded *im)
{
    if (!im) return -1;
    if (tw_kb_init() != TW_KB_OK) return -1;
    tw_obj_init();
    tw_rt_startup su;
    su.image = im;
    su.image_base = im->base;
    su.size_of_image = im->image_size;
    su.entry = im->base + im->pe.entry_rva;
    su.cmdline_w = tw_runtime_cmdline_w();
    su.cmdline_w_bytes = utf16_bytes(su.cmdline_w);
    su.image_path_w = tw_runtime_cmdline_w(); /* argv[0] portion is good enough for the path */
    su.image_path_w_bytes = su.cmdline_w_bytes;
    su.environment_w = tw_env_block_w();
    su.k32_base = tw_runtime_k32_base();
    su.ntdll_base = tw_runtime_ntdll_base();
    su.process_heap = (uint64_t)(uintptr_t)tw_runtime_heap();
    su.tls_dir_rva = (im->pe.ndirs > TW_PE_DIR_TLS) ? im->pe.dirs[TW_PE_DIR_TLS].rva : 0;
    su.std_in = (int64_t)(intptr_t)TW_HANDLE_STDIN;
    su.std_out = (int64_t)(intptr_t)TW_HANDLE_STDOUT;
    su.std_err = (int64_t)(intptr_t)TW_HANDLE_STDERR;
    if (tw_rt_process_init(&su) != 0) return -1;
    if (tw_rt_tls_init() != 0) {
        tw_rt_process_teardown();
        return -1;
    }
    tw_rt_seh_install();
    return 0;
}

void tw_rt_end(void);
void tw_rt_tls_reset(void);
void tw_rt_end(void)
{
    tw_rt_seh_reset();
    tw_obj_reset();
    tw_rt_tls_reset();
    tw_rt_process_teardown();
}
