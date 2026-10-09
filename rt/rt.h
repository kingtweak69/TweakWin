#ifndef TWEAKWIN_RT_H
#define TWEAKWIN_RT_H

/*
 * TweakWin runtime: the process/thread environment that sits above the
 * kernel backend (backend/kb.h) and below the Win32 DLLs. It owns the real
 * x86-64 Windows PEB/TEB, Windows TLS (implicit PE TLS and TlsAlloc slots),
 * threads, synchronization objects, and the SEH-foundation exception path.
 *
 * All guest-visible runtime memory is allocated through the backend VM
 * (rt_galloc), so it is validated by tw_rt_guest_check on both the host and
 * TweakKernel M4, and it is page-protected and thread-safe.
 */

#include <stddef.h>
#include <stdint.h>

struct tw_loaded;

/* ---- guest memory (backend VM, thread-safe) ---- */

/* Reserve+commit `size` bytes of RW guest memory. Returns the base, or 0.
 * Tracked so rt_gfree / tw_rt_guest_check see it. */
uint64_t rt_galloc(size_t size);
/* Commit with an explicit protection (1 R, 3 RW, 5 RX), page-rounded. */
uint64_t rt_galloc_prot(size_t size, uint32_t kb_prot);
int rt_gprotect(uint64_t base, size_t size, uint32_t kb_prot);
void rt_gfree(uint64_t base);

/* True if [addr,addr+len) is committed rt/backend memory with `need`
 * (PROT_READ=0x1 / PROT_WRITE=0x2 bits, matching sys/mman). */
int tw_rt_guest_check(uint64_t addr, uint64_t len, int need);

/* ---- process / thread environment ---- */

typedef struct tw_rt_startup {
    struct tw_loaded *image;  /* the mapped main image */
    uint64_t image_base;
    uint32_t size_of_image;
    uint64_t entry;           /* absolute entry VA */
    uint64_t cmdline_w;       /* UTF-16 command line (guest ptr) */
    uint32_t cmdline_w_bytes; /* length in bytes, no NUL */
    uint64_t image_path_w;    /* UTF-16 image path (guest ptr) */
    uint32_t image_path_w_bytes;
    uint64_t environment_w;   /* UTF-16 environment block (guest ptr), or 0 */
    uint64_t k32_base;
    uint64_t ntdll_base;
    uint64_t process_heap;    /* guest HANDLE value for the process heap */
    uint64_t tls_dir_rva;     /* PE TLS directory RVA, or 0 */
    int64_t std_in, std_out, std_err; /* Win32 HANDLE values */
} tw_rt_startup;

/* Build PEB, process parameters, loader data, and the main-thread TEB.
 * Returns 0 and records the environment, or -1. */
int tw_rt_process_init(const tw_rt_startup *su);
void tw_rt_process_teardown(void);
int tw_rt_active(void);

uint64_t tw_rt_peb(void);
uint64_t tw_rt_main_teb(void);
struct tw_loaded *tw_rt_image(void);

/* Current thread's TEB (0 if the calling host/kernel thread has none). */
uint64_t tw_rt_current_teb(void);
void tw_rt_set_current_teb(uint64_t teb);
/* Build a TEB for a thread with user stack [limit, base). */
uint64_t tw_rt_build_teb(uint64_t stack_base, uint64_t stack_limit, uint64_t tid);

/* Per-thread last error, stored in TEB.LastErrorValue. */
void tw_rt_set_last_error(uint32_t code);
uint32_t tw_rt_get_last_error(void);

/* Gather startup facts from an already-bound image and build the process
 * environment (PEB/TEB) plus implicit PE TLS. 0 on success. */
int tw_rt_begin(struct tw_loaded *im);
void tw_rt_end(void);

/* ---- SEH foundation (vectored handlers + top-level filter) ---- */
int tw_rt_seh_install(void);
void tw_rt_seh_reset(void);
/* Returns an opaque non-zero cookie, or 0. */
uint64_t tw_rt_veh_add(int first, uint64_t handler);
int tw_rt_veh_remove(uint64_t cookie);
uint64_t tw_rt_set_unhandled_filter(uint64_t filter);

/* ---- Windows TLS ---- */

/* Implicit PE TLS: parse the TLS directory and install the main thread's
 * block + allocate the TLS index. Safe to call with tls_dir_rva == 0. */
int tw_rt_tls_init(void);
/* Allocate/free this process's TLS block for the calling thread (used when
 * a new thread starts and ends). */
int tw_rt_tls_thread_attach(uint64_t teb);
void tw_rt_tls_thread_detach(uint64_t teb);
/* Run the PE TLS callbacks with the given reason (DLL_PROCESS_ATTACH=1,
 * THREAD_ATTACH=2, THREAD_DETACH=3, PROCESS_DETACH=0). */
void tw_rt_tls_run_callbacks(uint32_t reason);

/* TlsAlloc family (dynamic TLS slots in the TEB). */
#define TW_TLS_OUT_OF_INDEXES 0xFFFFFFFFu
uint32_t tw_rt_tls_alloc(void);
int tw_rt_tls_free(uint32_t index);
uint64_t tw_rt_tls_get(uint32_t index, int *ok);
int tw_rt_tls_set(uint32_t index, uint64_t value);

#endif
