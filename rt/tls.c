/*
 * Windows TLS, both kinds, kept distinct:
 *
 *  - Implicit (PE) TLS: the image's IMAGE_TLS_DIRECTORY64 describes a raw
 *    data template and a zero-fill tail. Each thread gets its own copy,
 *    pointed to by TEB.ThreadLocalStoragePointer[tls_index]; the loader
 *    stores the allocated index at *AddressOfIndex. __declspec(thread)
 *    data is addressed as GS:[0x58] -> [index*8] -> offset.
 *
 *  - Dynamic TLS: TlsAlloc/TlsSetValue/TlsGetValue/TlsFree use the 64
 *    TEB.TlsSlots (GS:[0x1480]). A free bitmap guards allocation.
 *
 * Only one PE TLS index is supported (one image). Callbacks run with the
 * documented reasons.
 */
#include "rt.h"
#include "winnt.h"

#include "../backend/kb.h"
#include "../loader/load.h"
#include "../loader/pe/pe.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>

uint64_t tw_rt_current_teb(void);
const tw_rt_startup *tw_rt_startup_info(void);

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3

static pthread_mutex_t g_tls_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_pe_tls_present;
static uint32_t g_pe_tls_index;        /* chosen index into the TLS array */
static uint64_t g_tls_template;        /* raw data start (guest VA) */
static uint64_t g_tls_template_end;
static uint32_t g_tls_zerofill;
static uint64_t g_tls_callbacks_va;
static uint8_t g_dyn_used[TEB_TLS_SLOTS];

static uint32_t rd32(uint64_t a) { uint32_t v; memcpy(&v, (void *)(uintptr_t)a, 4); return v; }
static uint64_t rd64(uint64_t a) { uint64_t v; memcpy(&v, (void *)(uintptr_t)a, 8); return v; }
static void wr64(uint64_t a, uint64_t v) { memcpy((void *)(uintptr_t)a, &v, 8); }

/* Allocate and fill this thread's implicit-TLS block, link it into the
 * TEB's ThreadLocalStoragePointer array (which we allocate lazily). */
static int attach_pe_tls(uint64_t teb)
{
    if (!g_pe_tls_present) return 0;
    uint64_t tmpl_bytes = g_tls_template_end - g_tls_template;
    uint64_t total = tmpl_bytes + g_tls_zerofill;
    if (total == 0) total = 1;

    /* The TLS array: (index+1) slots of 8 bytes. */
    uint64_t arr = rt_galloc((g_pe_tls_index + 1) * 8);
    if (!arr) return -1;
    uint64_t block = rt_galloc(total);
    if (!block) {
        rt_gfree(arr);
        return -1;
    }
    if (tmpl_bytes) memcpy((void *)(uintptr_t)block, (const void *)(uintptr_t)g_tls_template, tmpl_bytes);
    /* zero-fill tail already zero from rt_galloc */
    wr64(arr + g_pe_tls_index * 8, block);
    wr64(teb + TEB_ThreadLocalStoragePointer, arr);
    return 0;
}

static void detach_pe_tls(uint64_t teb)
{
    if (!g_pe_tls_present || !teb) return;
    uint64_t arr = rd64(teb + TEB_ThreadLocalStoragePointer);
    if (!arr) return;
    uint64_t block = rd64(arr + g_pe_tls_index * 8);
    if (block) rt_gfree(block);
    rt_gfree(arr);
    wr64(teb + TEB_ThreadLocalStoragePointer, 0);
}

int tw_rt_tls_init(void)
{
    const tw_rt_startup *su = tw_rt_startup_info();
    struct tw_loaded *im = tw_rt_image();
    if (!im || su->tls_dir_rva == 0) {
        /* No implicit TLS. Still give the main thread an (empty) TLS array
         * pointer so TlsGetValue has somewhere defined to look? Not needed:
         * dynamic slots live directly in the TEB. */
        return 0;
    }
    uint64_t dir = su->image_base + su->tls_dir_rva;
    if (!tw_guest_readable(im, dir, sizeof(tw_image_tls_dir64))) return -1;
    uint64_t raw_start = rd64(dir + 0);
    uint64_t raw_end = rd64(dir + 8);
    uint64_t idx_addr = rd64(dir + 16);
    uint64_t cb_va = rd64(dir + 24);
    uint32_t zerofill = rd32(dir + 32);
    if (raw_end < raw_start || raw_end - raw_start > (64u << 20)) return -1;
    /* Bound the zero-fill too: a hostile TLS directory must not make the
     * per-thread block allocation balloon. Cap the whole block at 64 MiB. */
    if (zerofill > (64u << 20) || (raw_end - raw_start) + (uint64_t)zerofill > (64u << 20)) return -1;
    if (raw_start && !tw_guest_readable(im, raw_start, raw_end - raw_start)) return -1;

    g_pe_tls_present = 1;
    g_pe_tls_index = 0; /* single image: index 0 */
    g_tls_template = raw_start;
    g_tls_template_end = raw_end;
    g_tls_zerofill = zerofill;
    g_tls_callbacks_va = cb_va;
    /* Publish the chosen index at *AddressOfIndex (writable image data). */
    if (idx_addr && tw_guest_writable(im, idx_addr, 4)) {
        uint32_t v = g_pe_tls_index;
        memcpy((void *)(uintptr_t)idx_addr, &v, 4);
    }
    /* Attach to the main-thread TEB: GS is not set until tw_execute, so the
     * current-TEB accessor would read 0 here. */
    return attach_pe_tls(tw_rt_main_teb());
}

int tw_rt_tls_thread_attach(uint64_t teb)
{
    pthread_mutex_lock(&g_tls_mu);
    int rc = attach_pe_tls(teb);
    pthread_mutex_unlock(&g_tls_mu);
    return rc;
}

void tw_rt_tls_thread_detach(uint64_t teb)
{
    pthread_mutex_lock(&g_tls_mu);
    detach_pe_tls(teb);
    pthread_mutex_unlock(&g_tls_mu);
}

void tw_rt_tls_run_callbacks(uint32_t reason)
{
    if (!g_pe_tls_present || !g_tls_callbacks_va) return;
    struct tw_loaded *im = tw_rt_image();
    uint64_t p = g_tls_callbacks_va;
    for (int i = 0; i < 64; i++) {
        if (!tw_guest_readable(im, p, 8)) break;
        uint64_t fn = rd64(p);
        if (fn == 0) break;
        if (!tw_guest_readable(im, fn, 1)) break;
        void(__attribute__((ms_abi)) * cb)(void *, uint32_t, void *);
        memcpy(&cb, &fn, 8);
        cb((void *)(uintptr_t)tw_rt_image()->base, reason, NULL);
        p += 8;
    }
}

uint32_t tw_rt_tls_alloc(void)
{
    pthread_mutex_lock(&g_tls_mu);
    for (uint32_t i = 0; i < TEB_TLS_SLOTS; i++) {
        if (!g_dyn_used[i]) {
            g_dyn_used[i] = 1;
            pthread_mutex_unlock(&g_tls_mu);
            /* A freshly allocated slot reads as 0 in every thread. We only
             * guarantee the calling thread here; new threads get zeroed
             * TEBs, and other existing threads are not reset by Windows
             * either beyond the current thread, which matches. */
            uint64_t teb = tw_rt_current_teb();
            if (teb) wr64(teb + TEB_TlsSlots + i * 8, 0);
            return i;
        }
    }
    pthread_mutex_unlock(&g_tls_mu);
    return TW_TLS_OUT_OF_INDEXES;
}

int tw_rt_tls_free(uint32_t index)
{
    if (index >= TEB_TLS_SLOTS) return -1;
    pthread_mutex_lock(&g_tls_mu);
    int was = g_dyn_used[index];
    g_dyn_used[index] = 0;
    pthread_mutex_unlock(&g_tls_mu);
    return was ? 0 : -1;
}

uint64_t tw_rt_tls_get(uint32_t index, int *ok)
{
    uint64_t teb = tw_rt_current_teb();
    if (index >= TEB_TLS_SLOTS || !teb) {
        if (ok) *ok = 0;
        return 0;
    }
    if (ok) *ok = 1;
    return rd64(teb + TEB_TlsSlots + index * 8);
}

int tw_rt_tls_set(uint32_t index, uint64_t value)
{
    uint64_t teb = tw_rt_current_teb();
    if (index >= TEB_TLS_SLOTS || !teb) return -1;
    wr64(teb + TEB_TlsSlots + index * 8, value);
    return 0;
}

void tw_rt_tls_reset(void);
void tw_rt_tls_reset(void)
{
    pthread_mutex_lock(&g_tls_mu);
    g_pe_tls_present = 0;
    g_tls_callbacks_va = 0;
    memset(g_dyn_used, 0, sizeof g_dyn_used);
    pthread_mutex_unlock(&g_tls_mu);
}
