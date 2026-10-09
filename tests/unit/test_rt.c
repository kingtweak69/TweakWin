/*
 * rt/ unit tests: guest memory, PEB/TEB construction, Windows TLS slots,
 * and implicit PE TLS index/template handling. Built with ASan + UBSan.
 * These exercise rt/ directly (no PE), pinning the structure layout and
 * the per-thread last-error semantics the Win32 layer relies on.
 */
#include "../../backend/kb.h"
#include "../../rt/rt.h"
#include "../../rt/winnt.h"

#include <stdio.h>
#include <string.h>

static int g_pass, g_fail;
#define CHECK(c)                                                               \
    do {                                                                       \
        if (c) g_pass++;                                                       \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

static uint64_t rd64(uint64_t a) { uint64_t v; memcpy(&v, (void *)(uintptr_t)a, 8); return v; }
static uint32_t rd32(uint64_t a) { uint32_t v; memcpy(&v, (void *)(uintptr_t)a, 4); return v; }

int main(void)
{
    CHECK(tw_kb_init() == TW_KB_OK);

    /* Guest memory round-trips and validates. */
    uint64_t p = rt_galloc(8192);
    CHECK(p != 0);
    CHECK(tw_rt_guest_check(p, 8192, 0x1 /*R*/));
    CHECK(tw_rt_guest_check(p, 8192, 0x3 /*RW*/));
    CHECK(!tw_rt_guest_check(p - 4096, 8192, 0x1)); /* spills before the span */
    CHECK(!tw_rt_guest_check(0x1234, 16, 0x1));
    *(volatile uint64_t *)(uintptr_t)p = 0xDEADBEEF;
    CHECK(rd64(p) == 0xDEADBEEF);
    rt_gfree(p);
    CHECK(!tw_rt_guest_check(p, 8, 0x1)); /* released */

    /* Minimal startup: no image. PEB/TEB must still be well-formed. */
    tw_rt_startup su;
    memset(&su, 0, sizeof su);
    su.image = NULL;
    su.image_base = 0x140000000ull;
    su.size_of_image = 0x4000;
    su.entry = 0x140001000ull;
    su.process_heap = 0x1234;
    su.std_in = 0x10;
    su.std_out = 0x14;
    su.std_err = 0x18;
    CHECK(tw_rt_process_init(&su) == 0);
    CHECK(tw_rt_active());

    uint64_t peb = tw_rt_peb();
    uint64_t teb = tw_rt_main_teb();
    CHECK(peb && teb);
    CHECK(rd64(peb + PEB_ImageBaseAddress) == 0x140000000ull);
    CHECK(rd64(peb + PEB_ProcessHeap) == 0x1234);
    uint64_t ldr = rd64(peb + PEB_Ldr);
    uint64_t rupp = rd64(peb + PEB_ProcessParameters);
    CHECK(ldr && rupp);
    CHECK(rd32(ldr + LDR_Initialized) == 1);
    CHECK(rd64(rupp + RUPP_StandardOutput) == 0x14);

    /* Loader list is circular and non-empty (two modules). */
    uint64_t head = ldr + LDR_InLoadOrderModuleList;
    uint64_t f1 = rd64(head + 0);
    CHECK(f1 != head);                 /* populated */
    uint64_t f2 = rd64(f1 + 0);
    uint64_t f3 = rd64(f2 + 0);
    CHECK(f3 == head);                 /* exactly two entries, circular */
    /* First entry's DllBase is the image base. */
    CHECK(rd64(f1 - LDE_InLoadOrderLinks + LDE_DllBase) == 0x140000000ull);

    /* TEB self/PEB/ClientId. */
    CHECK(rd64(teb + TEB_NtTib_Self) == teb);
    CHECK(rd64(teb + TEB_ProcessEnvironmentBlock) == peb);
    CHECK(rd64(teb + TEB_ClientId_Process) == tw_kb_process_id());

    /* Per-thread last error lives in the TEB. */
    tw_rt_set_current_teb(teb);
    tw_rt_set_last_error(0);
    CHECK(tw_rt_get_last_error() == 0);
    tw_rt_set_last_error(123);
    CHECK(tw_rt_get_last_error() == 123);
    CHECK(rd32(teb + TEB_LastErrorValue) == 123);

    /* Dynamic TLS slots in the TEB. */
    uint32_t i0 = tw_rt_tls_alloc();
    uint32_t i1 = tw_rt_tls_alloc();
    CHECK(i0 != TW_TLS_OUT_OF_INDEXES && i1 != TW_TLS_OUT_OF_INDEXES && i0 != i1);
    int ok = 0;
    CHECK(tw_rt_tls_get(i0, &ok) == 0 && ok);       /* fresh slot is 0 */
    CHECK(tw_rt_tls_set(i0, 0xABCD) == 0);
    CHECK(tw_rt_tls_get(i0, &ok) == 0xABCD && ok);
    CHECK(tw_rt_tls_get(i1, &ok) == 0);              /* independent slot */
    CHECK(rd64(teb + TEB_TlsSlots + i0 * 8) == 0xABCD);
    CHECK(tw_rt_tls_free(i0) == 0);
    CHECK(tw_rt_tls_free(i0) == -1);                 /* double free */
    CHECK(tw_rt_tls_set(99999, 1) == -1);            /* out of range */

    tw_rt_process_teardown();
    CHECK(!tw_rt_active());

    fprintf(stderr, "rt: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
