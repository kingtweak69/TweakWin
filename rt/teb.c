/*
 * Real x86-64 Windows process/thread environment: PEB, process parameters,
 * loader data (two modules: the image and kernel32), and a TEB per thread.
 * GS is pointed at the TEB through the backend (tw_kb_tls_set GS), which is
 * what a Windows x86-64 guest reads. All blocks are backend VM so a guest
 * can walk them and tw_rt_guest_check validates pointers into them.
 *
 * Per-thread LastError lives in TEB.LastErrorValue, so error state is
 * genuinely per-thread once threads exist.
 */
#include "rt.h"
#include "winnt.h"

#include "../backend/kb.h"
#include "../loader/load.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>

void tw_rt_mem_reset(void);

static int g_active;
static uint64_t g_peb;
static uint64_t g_main_teb;
static uint64_t g_rupp;
static uint64_t g_ldr;
static struct tw_loaded *g_image;
static tw_rt_startup g_su;

/* Current thread's TEB. Set when a thread enters the guest, cleared on
 * exit. On the host, glibc uses FS for its own TLS, so this __thread lives
 * in FS storage and never collides with the guest GS base. */
static __thread uint64_t t_teb;

uint64_t tw_rt_current_teb(void) { return t_teb; }
void tw_rt_set_current_teb(uint64_t teb);
void tw_rt_set_current_teb(uint64_t teb) { t_teb = teb; }

uint64_t tw_rt_peb(void) { return g_peb; }
uint64_t tw_rt_main_teb(void) { return g_main_teb; }
struct tw_loaded *tw_rt_image(void) { return g_image; }
int tw_rt_active(void) { return g_active; }
const tw_rt_startup *tw_rt_startup_info(void);
const tw_rt_startup *tw_rt_startup_info(void) { return &g_su; }

static void wr16(uint64_t at, uint16_t v) { memcpy((void *)(uintptr_t)at, &v, 2); }
static void wr32(uint64_t at, uint32_t v) { memcpy((void *)(uintptr_t)at, &v, 4); }
static void wr64(uint64_t at, uint64_t v) { memcpy((void *)(uintptr_t)at, &v, 8); }
static uint64_t rd64(uint64_t at)
{
    uint64_t v;
    memcpy(&v, (const void *)(uintptr_t)at, 8);
    return v;
}

/* Write a UNICODE_STRING header at `at` describing `bytes` at `buf`. */
static void unicode_string(uint64_t at, uint64_t buf, uint32_t bytes)
{
    uint16_t len = (uint16_t)bytes;
    wr16(at + 0, len);
    wr16(at + 2, (uint16_t)(len + 2)); /* MaximumLength includes room for NUL */
    wr32(at + 4, 0);
    wr64(at + 8, buf);
}

/* One LDR_DATA_TABLE_ENTRY, linked into the three module lists. `prev_*`
 * are the LIST_ENTRY addresses to link after; pass the list head addresses
 * for the first entry. Returns the entry base. */
static uint64_t make_ldr_entry(uint64_t base, uint32_t size, uint64_t entrypt, uint64_t full_w,
                               uint32_t full_bytes, uint64_t base_w, uint32_t base_bytes)
{
    uint64_t e = rt_galloc(LDE_SIZE);
    if (!e) return 0;
    wr64(e + LDE_DllBase, base);
    wr64(e + LDE_EntryPoint, entrypt);
    wr32(e + LDE_SizeOfImage, size);
    unicode_string(e + LDE_FullDllName, full_w, full_bytes);
    unicode_string(e + LDE_BaseDllName, base_w, base_bytes);
    wr32(e + LDE_Flags, 0x00004000); /* LDRP_PROCESS_ATTACH_CALLED */
    wr16(e + LDE_LoadCount, 0xFFFF);
    return e;
}

/* Insert `entry`'s LIST_ENTRY at field offset `off` at the tail of the
 * circular list whose head LIST_ENTRY is at `head`. */
static void list_append(uint64_t head, uint64_t entry_links)
{
    uint64_t last = rd64(head + 0); /* head.Flink (tail for a populated list) */
    if (last == 0) last = head;     /* empty: head not yet initialised */
    /* entry.Flink = head; entry.Blink = last */
    wr64(entry_links + 0, head);
    wr64(entry_links + 8, last);
    /* last.Flink = entry ; head.Blink = entry */
    wr64(last + 0, entry_links);
    wr64(head + 8, entry_links);
    if (rd64(head + 0) == 0 || last == head) wr64(head + 0, rd64(head + 0) == head ? entry_links : rd64(head + 0));
}

static void list_init(uint64_t head)
{
    wr64(head + 0, head);
    wr64(head + 8, head);
}

static void list_insert_tail(uint64_t head, uint64_t entry_links)
{
    uint64_t blink = rd64(head + 8);
    wr64(entry_links + 0, head);
    wr64(entry_links + 8, blink);
    wr64(blink + 0, entry_links);
    wr64(head + 8, entry_links);
}

static uint64_t build_ldr(void)
{
    uint64_t ldr = rt_galloc(LDR_SIZE);
    if (!ldr) return 0;
    wr32(ldr + LDR_Length, LDR_SIZE);
    wr32(ldr + LDR_Initialized, 1);
    list_init(ldr + LDR_InLoadOrderModuleList);
    list_init(ldr + LDR_InMemoryOrderModuleList);
    list_init(ldr + LDR_InInitializationOrderModuleList);

    /* UTF-16 names in guest memory. */
    static const uint16_t exe_full[] = { 'C',':','\\','t','w','e','a','k','w','i','n','\\','a','p','p','.','e','x','e',0 };
    static const uint16_t exe_base[] = { 'a','p','p','.','e','x','e',0 };
    static const uint16_t k32_full[] = { 'C',':','\\','t','w','e','a','k','w','i','n','\\','k','e','r','n','e','l','3','2','.','d','l','l',0 };
    static const uint16_t k32_base[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };

    uint64_t ef = rt_galloc(sizeof exe_full), eb = rt_galloc(sizeof exe_base);
    uint64_t kf = rt_galloc(sizeof k32_full), kb = rt_galloc(sizeof k32_base);
    if (!ef || !eb || !kf || !kb) return 0;
    memcpy((void *)(uintptr_t)ef, exe_full, sizeof exe_full);
    memcpy((void *)(uintptr_t)eb, exe_base, sizeof exe_base);
    memcpy((void *)(uintptr_t)kf, k32_full, sizeof k32_full);
    memcpy((void *)(uintptr_t)kb, k32_base, sizeof k32_base);

    uint64_t ie = make_ldr_entry(g_su.image_base, g_su.size_of_image, g_su.entry, ef,
                                 (uint32_t)(sizeof exe_full - 2), eb, (uint32_t)(sizeof exe_base - 2));
    uint64_t ke = make_ldr_entry(g_su.k32_base, 0x1000, 0, kf, (uint32_t)(sizeof k32_full - 2), kb,
                                 (uint32_t)(sizeof k32_base - 2));
    if (!ie || !ke) return 0;
    list_insert_tail(ldr + LDR_InLoadOrderModuleList, ie + LDE_InLoadOrderLinks);
    list_insert_tail(ldr + LDR_InLoadOrderModuleList, ke + LDE_InLoadOrderLinks);
    list_insert_tail(ldr + LDR_InMemoryOrderModuleList, ie + LDE_InMemoryOrderLinks);
    list_insert_tail(ldr + LDR_InMemoryOrderModuleList, ke + LDE_InMemoryOrderLinks);
    list_insert_tail(ldr + LDR_InInitializationOrderModuleList, ke + LDE_InInitializationOrderLinks);
    list_insert_tail(ldr + LDR_InInitializationOrderModuleList, ie + LDE_InInitializationOrderLinks);
    (void)list_append;
    return ldr;
}

static uint64_t build_rupp(void)
{
    uint64_t rupp = rt_galloc(RUPP_SIZE);
    if (!rupp) return 0;
    wr32(rupp + RUPP_MaximumLength, RUPP_SIZE);
    wr32(rupp + RUPP_Length, RUPP_SIZE);
    wr64(rupp + RUPP_StandardInput, (uint64_t)g_su.std_in);
    wr64(rupp + RUPP_StandardOutput, (uint64_t)g_su.std_out);
    wr64(rupp + RUPP_StandardError, (uint64_t)g_su.std_err);
    unicode_string(rupp + RUPP_ImagePathName, g_su.image_path_w, g_su.image_path_w_bytes);
    unicode_string(rupp + RUPP_CommandLine, g_su.cmdline_w, g_su.cmdline_w_bytes);
    wr64(rupp + RUPP_Environment, g_su.environment_w);
    return rupp;
}

static uint64_t build_peb(void)
{
    uint64_t peb = rt_galloc(PEB_SIZE);
    if (!peb) return 0;
    wr64(peb + PEB_ImageBaseAddress, g_su.image_base);
    wr64(peb + PEB_Ldr, g_ldr);
    wr64(peb + PEB_ProcessParameters, g_rupp);
    wr64(peb + PEB_ProcessHeap, g_su.process_heap);
    wr32(peb + PEB_NumberOfProcessors, 1);
    wr32(peb + PEB_OSMajorVersion, 10);
    wr32(peb + PEB_OSMinorVersion, 0);
    wr16(peb + PEB_OSBuildNumber, 19041);
    wr32(peb + PEB_OSPlatformId, 2); /* VER_PLATFORM_WIN32_NT */
    return peb;
}

/* Build a TEB for a thread whose user stack runs [stack_limit, stack_base). */
uint64_t tw_rt_build_teb(uint64_t stack_base, uint64_t stack_limit, uint64_t tid);
uint64_t tw_rt_build_teb(uint64_t stack_base, uint64_t stack_limit, uint64_t tid)
{
    uint64_t teb = rt_galloc(TEB_SIZE);
    if (!teb) return 0;
    wr64(teb + TEB_NtTib_StackBase, stack_base);
    wr64(teb + TEB_NtTib_StackLimit, stack_limit);
    wr64(teb + TEB_NtTib_Self, teb);
    wr64(teb + TEB_NtTib_ExceptionList, (uint64_t)-1); /* EXCEPTION_CHAIN_END */
    wr64(teb + TEB_ClientId_Process, tw_kb_process_id());
    wr64(teb + TEB_ClientId_Thread, tid);
    wr64(teb + TEB_ProcessEnvironmentBlock, g_peb);
    wr32(teb + TEB_LastErrorValue, 0);
    return teb;
}

int tw_rt_process_init(const tw_rt_startup *su)
{
    if (!su) return -1;
    g_su = *su;
    g_image = su->image;
    g_ldr = build_ldr();
    g_rupp = build_rupp();
    if (!g_ldr || !g_rupp) return -1;
    g_peb = build_peb();
    if (!g_peb) return -1;
    uint64_t sb = 0, sl = 0;
    if (su->image && su->image->stack) {
        sl = (uint64_t)(uintptr_t)su->image->stack;
        sb = sl + su->image->stack_len;
    }
    g_main_teb = tw_rt_build_teb(sb, sl, tw_kb_thread_id());
    if (!g_main_teb) return -1;
    g_active = 1;
    return 0;
}

void tw_rt_set_main_stack(uint64_t base, uint64_t limit);
void tw_rt_set_main_stack(uint64_t base, uint64_t limit)
{
    if (g_main_teb) {
        wr64(g_main_teb + TEB_NtTib_StackBase, base);
        wr64(g_main_teb + TEB_NtTib_StackLimit, limit);
    }
}

void tw_rt_process_teardown(void)
{
    g_active = 0;
    g_peb = g_main_teb = g_rupp = g_ldr = 0;
    g_image = NULL;
    t_teb = 0;
    tw_rt_mem_reset();
}

void tw_rt_set_last_error(uint32_t code)
{
    uint64_t teb = t_teb ? t_teb : g_main_teb;
    if (teb) wr32(teb + TEB_LastErrorValue, code);
}

uint32_t tw_rt_get_last_error(void)
{
    uint64_t teb = t_teb ? t_teb : g_main_teb;
    if (!teb) return 0;
    uint32_t v;
    memcpy(&v, (const void *)(uintptr_t)(teb + TEB_LastErrorValue), 4);
    return v;
}
