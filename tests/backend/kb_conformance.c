/*
 * Backend conformance suite. Written only against backend/kb.h and without
 * the C library, so the same file runs on the Linux host backend
 * (tests/backend/kb_host_main.c) and inside TweakKernel M4 under QEMU
 * (tests/m4/). It pins the M4 contract the NT layer relies on.
 */
#include "../../backend/kb.h"

int kb_conformance_run(void);

static int g_pass, g_fail;

static uint64_t slen(const char *s)
{
    uint64_t n = 0;
    while (s[n]) n++;
    return n;
}

static void say(const char *s) { tw_kb_debug_write(s, (size_t)slen(s)); }

static void say_num(const char *label, int64_t v)
{
    char buf[96];
    uint64_t n = 0;
    while (label[n] && n < 60) {
        buf[n] = label[n];
        n++;
    }
    uint64_t u = v < 0 ? (uint64_t)-v : (uint64_t)v;
    char tmp[24];
    int k = 0;
    do {
        tmp[k++] = (char)('0' + u % 10);
        u /= 10;
    } while (u && k < 22);
    if (v < 0) buf[n++] = '-';
    while (k) buf[n++] = tmp[--k];
    buf[n++] = '\n';
    tw_kb_debug_write(buf, (size_t)n);
}

#define CHECK(c)                                   \
    do {                                           \
        if (c) g_pass++;                           \
        else {                                     \
            g_fail++;                              \
            say_num("kb: FAIL line ", __LINE__);   \
        }                                          \
    } while (0)

#define MS 1000000ull

/* ---- thread scaffolding ---- */

__attribute__((noreturn, used)) static void thread_return(int64_t rax)
{
    tw_kb_thread_exit((int32_t)rax);
}

/* A returning thread entry lands here with the entry's RAX. */
__attribute__((naked, used)) static void thread_return_thunk(void)
{
    __asm__ volatile("movq %rax, %rdi\n\t"
                     "andq $-16, %rsp\n\t"
                     "call thread_return\n\t"
                     "ud2\n\t");
}

static uint64_t new_stack(uint64_t size, uint64_t *base)
{
    int64_t b = tw_kb_vm_reserve(0, size, TW_KB_PROT_RW, TW_KB_VM_COMMIT);
    if (b <= 0) return 0;
    uint64_t top = (uint64_t)b + size - 64 - 8; /* entry sees RSP = 8 mod 16, as after CALL */
    void (*ret)(void) = thread_return_thunk;
    uint64_t rv;
    __builtin_memcpy(&rv, &ret, 8);
    *(uint64_t *)(uintptr_t)top = rv;
    if (base) *base = (uint64_t)b;
    return top;
}

static tw_kh spawn(int64_t (*fn)(int64_t), int64_t arg, uint64_t gs, uint64_t *stack_base)
{
    uint64_t sp = new_stack(64 * 1024, stack_base);
    if (!sp) return TW_KB_ENOMEM;
    uint64_t e;
    __builtin_memcpy(&e, &fn, 8);
    return tw_kb_thread_create(e, sp, (uint64_t)arg, gs);
}

static int64_t join(tw_kh h, uint64_t stack_base)
{
    tw_kb_exitinfo info;
    int64_t w = tw_kb_wait_one(h, 5000 * MS);
    if (w != 0) return -1000 + w;
    if (tw_kb_exit_info(h, &info) != 0 || info.size != 32) return -2000;
    tw_kb_close(h);
    if (stack_base) tw_kb_vm_release(stack_base);
    return info.status;
}

/* ---- tests ---- */

static void t_info(void)
{
    CHECK(tw_kb_init() == TW_KB_OK);
    const tw_kb_info_t *i = tw_kb_info();
    CHECK(i != 0);
    if (!i) return;
    CHECK(i->abi_version == 2);
    CHECK((i->caps & TW_KB_CAPS_M4) == TW_KB_CAPS_M4);
    /* M4 baseline: no M5 capability may be claimed. */
    CHECK((i->caps & TW_KB_CAPS_M5) == 0);
    CHECK(i->max_handles >= 16 && i->max_threads >= 16 && i->max_wait >= 8);
    CHECK(i->max_commit >= (16ull << 20));
    CHECK(tw_kb_process_id() != 0);
    CHECK(tw_kb_thread_id() != 0);
    say("kb: info\n");
}

static void t_events(void)
{
    tw_kh a = tw_kb_event_create(0);
    CHECK(a > 0);
    CHECK(tw_kb_wait_one(a, 0) == TW_KB_WAIT_TIMEOUT);
    CHECK(tw_kb_event_set(a) == 0);
    CHECK(tw_kb_event_set(a) == 1);
    CHECK(tw_kb_wait_one(a, 0) == 0);
    CHECK(tw_kb_wait_one(a, 0) == TW_KB_WAIT_TIMEOUT); /* auto-reset consumed */
    tw_kh m = tw_kb_event_create(TW_KB_EVENT_MANUAL | TW_KB_EVENT_SIGNALED);
    CHECK(m > 0);
    CHECK(tw_kb_wait_one(m, 0) == 0);
    CHECK(tw_kb_wait_one(m, 0) == 0); /* manual stays signaled */
    CHECK(tw_kb_event_reset(m) == 1);
    CHECK(tw_kb_wait_one(m, 0) == TW_KB_WAIT_TIMEOUT);
    uint64_t t0 = tw_kb_time_ns();
    CHECK(tw_kb_wait_one(m, 30 * MS) == TW_KB_WAIT_TIMEOUT);
    CHECK(tw_kb_time_ns() - t0 >= 20 * MS);
    CHECK(tw_kb_event_create(4) == TW_KB_EINVAL);
    tw_kh hs[2] = { a, m };
    CHECK(tw_kb_event_set(m) == 0);
    CHECK(tw_kb_wait_any(hs, 2, 0) == 1);
    CHECK(tw_kb_event_set(a) == 0);
    CHECK(tw_kb_wait_any(hs, 2, 0) == 0); /* both signaled: first in order wins */
    CHECK(tw_kb_wait_any(hs, 0, 0) == TW_KB_EINVAL);
    CHECK(tw_kb_close(a) == 0);
    CHECK(tw_kb_close(m) == 0);
    say("kb: events\n");
}

static void t_semaphores(void)
{
    tw_kh s = tw_kb_sem_create(1, 2);
    CHECK(s > 0);
    CHECK(tw_kb_wait_one(s, 0) == 0);
    CHECK(tw_kb_wait_one(s, 0) == TW_KB_WAIT_TIMEOUT);
    CHECK(tw_kb_sem_release(s, 1) == 0);
    CHECK(tw_kb_sem_release(s, 2) == TW_KB_ESTATE); /* 1 + 2 > max */
    CHECK(tw_kb_sem_release(s, 1) == 1);
    CHECK(tw_kb_wait_one(s, 0) == 0);
    CHECK(tw_kb_wait_one(s, 0) == 0);
    CHECK(tw_kb_wait_one(s, 0) == TW_KB_WAIT_TIMEOUT);
    CHECK(tw_kb_sem_create(3, 2) < 0);
    CHECK(tw_kb_sem_create(0, 0) < 0);
    CHECK(tw_kb_close(s) == 0);
    say("kb: semaphores\n");
}

static void t_handles(void)
{
    tw_kh e = tw_kb_event_create(0);
    CHECK(e > 0);
    int64_t info = tw_kb_handle_info(e);
    CHECK(info > 0 && (info >> 32) == TW_KB_TYPE_EVENT);
    CHECK((info & 0xffffffff) == (TW_KB_RIGHT_WAIT | TW_KB_RIGHT_SIGNAL | TW_KB_RIGHT_QUERY));
    tw_kh w = tw_kb_dup(e, TW_KB_RIGHT_WAIT, 0);
    CHECK(w > 0 && w != e);
    CHECK(tw_kb_event_set(w) == TW_KB_EPERM); /* narrowed: no SIGNAL */
    CHECK(tw_kb_dup(w, TW_KB_RIGHT_WAIT | TW_KB_RIGHT_SIGNAL, 0) == TW_KB_EPERM); /* no amplification */
    CHECK(tw_kb_dup(e, 0, 0) == TW_KB_EPERM);
    CHECK(tw_kb_event_set(e) == 0);
    CHECK(tw_kb_wait_one(w, 0) == 0); /* same object */
    CHECK(tw_kb_close(e) == 0);
    CHECK(tw_kb_close(e) == TW_KB_EBADH);       /* stale */
    CHECK(tw_kb_event_set(e) == TW_KB_EBADH);
    CHECK(tw_kb_wait_one(w, 0) == TW_KB_WAIT_TIMEOUT); /* still alive via dup */
    CHECK(tw_kb_close(w) == 0);
    CHECK(tw_kb_close(0) == TW_KB_EBADH);
    CHECK(tw_kb_close(-5) == TW_KB_EBADH);
    tw_kh sem = tw_kb_sem_create(0, 1);
    CHECK(tw_kb_event_set(sem) == TW_KB_EBADH); /* wrong type */
    tw_kb_close(sem);

    /* Exhaust the table: the limit is reported, not guessed. */
    tw_kh hs[600];
    int n = 0;
    int64_t last = 0;
    while (n < 600) {
        last = tw_kb_event_create(0);
        if (last < 0) break;
        hs[n++] = last;
    }
    const tw_kb_info_t *i = tw_kb_info();
    if (i->max_handles <= 512) {
        CHECK(last == TW_KB_ENOMEM);
        CHECK(n <= (int)i->max_handles);
    }
    while (n) tw_kb_close(hs[--n]);
    say("kb: handles\n");
}

/* ---- threads ---- */

static volatile int64_t g_shared;

static int64_t th_basic(int64_t arg)
{
    g_shared = arg * 2;
    return arg + 1;
}

static int64_t th_gs(int64_t arg)
{
    return tw_kb_tls_get(TW_KB_TLS_GS) == (uint64_t)arg ? 1 : 0;
}

static int64_t th_exit(int64_t arg)
{
    tw_kb_thread_exit((int32_t)arg);
}

static tw_kh g_auto;
static volatile int g_woke;

static int64_t th_waiter(int64_t arg)
{
    (void)arg;
    if (tw_kb_wait_one(g_auto, 400 * MS) == 0) {
        __atomic_add_fetch(&g_woke, 1, __ATOMIC_SEQ_CST);
        return 1;
    }
    return 0;
}

static void t_threads(void)
{
    uint64_t sb = 0;
    tw_kh t = spawn(th_basic, 20, 0, &sb);
    CHECK(t > 0);
    CHECK(join(t, sb) == 21);
    CHECK(g_shared == 40);

    t = spawn(th_exit, -7, 0, &sb);
    CHECK(t > 0);
    CHECK(join(t, sb) == -7); /* 32-bit status, sign-extended */

    int64_t gsb = tw_kb_vm_reserve(0, 4096, TW_KB_PROT_RW, TW_KB_VM_COMMIT);
    CHECK(gsb > 0);
    t = spawn(th_gs, gsb, (uint64_t)gsb, &sb);
    CHECK(t > 0);
    CHECK(join(t, sb) == 1);

    /* Thread handle: waitable and still valid after exit. */
    t = spawn(th_basic, 1, 0, &sb);
    CHECK(tw_kb_wait_one(t, 5000 * MS) == 0);
    CHECK(tw_kb_wait_one(t, 0) == 0);
    tw_kb_exitinfo ei;
    CHECK(tw_kb_exit_info(t, &ei) == 0 && ei.reason == TW_KB_EXIT_NORMAL && ei.status == 2 && ei.id != 0);
    CHECK(tw_kb_close(t) == 0);
    tw_kb_vm_release(sb);

    /* Auto-reset consumed by exactly one waiter. */
    g_auto = tw_kb_event_create(0);
    g_woke = 0;
    uint64_t s1 = 0, s2 = 0;
    tw_kh a = spawn(th_waiter, 0, 0, &s1);
    tw_kh b = spawn(th_waiter, 0, 0, &s2);
    tw_kb_sleep_ns(60 * MS);
    CHECK(tw_kb_event_set(g_auto) == 0);
    int64_t ra = join(a, s1), rb = join(b, s2);
    CHECK(ra + rb == 1);
    CHECK(g_woke == 1);
    tw_kb_close(g_auto);

    CHECK(tw_kb_thread_create(0, 0x100000, 0, 0) < 0);
    tw_kb_vm_release((uint64_t)gsb);
    say("kb: threads\n");
}

/* ---- virtual memory ---- */

static void t_vm(void)
{
    const uint64_t P = 4096;
    int64_t b = tw_kb_vm_reserve(0, 16 * P, TW_KB_PROT_RW, 0);
    CHECK(b > 0 && (b & (P - 1)) == 0);
    tw_kb_vminfo vi;
    CHECK(tw_kb_vm_query((uint64_t)b, &vi) == 0);
    CHECK(vi.state == TW_KB_VM_RESERVED && vi.region_base == (uint64_t)b && vi.region_size == 16 * P);
    CHECK(vi.type == TW_KB_VMT_PRIVATE);
    CHECK(tw_kb_vm_protect((uint64_t)b, P, TW_KB_PROT_R) == TW_KB_EFAULT); /* not committed */
    CHECK(tw_kb_vm_commit((uint64_t)b + 4 * P, 2 * P, TW_KB_PROT_RW) == 0);
    volatile uint8_t *p = (volatile uint8_t *)(uintptr_t)(b + 4 * P);
    p[0] = 0x5A;
    p[P + 7] = 0xA5;
    CHECK(tw_kb_vm_query((uint64_t)b + 4 * P, &vi) == 0);
    CHECK(vi.state == TW_KB_VM_COMMITTED && vi.prot == TW_KB_PROT_RW && vi.size == 2 * P);
    CHECK(tw_kb_vm_commit((uint64_t)b + 4 * P, P, TW_KB_PROT_R) == 0); /* recommit keeps */
    CHECK(p[0] == 0x5A);
    CHECK(tw_kb_vm_protect((uint64_t)b + 4 * P, 2 * P, TW_KB_PROT_R) == TW_KB_PROT_RW);
    CHECK(tw_kb_vm_query((uint64_t)b + 5 * P, &vi) == 0 && vi.prot == TW_KB_PROT_R);
    CHECK(tw_kb_vm_protect((uint64_t)b + 4 * P, P, 7) == TW_KB_EINVAL);      /* W+X */
    CHECK(tw_kb_vm_protect((uint64_t)b + 4 * P, P, 6) == TW_KB_EINVAL);
    CHECK(tw_kb_vm_protect((uint64_t)b + 4 * P, P, 4) == TW_KB_PROT_R);      /* X reported RX */
    CHECK(tw_kb_vm_query((uint64_t)b + 4 * P, &vi) == 0 && vi.prot == TW_KB_PROT_RX);
    CHECK(tw_kb_vm_protect((uint64_t)b + 4 * P, 2 * P, TW_KB_PROT_RW) == TW_KB_PROT_RX);
    CHECK(tw_kb_vm_decommit((uint64_t)b + 4 * P, P) == 0);
    CHECK(tw_kb_vm_query((uint64_t)b + 4 * P, &vi) == 0 && vi.state == TW_KB_VM_RESERVED);
    CHECK(tw_kb_vm_commit((uint64_t)b + 4 * P, P, TW_KB_PROT_RW) == 0);
    CHECK(p[0] == 0);          /* decommit discards */
    CHECK(p[P + 7] == 0xA5);   /* neighbour kept */
    CHECK(tw_kb_vm_reserve((uint64_t)b + P, P, TW_KB_PROT_RW, 0) == TW_KB_ESTATE); /* overlap */
    CHECK(tw_kb_vm_commit((uint64_t)b + 15 * P, 2 * P, TW_KB_PROT_RW) == TW_KB_EFAULT); /* crosses end */
    CHECK(tw_kb_vm_commit((uint64_t)b + 1, P, TW_KB_PROT_RW) == TW_KB_EINVAL);
    CHECK(tw_kb_vm_reserve(0, 0, TW_KB_PROT_RW, 0) == TW_KB_EINVAL);
    CHECK(tw_kb_vm_reserve(0, P, 7, 0) == TW_KB_EINVAL);
    CHECK(tw_kb_vm_release((uint64_t)b + P) == TW_KB_EFAULT);
    CHECK(tw_kb_vm_release((uint64_t)b) == 0);
    CHECK(tw_kb_vm_release((uint64_t)b) == TW_KB_EFAULT);
    CHECK(tw_kb_vm_query((uint64_t)b, &vi) == 0 && vi.state == TW_KB_VM_FREE);
    /* Fixed placement at a known-free address. */
    int64_t f = tw_kb_vm_reserve((uint64_t)b, 4 * P, TW_KB_PROT_RW, TW_KB_VM_COMMIT);
    CHECK(f == b);
    if (f > 0) CHECK(tw_kb_vm_release((uint64_t)f) == 0);
    say("kb: vm\n");
}

static void t_sections(void)
{
    const uint64_t P = 4096;
    tw_kh s = tw_kb_section_create(4 * P);
    CHECK(s > 0);
    int64_t rw = tw_kb_section_map(s, 0, TW_KB_PROT_RW, 0, 0);
    CHECK(rw > 0);
    int64_t ro = tw_kb_section_map(s, 0, TW_KB_PROT_R, P, P);
    CHECK(ro > 0 && ro != rw);
    ((volatile uint8_t *)(uintptr_t)rw)[P + 3] = 0x77;
    CHECK(((volatile uint8_t *)(uintptr_t)ro)[3] == 0x77);
    CHECK(tw_kb_section_map(s, 0, TW_KB_PROT_RX, 0, 0) == TW_KB_ESTATE); /* W^X across views */
    tw_kb_vminfo vi;
    CHECK(tw_kb_vm_query((uint64_t)rw, &vi) == 0 && vi.type == TW_KB_VMT_SECTION && vi.prot == TW_KB_PROT_RW);
    CHECK(tw_kb_vm_protect((uint64_t)rw, P, TW_KB_PROT_R) == TW_KB_EINVAL);
    CHECK(tw_kb_vm_release((uint64_t)rw) == TW_KB_EINVAL);
    CHECK(tw_kb_section_unmap((uint64_t)rw) == 0);
    CHECK(tw_kb_section_unmap((uint64_t)rw) == TW_KB_EFAULT);
    int64_t rx = tw_kb_section_map(s, 0, TW_KB_PROT_RX, 0, 0);
    CHECK(rx > 0);
    CHECK(tw_kb_section_map(s, 0, TW_KB_PROT_RW, 0, 0) == TW_KB_ESTATE);
    CHECK(tw_kb_section_map(s, 0, TW_KB_PROT_R, 4 * P, 0) == TW_KB_EINVAL); /* offset past end */
    CHECK(tw_kb_section_map(s, 0, 0, 0, 0) == TW_KB_EINVAL);
    tw_kh rd = tw_kb_dup(s, TW_KB_RIGHT_READ, 0);
    CHECK(rd > 0);
    CHECK(tw_kb_section_map(rd, 0, TW_KB_PROT_RW, 0, 0) == TW_KB_EPERM);
    CHECK(tw_kb_close(rd) == 0);
    CHECK(tw_kb_close(s) == 0);
    /* Views keep the section alive after its handles close. */
    CHECK(((volatile uint8_t *)(uintptr_t)rx)[P + 3] == 0x77);
    CHECK(tw_kb_section_unmap((uint64_t)rx) == 0);
    CHECK(tw_kb_section_unmap((uint64_t)ro) == 0);
    CHECK(tw_kb_section_create(0) == TW_KB_EINVAL);
    say("kb: sections\n");
}

/* ---- exceptions ---- */

static volatile uint64_t g_vec, g_addr, g_count;

__attribute__((used)) static void exc_handler(tw_kb_excrec *r)
{
    g_vec = r->vector;
    g_addr = r->fault_address;
    g_count++;
    if (r->size != TW_KB_EXC_RECORD_SIZE || r->version != 1) tw_kb_exc_return(r, TW_KB_EXC_TERMINATE);
    if (r->vector == TW_KB_VEC_UD) r->rip += 2;           /* ud2 */
    else if (r->vector == TW_KB_VEC_PF) { r->rip += 3; r->rax = 7; }   /* mov rax,[rdi] */
    else if (r->vector == TW_KB_VEC_DE) { r->rip += 2; r->rax = 9; }   /* div esi */
    else if (r->vector == TW_KB_VEC_BP) { r->rax = 3; }   /* int3: RIP already past it */
    else if (r->vector == TW_KB_VEC_GP && r->error_code == 0x1A &&
             *(const volatile uint8_t *)(uintptr_t)r->rip == 0xCC) {
        /* TweakKernel M4: IDT gate 3 is DPL 0, so a ring-3 int3 raises
         * #GP(IDT vector 3) with RIP *at* the int3. */
        r->rip += 1;
        r->rax = 3;
    }
    tw_kb_exc_return(r, TW_KB_EXC_CONTINUE);
    tw_kb_exc_return(r, TW_KB_EXC_TERMINATE);
}

/* Code that faults, placed in VM so it is "guest code". */
static const uint8_t k_code[] = {
    /* 0: ud2; mov eax, 42; ret */
    0x0f, 0x0b, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
    /* 8: mov rax, [rdi]; ret */
    0x48, 0x8b, 0x07, 0xc3,
    /* 12: xor edx, edx; xor esi, esi; mov eax, 1; div esi; ret */
    0x31, 0xd2, 0x31, 0xf6, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xf7, 0xf6, 0xc3,
    /* 24: int3; ret */
    0xcc, 0xc3,
};

static int64_t th_exc(int64_t code)
{
    typedef int64_t (*fn_t)(uint64_t);
    fn_t f0, f8, f12, f24;
    uint64_t a0 = (uint64_t)code, a8 = a0 + 8, a12 = a0 + 12, a24 = a0 + 24;
    __builtin_memcpy(&f0, &a0, 8);
    __builtin_memcpy(&f8, &a8, 8);
    __builtin_memcpy(&f12, &a12, 8);
    __builtin_memcpy(&f24, &a24, 8);
    int64_t ok = 0;
    if (f0(0) == 42 && g_vec == TW_KB_VEC_UD) ok |= 1;
    int64_t hole = tw_kb_vm_reserve(0, 4096, TW_KB_PROT_RW, 0); /* reserved, not committed */
    if (hole > 0 && f8((uint64_t)hole + 16) == 7 && g_vec == TW_KB_VEC_PF && g_addr == (uint64_t)hole + 16)
        ok |= 2;
    if (hole > 0) tw_kb_vm_release((uint64_t)hole);
    if (f12(0) == 9 && g_vec == TW_KB_VEC_DE) ok |= 4;
    if (f24(0) == 3 && (g_vec == TW_KB_VEC_BP || g_vec == TW_KB_VEC_GP)) ok |= 8;
    if (g_vec == TW_KB_VEC_GP) ok |= 16;
    return ok;
}

static void t_exceptions(void)
{
    const uint64_t P = 4096;
    int64_t code = tw_kb_vm_reserve(0, P, TW_KB_PROT_RW, TW_KB_VM_COMMIT);
    CHECK(code > 0);
    for (unsigned i = 0; i < sizeof k_code; i++) ((uint8_t *)(uintptr_t)code)[i] = k_code[i];
    CHECK(tw_kb_vm_protect((uint64_t)code, P, TW_KB_PROT_RX) == TW_KB_PROT_RW);
    void (*h)(tw_kb_excrec *) = exc_handler;
    uint64_t hv;
    __builtin_memcpy(&hv, &h, 8);
    tw_kb_exc_handler(hv);
    CHECK(tw_kb_exc_return(0, TW_KB_EXC_CONTINUE) == TW_KB_ESTATE); /* not in an exception */
    uint64_t sb = 0;
    tw_kh t = spawn(th_exc, code, 0, &sb);
    CHECK(t > 0);
    int64_t r = join(t, sb);
    CHECK((r & 1) != 0);
    CHECK((r & 2) != 0);
    CHECK((r & 4) != 0);
    CHECK((r & 8) != 0);
    CHECK(g_count == 4);
    say((r & 16) ? "kb: int3 arrives as #GP(0x1A)\n" : "kb: int3 arrives as #BP\n");
    CHECK(tw_kb_exc_handler(0) == hv);
    tw_kb_vm_release((uint64_t)code);
    say("kb: exceptions\n");
}

int kb_conformance_run(void)
{
    g_pass = g_fail = 0;
    t_info();
    t_events();
    t_semaphores();
    t_handles();
    t_threads();
    t_vm();
    t_sections();
    t_exceptions();
    say_num("kb: passed ", g_pass);
    say_num("kb: failed ", g_fail);
    return g_fail;
}
