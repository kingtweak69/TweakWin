/*
 * Microsoft x64 ABI sanity: arguments land in RCX, RDX, R8, R9 with a
 * 32-byte shadow space, which is what a Windows guest uses to call us.
 */

#include "../../runtime/winapi.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

static int g_fail, g_pass;

#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        unsigned long long _a = (unsigned long long)(a), _b = (unsigned long long)(b); \
        if (_a == _b) g_pass++;                                                 \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s == %s (0x%llx != 0x%llx)\n", \
                                 __FILE__, __LINE__, #a, #b, _a, _b); }         \
    } while (0)

static uint64_t g_seen[5];

static TW_MS_ABI uint64_t sink(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    g_seen[0] = a;
    g_seen[1] = b;
    g_seen[2] = c;
    g_seen[3] = d;
    g_seen[4] = e;
    return a ^ b ^ c ^ d ^ e;
}

/*
 * Call `fn` the way a Windows x64 guest would. Host RSP is saved in R15
 * (non-volatile under the Microsoft ABI) for the duration of the call.
 */
__attribute__((noinline))
static uint64_t call_ms_abi(uint64_t fn, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    uint64_t ret;
    __asm__ volatile(
        "movq %%rsp, %%r15\n\t"
        "andq $-16, %%rsp\n\t"
        "subq $8, %%rsp\n\t"
        "subq $0x28, %%rsp\n\t"
        "movq %[e], 0x20(%%rsp)\n\t"
        "movq %[a], %%rcx\n\t"
        "movq %[b], %%rdx\n\t"
        "movq %[c], %%r8\n\t"
        "movq %[d], %%r9\n\t"
        "callq *%[fn]\n\t"
        "movq %%r15, %%rsp\n\t"
        : "=a"(ret)
        : [fn] "r"(fn), [a] "r"(a), [b] "r"(b), [c] "r"(c), [d] "r"(d), [e] "r"(e)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "r15", "memory", "cc"
    );
    return ret;
}

int main(void)
{
    uint64_t fnbits = 0;
    uint64_t (TW_MS_ABI *fp)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) = sink;
    memcpy(&fnbits, &fp, sizeof fp);

    uint64_t got = call_ms_abi(fnbits, 0x11, 0x22, 0x33, 0x44, 0x55);
    CHECK_EQ(g_seen[0], 0x11);
    CHECK_EQ(g_seen[1], 0x22);
    CHECK_EQ(g_seen[2], 0x33);
    CHECK_EQ(g_seen[3], 0x44);
    CHECK_EQ(g_seen[4], 0x55);
    CHECK_EQ(got, 0x11 ^ 0x22 ^ 0x33 ^ 0x44 ^ 0x55);

    uint64_t via_c = sink(1, 2, 3, 4, 5);
    CHECK_EQ(g_seen[0], 1);
    CHECK_EQ(g_seen[1], 2);
    CHECK_EQ(g_seen[2], 3);
    CHECK_EQ(g_seen[3], 4);
    CHECK_EQ(g_seen[4], 5);
    CHECK_EQ(via_c, 1 ^ 2 ^ 3 ^ 4 ^ 5);

    printf("abi: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
