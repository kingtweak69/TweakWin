#ifndef TWEAKWIN_KB_M4_ABI_H
#define TWEAKWIN_KB_M4_ABI_H

/*
 * TweakKernel M4 native ABI (v0.5.0-m4, commit 378bc548, ABI 2), from
 * TweakKernel docs/SYSCALLS.md. Included ONLY by kb_tweakkernel.c: no
 * other TweakWin file may know a syscall number.
 *
 * SYSCALL: rax = number, args rdi rsi rdx r10 r8 r9; rcx/r11 clobbered.
 * rax >= 0 success, negative = -TWEAK_ERR_*.
 */

#define M4_SYS_DEBUG            0
#define M4_SYS_YIELD            1
#define M4_SYS_EXIT             2
#define M4_SYS_TICKS            5
#define M4_SYS_SLEEP            6   /* ticks 0..1000 */
#define M4_SYS_ABI              14
#define M4_SYS_CLOSE            16
#define M4_SYS_THREAD_CREATE    19  /* entry, stack, arg, flags(0), fs, gs */
#define M4_SYS_THREAD_EXIT      20
#define M4_SYS_THREAD_SELF      21
#define M4_SYS_TLS_SET          22
#define M4_SYS_TLS_GET          23
#define M4_SYS_WAIT_ONE         24
#define M4_SYS_WAIT_ANY         25
#define M4_SYS_EVENT_CREATE     26
#define M4_SYS_EVENT_SET        27
#define M4_SYS_EVENT_RESET      28
#define M4_SYS_SEM_CREATE       29
#define M4_SYS_SEM_RELEASE      30
#define M4_SYS_HANDLE_DUP       31
#define M4_SYS_HANDLE_INFO      32
#define M4_SYS_EXIT_INFO        33
#define M4_SYS_PROCESS_SELF     34
#define M4_SYS_PROCESS_TERMINATE 35
#define M4_SYS_VM_RESERVE       36
#define M4_SYS_VM_COMMIT        37
#define M4_SYS_VM_DECOMMIT      38
#define M4_SYS_VM_RELEASE       39
#define M4_SYS_VM_PROTECT       40
#define M4_SYS_VM_QUERY         41
#define M4_SYS_SECTION_CREATE   42
#define M4_SYS_SECTION_MAP      43
#define M4_SYS_SECTION_UNMAP    44
#define M4_SYS_EXC_HANDLER      45
#define M4_SYS_EXC_RETURN       46
#define M4_SYS_ABI_INFO         47

#define M4_ABI_VERSION          2
#define M4_SYS_COUNT            48

#define M4_ABI_INFO_VERSION     0
#define M4_ABI_INFO_SYSCALLS    1
#define M4_ABI_INFO_FEATURES    2

#define M4_FEATURE_THREADS   (1u << 0)
#define M4_FEATURE_FPU       (1u << 1)
#define M4_FEATURE_TLS       (1u << 2)
#define M4_FEATURE_WAIT      (1u << 3)
#define M4_FEATURE_EVENT     (1u << 4)
#define M4_FEATURE_SEMAPHORE (1u << 5)
#define M4_FEATURE_DUP       (1u << 6)
#define M4_FEATURE_VM        (1u << 7)
#define M4_FEATURE_SECTION   (1u << 8)
#define M4_FEATURE_EXCEPTION (1u << 9)

#define M4_WAIT_TIMEOUT  0x102
#define M4_WAIT_INFINITE (~0ull)
#define M4_WAIT_MAX      8
#define M4_TICK_NS       10000000ull /* PIT at 100 Hz */
#define M4_SLEEP_MAX     1000

#define M4_HANDLES       16
#define M4_THREADS       16
#define M4_VM_REGIONS    64
#define M4_VM_MIN        0x10000ull
#define M4_VM_LIMIT      0x00007FFFFFFF0000ull
#define M4_COMMIT_MAX    (16ull << 20)
#define M4_RESERVE_MAX   (64ull << 30)
#define M4_SECTION_MAX   (4ull << 20)
#define M4_DEBUG_MAX     256

#endif
