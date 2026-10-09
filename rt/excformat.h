#ifndef TWEAKWIN_EXCFORMAT_H
#define TWEAKWIN_EXCFORMAT_H

/*
 * x86-64 Windows exception structures, from the published winnt.h layout.
 * TweakWin builds these from the backend's fault record and hands them to
 * guest vectored handlers. CONTEXT is the full 1232-byte x64 record so a
 * handler that indexes known offsets (Rip/Rsp/Rax/...) reads valid memory;
 * only the integer+control subset is populated (ContextFlags says so).
 */

#include <stdint.h>

/* EXCEPTION_RECORD (x64) */
#define ER_ExceptionCode        0x00
#define ER_ExceptionFlags       0x04
#define ER_ExceptionRecord      0x08
#define ER_ExceptionAddress     0x10
#define ER_NumberParameters     0x18
#define ER_ExceptionInformation 0x20 /* 15 * 8 */
#define ER_SIZE                 0x98

/* EXCEPTION_POINTERS */
#define EP_ExceptionRecord 0x00
#define EP_ContextRecord   0x08
#define EP_SIZE            0x10

/* CONTEXT (x64) */
#define CTX_ContextFlags 0x30
#define CTX_MxCsr        0x34
#define CTX_SegCs        0x38
#define CTX_SegSs        0x42
#define CTX_EFlags       0x44
#define CTX_Rax          0x78
#define CTX_Rcx          0x80
#define CTX_Rdx          0x88
#define CTX_Rbx          0x90
#define CTX_Rsp          0x98
#define CTX_Rbp          0xA0
#define CTX_Rsi          0xA8
#define CTX_Rdi          0xB0
#define CTX_R8           0xB8
#define CTX_R9           0xC0
#define CTX_R10          0xC8
#define CTX_R11          0xD0
#define CTX_R12          0xD8
#define CTX_R13          0xE0
#define CTX_R14          0xE8
#define CTX_R15          0xF0
#define CTX_Rip          0xF8
#define CTX_SIZE         0x4D0

#define CONTEXT_AMD64   0x00100000u
#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x1u)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x2u)
#define CONTEXT_FULL    (CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_AMD64 | 0x4u))

/* Exception disposition / VEH return values. */
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define EXCEPTION_CONTINUE_SEARCH    (0)
#define EXCEPTION_EXECUTE_HANDLER    (1)

/* Exception codes (== NTSTATUS values). */
#define EXC_ACCESS_VIOLATION    0xC0000005u
#define EXC_IN_PAGE_ERROR       0xC0000006u
#define EXC_ILLEGAL_INSTRUCTION 0xC000001Du
#define EXC_PRIV_INSTRUCTION    0xC0000096u
#define EXC_INT_DIVIDE_BY_ZERO  0xC0000094u
#define EXC_INT_OVERFLOW        0xC0000095u
#define EXC_ARRAY_BOUNDS        0xC000008Cu
#define EXC_BREAKPOINT          0x80000003u
#define EXC_SINGLE_STEP         0x80000004u
#define EXC_FLT_DIVIDE_BY_ZERO  0xC000008Eu
#define EXC_FLT_INVALID_OP      0xC0000090u
#define EXC_FLT_OVERFLOW        0xC0000091u
#define EXC_FLT_UNDERFLOW       0xC0000093u
#define EXC_FLT_STACK_CHECK     0xC0000092u
#define EXC_FLT_DENORMAL        0xC000008Du
#define EXC_FLT_INEXACT         0xC000008Fu

#endif
