# Exceptions / SEH foundation

```
 TweakKernel exception  (or host SIGSEGV/SIGILL/...)
          |
 backend exception delivery         tw_kb_exc_handler / 192-byte record
          |
 NT exception translation           rt/seh.c: record -> EXCEPTION_RECORD + CONTEXT
          |
 vectored handler chain              AddVectoredExceptionHandler handlers
          |
 unhandled-exception filter          SetUnhandledExceptionFilter
          |
 handler resumes, or process terminates
```

## What is implemented

- The backend delivers a fault on the faulting thread with a fixed
  `TweakExceptionRecord` (the host backend synthesises the same record from a
  `SIGSEGV`/`SIGILL`/`SIGFPE`/`SIGTRAP`/`SIGBUS` on an alternate stack).
- `rt/seh.c` translates it into a Windows `EXCEPTION_RECORD` + full 1232-byte
  `CONTEXT` (integer + control registers populated; `ContextFlags` says so),
  wraps them in `EXCEPTION_POINTERS`, and runs the guest's **vectored
  exception handlers**, then the **unhandled-exception filter**.
- A handler may return `EXCEPTION_CONTINUE_EXECUTION` to resume, optionally
  after editing the `CONTEXT` (TweakWin copies the integer+control registers
  back and the backend resumes there), or `EXCEPTION_CONTINUE_SEARCH` to pass
  to the next handler.
- Access violations carry `ExceptionInformation[0]` (0 read / 1 write / 8
  execute, from the page-fault error code) and `[1]` (fault address).
- Vector → code mapping (`rt/seh.c`): `#PF`→ACCESS_VIOLATION,
  `#UD`→ILLEGAL_INSTRUCTION, `#DE`→INT_DIVIDE_BY_ZERO,
  `#GP`→PRIV_INSTRUCTION, `#BP`→BREAKPOINT, `#DB`→SINGLE_STEP, FP vectors to
  the FLT_* codes. On TweakKernel M4 a ring-3 `int3` surfaces as
  `#GP(error 0x1A)`; that exact case is mapped to `EXCEPTION_BREAKPOINT`.
- A recursive fault during dispatch, or a fault with no handler, terminates
  the process cleanly (the backend's in-exception guard + the dispatcher's
  terminate path).

## What is NOT implemented (and is not faked)

- **Frame-based SEH**: `__try`/`__except`/`__finally`, language-specific
  handlers, `RtlDispatchException` table walking over `.pdata`/`.xdata`, and
  `RtlUnwind`/`RtlVirtualUnwind`. A guest that relies on table-based
  unwinding (most C++ exception machinery, `/EHsc`) is not supported yet.
  The PE's `.pdata` is parsed and validated by the loader but not executed.
- `RaiseException`, `AddVectoredContinueHandler`, and the full `CONTEXT`
  xstate (XMM/AVX) — see `KERNEL-REQUIREMENTS.md` (XSAVE).

## Demonstrated

`exc-m3.exe` (clang + lld-link, no CRT) installs a vectored handler,
dereferences a null pointer, and the handler steps `CONTEXT.Rip` past the
faulting instruction and sets `CONTEXT.Rax`, returning
`EXCEPTION_CONTINUE_EXECUTION`; the program then observes the supplied value
and exits 0. Verified on the host (including ASan + UBSan). The underlying
backend delivery/resume is verified on real TweakKernel M4 under QEMU by the
`exceptions` section of `tests/backend/kb_conformance.c` (#UD, #PF, #DE, and
the int3 case), which resumes from each.
