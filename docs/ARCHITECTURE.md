# TweakWin architecture (M3 runtime)

TweakWin is a 64-bit Windows compatibility personality for TweakOS. It owns
Windows semantics; TweakKernel provides general, NT-friendly primitives.

```
 Windows PE application
          |
   Win32 compatibility DLLs      kernel32/   (and the ntdll namespace)
          |
       NTDLL layer               nt/         NTSTATUS, sync; NtXxx shapes
          |
   TweakWin runtime              rt/         PEB/TEB, TLS, threads, SEH, objects
          |
   TweakKernel backend           backend/    the ONE kernel contract
          |
   TweakKernel M4 ABI            (v0.5.0-m4, ABI 2) — or the Linux host
```

## The one rule

Windows-facing code depends on TweakWin abstractions, never on raw kernel
syscalls. Exactly one file knows TweakKernel syscall numbers:
`backend/kb_m4_abi.h`, included only by `backend/kb_tweakkernel.c`. Everything
above calls `backend/kb.h`. This is what lets TweakWin adopt TweakKernel M5
later by changing only the backend (see `KERNEL-REQUIREMENTS.md`).

## Layers

- **backend/** — `kb.h` is the kernel contract: handles with rights, waits,
  page-granular VM with W^X, sections, exceptions, threads, TLS base, plus
  host-only services (files, console, spawn) behind `TW_KB_CAP_HOST_*`. Two
  implementations: `kb_tweakkernel.c` (freestanding M4, raw SYSCALL) and
  `kb_host.c` (Linux, re-implementing the M4 object model in userspace — no
  M5 behaviour). Capability bits (`TW_KB_CAP_*`) advertise what the live
  kernel supports; all M5 caps report false today.
- **nt/** — `ntstatus.h` + `status.c` own the three error domains and the
  only conversions between them (`tw_nt_from_kb`, `tw_nt_to_win32`).
  `sync.c` is the NT synchronization layer (events, semaphores, waits),
  returning NTSTATUS over backend handles.
- **rt/** — the process/thread environment. `teb.c` builds the PEB, process
  parameters, loader data and per-thread TEB (GS base). `tls.c` is Windows
  TLS. `thread.c` is the Windows thread model. `object.c` bridges Win32
  HANDLEs to backend handles. `seh.c` is the exception-dispatch foundation.
  `mem.c` is the thread-safe guest allocator over the backend VM.
- **kernel32/** — Win32 exports built on nt/ and rt/, translating NTSTATUS
  to LastError. `loader/` + the legacy `runtime/` keep the M1/M2 console path
  working unchanged.

## Memory model

Runtime-owned guest memory (TEB, PEB, process parameters, TLS blocks, thread
stacks) is allocated through the backend VM (`rt_galloc`), so it is
page-protected, thread-safe, W^X, and validated by `tw_rt_guest_check` on
both backends. The legacy loader still maps the main image and its primary
stack with host `mmap`; the host backend is told those ranges
(`tw_kb_fault_region_add`) so its exception path recognises faults in image
code and accepts the image stack for the exception record. On TweakKernel M4
the image lives in the kernel's own VM, so that registration is a no-op.

## What runs where

The host backend is what `tweakwin run` uses on TweakOS 0.3 (a Linux host).
The M4 backend is exercised by `tests/m4/run-m4.sh`, which boots a scratch
copy of TweakKernel v0.5.0-m4 under QEMU with the backend conformance suite
as its only user program and requires the `TWEAKWIN_M4_KB_OK` marker. The
same `tests/backend/kb_conformance.c` runs against both, so the contract the
runtime depends on is identical on both.
