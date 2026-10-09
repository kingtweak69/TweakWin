# Compatibility support table

Status vocabulary, used strictly:

- **IMPLEMENTED** — demonstrated by an actual PE workload or a direct test.
- **PARTIAL** — a correct subset works; the rest fails explicitly.
- **STUB** — present but returns a defined "not done" result
  (`ERROR_CALL_NOT_IMPLEMENTED` / `STATUS_NOT_IMPLEMENTED`).
- **UNSUPPORTED** — not present; importing it fails at load.

No "mostly supported". A capability is IMPLEMENTED only where a PE
demonstrates it (acceptance fixtures `*-m3.exe`, M1/M2 guests) or a unit
test exercises it.

## Subsystems

| area | status | evidence |
|---|---|---|
| PE32+ x86-64 parse + validation | IMPLEMENTED | `test_pe`, fuzz sweep 439k parses |
| PE32+ map, DIR64 reloc, IAT bind, W^X | IMPLEMENTED | `test_loader`, M1/M2/M3 PEs |
| Console I/O (GetStdHandle/WriteFile/ReadFile) | IMPLEMENTED | M1/M2 guests |
| Command line (A/W, Windows quoting) | IMPLEMENTED | `args-m2`, `peb-m3` |
| Environment block (A/W) | IMPLEMENTED | `env-m2` |
| VirtualAlloc/Free/Protect/Query | IMPLEMENTED | `mem-m2`, `test_runtime` |
| Process heap (HeapAlloc/Free/ReAlloc/Size) | IMPLEMENTED | `heap-m2` |
| Files (CreateFile/Read/Write, relative policy) | PARTIAL | `file-m2`; no sharing/locking, no async |
| Time (Sleep/GetTickCount/QPC) | IMPLEMENTED | `timer-m2` |
| UTF-8/16 conversion | IMPLEMENTED | `test_runtime` |
| PEB / TEB (x64, GS-based) | IMPLEMENTED | `peb-m3`, `test_rt` |
| Implicit PE TLS (per-thread blocks) | IMPLEMENTED | `thread-m3`, `tls-m3` |
| Dynamic TLS (TlsAlloc slots) | IMPLEMENTED | `tls-m3`, `test_rt` |
| TLS callbacks (process-attach) | PARTIAL | run with GS set; thread-attach/detach run; not stress-tested with real callbacks |
| Threads (Create/Exit/GetExitCode/join) | IMPLEMENTED | `thread-m3`, `tls-m3` |
| Events (auto/manual) | IMPLEMENTED | `thread-m3`, `test_seh`, backend conformance |
| Semaphores | IMPLEMENTED | `thread-m3`, backend conformance |
| WaitForSingleObject | IMPLEMENTED | `thread-m3` |
| WaitForMultipleObjects (any) | IMPLEMENTED | `test_m3`/backend conformance (wait-any) |
| WaitForMultipleObjects (all) | STUB | `ERROR_CALL_NOT_IMPLEMENTED` (M5 WAIT_ALL) |
| Per-thread LastError (TEB) | IMPLEMENTED | `test_rt` |
| SEH: vectored handlers + unhandled filter | IMPLEMENTED | `exc-m3`, `test_seh` |
| SEH: exception translation (AV/#UD/#DE/#BP/FP) | IMPLEMENTED | `exc-m3`, backend conformance |
| SEH: frame-based __try/__except (unwinding) | UNSUPPORTED | see `EXCEPTIONS.md` |
| SuspendThread/ResumeThread | STUB | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| Get/SetThreadContext | STUB | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| Mutexes | UNSUPPORTED | M5 |
| Named objects / Open* | UNSUPPORTED | `ERROR_NOT_SUPPORTED` (M5) |
| DLL loader (LoadLibrary/GetProcAddress) | UNSUPPORTED | internal module registry only |
| CreateProcess | UNSUPPORTED | backend `process_spawn` exists; no Win32 wrapper yet |
| Registry | UNSUPPORTED | next milestone |
| Windows path/VFS (drives, `..`, `C:\`) | UNSUPPORTED | M2 relative-path policy only |
| USER32 / GDI / COM / DirectX / .NET | UNSUPPORTED | out of scope for this milestone |

## Backend portability

Every IMPLEMENTED item above runs on the Linux host backend. The kernel
contract those items depend on (`tests/backend/kb_conformance.c`: VM,
threads, TLS base, events, semaphores, wait-one/any, sections, exceptions,
handles/rights) is additionally verified on real TweakKernel v0.5.0-m4 under
QEMU (`make m4`). Host-only services (file/console/spawn) are
capability-gated and are not claimed on M4.
