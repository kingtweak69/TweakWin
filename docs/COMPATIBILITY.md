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
| SEH: frame-based __try/__except (unwinding) | UNSUPPORTED | `.pdata`/`.xdata` unwinding was investigated but not implemented; see `EXCEPTIONS.md` |
| SuspendThread/ResumeThread | STUB | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| Get/SetThreadContext | STUB | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| Mutexes | UNSUPPORTED | M5 |
| Named objects / Open* | UNSUPPORTED | `ERROR_NOT_SUPPORTED` (M5) |
| LoadLibraryA/W, LoadLibraryExA/W (flags 0, `LOAD_WITH_ALTERED_SEARCH_PATH`) | IMPLEMENTED | `m4-main`, `m4-dyn`, `test_m4.py` |
| LoadLibraryEx other flags | PARTIAL | known flags fail `ERROR_NOT_SUPPORTED`, unknown bits `ERROR_INVALID_PARAMETER` |
| GetProcAddress (name, ordinal) / GetModuleHandleA/W / FreeLibrary | IMPLEMENTED | `m4-main`, `m4-dyn` (GetProcAddress on the EXE's own handle is not supported) |
| DLL dependency chains, import binding across modules (name + ordinal) | IMPLEMENTED | `m4-impl`, `m4-dyn` (`m4_top`→`m4_mid`→`m4_base`) |
| Export forwarders (`DLL.Func`, `DLL.#N`), cycle + malformed detection | IMPLEMENTED | `m4-dyn` (`m4_mid`, `m4_loop_a/b`, patched malformed forwarder) |
| DLL relocation / base conflicts | IMPLEMENTED | `m4-dyn` (`m4_dupa`/`m4_dupb` share a base) |
| DllMain PROCESS_ATTACH/DETACH ordering, refcounts, rollback | IMPLEMENTED | `m4-impl`, `m4-dyn`, `test_m4.py` |
| DllMain THREAD_ATTACH/DETACH | PARTIAL | delivered for threads created via `CreateThread`; `DisableThreadLibraryCalls` is not implemented |
| DLL implicit TLS (`.tls`) | UNSUPPORTED | rejected at load (`ERROR_BAD_EXE_FORMAT`); the M3 TLS model is single-image. Dynamic TLS (`TlsAlloc`) from a DLL works (`m4-dyn`) |
| Loader lock | PARTIAL | one recursive process-wide lock serialises load/free/attach/detach; no Win32 `LdrLockLoaderLock` surface |
| Circular DLL dependencies (A↔B) | PARTIAL | load works, but the cycle's modules are only reclaimed at process exit |
| Windows namespace: `C:\`, `..`, cwd, case-insensitive match, confinement | PARTIAL | `m4-fs`, `test_m4ns`; one drive; used by LoadLibrary and the new attribute/enumeration APIs only |
| GetFileAttributesA/W, FindFirst/NextFileA/W, FindClose, Get/SetCurrentDirectoryA | PARTIAL | `m4-fs`; no `*Ex`, no info levels, no `SetCurrentDirectoryW`/`GetCurrentDirectoryW` |
| Symlink + host-escape protection | IMPLEMENTED | `m4-fs`, `test_m4ns` (symlinks refused, never followed; ambiguous case collisions refused) |
| CreateFile through the namespace | UNSUPPORTED | CreateFile keeps the M2 relative-path policy (unchanged) |
| Registry: RegOpenKeyExA/W, RegCreateKeyExA/W, RegQueryValueExA/W, RegSetValueExA/W, RegCloseKey, RegDeleteValueA/W | PARTIAL | `m4-reg`, `test_m4ns`; in-memory HKCU/HKLM only, never touches the host |
| Registry persistence, enumeration, RegDeleteKey, other predefined roots | UNSUPPORTED | imports fail at load; other roots return `ERROR_INVALID_HANDLE` |
| DLL search: exe dir, cwd, configured paths | PARTIAL | `test_m4ns`; no PATH, no system directories, no SxS/manifests, no API sets |
| CreateProcess | UNSUPPORTED | backend `process_spawn` exists; no Win32 wrapper yet |
| USER32 / GDI / COM / DirectX / .NET | UNSUPPORTED | out of scope for this milestone |

## Backend portability

Every IMPLEMENTED item above runs on the Linux host backend. The kernel
contract those items depend on (`tests/backend/kb_conformance.c`: VM,
threads, TLS base, events, semaphores, wait-one/any, sections, exceptions,
handles/rights) is additionally verified on real TweakKernel v0.5.0-m4 under
QEMU (`make m4`). Host-only services (file/console/spawn) are
capability-gated and are not claimed on M4.

The M4 (milestone) dynamic loader, namespace and registry are host-backend
features. They use only existing `kb.h` services (VM, threads, TLS) but have
**not** been executed on TweakKernel: `make m4` needs the TweakKernel tree and
QEMU, which were unavailable when this work was done, so none of the new
items is claimed on TweakKernel.
