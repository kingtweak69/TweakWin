# kernel32 surface

TweakWin's `kernel32.dll` is a TweakWin-owned module. Ordinals are
TweakWin's, not any Windows build's. Ordinals 1–3 are frozen
(`GetStdHandle`, `WriteFile`, `ExitProcess`); 4–41 are the M2 console
surface (see `RUNTIME.md`); 42–68 are the M3 runtime surface below. kernel32
is built on the NT layer and the rt runtime, not directly on the backend.

An unimplemented import fails at load ("unresolved symbol"); no export is a
stub that returns success.

## M3 additions (ordinals 42–68)

| ordinal | export | status | notes |
|---|---|---|---|
| 42–43 | CreateEventA / CreateEventW | IMPLEMENTED | unnamed only; named → `ERROR_NOT_SUPPORTED` (M5) |
| 44 | SetEvent | IMPLEMENTED | |
| 45 | ResetEvent | IMPLEMENTED | |
| 46–47 | CreateSemaphoreA / W | IMPLEMENTED | unnamed only |
| 48 | ReleaseSemaphore | IMPLEMENTED | previous count out-param |
| 49 | WaitForSingleObject | IMPLEMENTED | events, semaphores, threads |
| 50 | WaitForMultipleObjects | PARTIAL | `bWaitAll=FALSE` works; `TRUE` → `ERROR_CALL_NOT_IMPLEMENTED` (M5 WAIT_ALL) |
| 51 | GetCurrentProcess | IMPLEMENTED | pseudo-handle -1 |
| 52 | GetCurrentThread | IMPLEMENTED | pseudo-handle -2 |
| 53 | GetCurrentProcessId | IMPLEMENTED | |
| 54 | GetCurrentThreadId | IMPLEMENTED | |
| 55 | CreateThread | IMPLEMENTED | `CREATE_SUSPENDED` → `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| 56 | ExitThread | IMPLEMENTED | |
| 57 | GetExitCodeThread | IMPLEMENTED | `STILL_ACTIVE` while running |
| 58 | SuspendThread | UNSUPPORTED | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| 59 | ResumeThread | UNSUPPORTED | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| 60 | GetThreadContext | UNSUPPORTED | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| 61 | SetThreadContext | UNSUPPORTED | `ERROR_CALL_NOT_IMPLEMENTED` (M5) |
| 62 | TlsAlloc | IMPLEMENTED | 64 TEB slots |
| 63 | TlsFree | IMPLEMENTED | |
| 64 | TlsGetValue | IMPLEMENTED | |
| 65 | TlsSetValue | IMPLEMENTED | |
| 66 | AddVectoredExceptionHandler | IMPLEMENTED | first/last ordering |
| 67 | RemoveVectoredExceptionHandler | IMPLEMENTED | |
| 68 | SetUnhandledExceptionFilter | IMPLEMENTED | returns previous filter |

`CloseHandle` (ordinal 25) now also closes kernel objects (events,
semaphores, threads) via the rt object table, in addition to files and the
heap.

## Handles

A `HANDLE` is an opaque table value. Files and the process heap live in the
legacy handle table (values `0x20000+`); kernel objects live in the rt
object table (values `0x40000+`); the three standard handles keep the M1
values `0x10`/`0x14`/`0x18`; `GetCurrentProcess`/`GetCurrentThread` are the
pseudo-handles -1/-2. None is a pointer the caller may dereference.

## LastError

Per-thread, stored in `TEB.LastErrorValue`. NT-layer failures are translated
once, at the Win32 boundary, with `tw_nt_to_win32`.
