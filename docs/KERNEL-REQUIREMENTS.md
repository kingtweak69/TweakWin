# TweakKernel requirements from TweakWin

TweakWin is built against the **released** TweakKernel M4
(`v0.5.0-m4`, commit `378bc5480f87e000111afc7da61fdec81a8d9110`, ABI 2). It
does not block on M5. This file tracks M5 features that would let TweakWin
drop or simplify an M4 workaround.

The backend advertises capabilities (`TW_KB_CAP_*` in `backend/kb.h`).
`backend/kb_tweakkernel.c` sets them from `ABI_INFO(2)`; every M5 capability
reports false today, and the runtime takes the M4 path whenever the
capability is absent. When M5 lands, the backend learns the new calls and
flips the bit — nothing above the backend changes.

A ✅ workaround is correct and complete on M4. A ⚠️ workaround is a correct
subset or is reported as unsupported rather than faked.

| M5 feature | TW_KB_CAP_ | Why TweakWin wants it | M4 workaround | OK? | Backend change when M5 arrives |
|---|---|---|---|---|---|
| wait-all | WAIT_ALL | `WaitForMultipleObjects(bWaitAll=TRUE)` | none that is atomic; `tw_nt_wait_multiple` returns `STATUS_NOT_IMPLEMENTED` → `ERROR_CALL_NOT_IMPLEMENTED` | ⚠️ | one `wait_all` backend call behind the cap; delete the NOT_IMPLEMENTED branch |
| mutexes | MUTEX | `CreateMutex`/`ReleaseMutex` with ownership + recursion | not implemented; a semaphore is not a mutex (no owner, no recursion) | ⚠️ | `tw_kb_mutex_*`; a real `CreateMutex` |
| APC delivery | APC | `QueueUserAPC`, alertable waits | not implemented | ⚠️ | `tw_kb_queue_apc` + alertable flag on waits |
| suspend/resume | SUSPEND_RESUME | `SuspendThread`/`ResumeThread`, `CREATE_SUSPENDED` | return `ERROR_CALL_NOT_IMPLEMENTED`; `CreateThread` rejects `CREATE_SUSPENDED` | ⚠️ | `tw_kb_thread_suspend/resume`; honour the flag |
| get/set context | THREAD_CONTEXT | `GetThreadContext`/`SetThreadContext` of another thread | return `ERROR_CALL_NOT_IMPLEMENTED` | ⚠️ | `tw_kb_thread_get/set_context`; fill a CONTEXT |
| growable handles | GROWABLE_HANDLES | more than 16 live kernel objects per process | M4 caps the handle table at 16; the host backend allows more, so a guest that needs many handles runs on the host but is capped on M4 | ⚠️ | raise/remove the per-process cap in `tw_kb_info` |
| named objects | NAMED_OBJECTS | named events/semaphores/sections, `OpenEvent` | named create is rejected (`ERROR_NOT_SUPPORTED`) | ⚠️ | a namespace keyed by name in the kernel; pass the name through |
| image sections | IMAGE_SECTIONS | map a PE as an image section (shared, COW, relocated once) | the loader maps the main image by hand via VM/`mmap`; DLLs are an internal registry | ⚠️ | `tw_kb_section_create_image`; map views for the loader |
| async file I/O | ASYNC_IO | overlapped `ReadFile`/`WriteFile`, `GetOverlappedResult` | overlapped is rejected; only synchronous host files | ⚠️ | `tw_kb_file_*` async variants + a completion signal |
| completion queues | COMPLETION_QUEUE | `CreateIoCompletionPort`, `GetQueuedCompletionStatus` | not implemented | ⚠️ | a completion object type + its waits |
| XSAVE/AVX | XSAVE | AVX in guests; full `CONTEXT` xstate | M4 gives x87+SSE per thread; AVX faults `#UD`; the translated CONTEXT carries integer+control only | ⚠️ | wider context save; set the cap so AVX executes |

## Things M4 already gives TweakWin

First-class processes and threads; per-thread FS/GS; x87/SSE context
isolation; generic handles with rights narrowing and cross-process
duplication; wait-one and wait-any; events; semaphores; shared sections with
object-level W^X; VM reserve/commit/decommit/release with page-granular
protection and W^X; exception delivery with a resumable record;
process/thread waitability; hardened ring-3 entry/exit. These are consumed
directly, not worked around.

## Notes for the M5 developer

- A ring-3 `int3` currently arrives as `#GP` with error code `0x1A`, not
  `#BP`. TweakWin's SEH maps that case to `EXCEPTION_BREAKPOINT`, but a real
  `#BP` delivery would be cleaner for debuggers. (`backend/kb_tweakkernel.c`
  and `rt/seh.c` both have the workaround; `tests/backend/kb_conformance.c`
  documents the observed behaviour.)
- `WAIT_ALL` and `CREATE_SUSPENDED` are the two most visible gaps for real
  console programs; they are the highest-value M5 additions for TweakWin.
