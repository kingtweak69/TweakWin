# NT layer

The NT layer (`nt/`) sits between the Win32 DLLs and the backend. It returns
`NTSTATUS` and operates on backend handles; Win32 wrappers translate
`NTSTATUS` to `LastError`. The three error domains never mix.

## Error domains

```
 backend  TW_KB_E*   --tw_nt_from_kb(err, ctx)-->  NTSTATUS
 NTSTATUS            --tw_nt_to_win32(status)-->    Win32 LastError
```

- `nt/ntstatus.h` — the `STATUS_*` values TweakWin produces.
- `nt/status.c` — the only conversions. `tw_nt_from_kb` takes a context
  (`HANDLE`/`VM`/`CREATE`/`FILE`/`GENERIC`) so a generic backend error maps
  to the right status (e.g. `TW_KB_EFAULT` is `STATUS_ACCESS_VIOLATION` for a
  handle op but `STATUS_MEMORY_NOT_ALLOCATED` for a VM op). `tw_nt_to_win32`
  follows the documented `RtlNtStatusToDosError` correspondences; an unknown
  status maps to 317 (`ERROR_MR_MID_NOT_FOUND`).

Nothing converts a Win32 code back into an `NTSTATUS`.

## NT synchronization (`nt/sync.c`)

| function | status | notes |
|---|---|---|
| `tw_nt_create_event` | IMPLEMENTED | manual/auto, initial state |
| `tw_nt_set_event` / `tw_nt_reset_event` | IMPLEMENTED | return previous state |
| `tw_nt_create_semaphore` | IMPLEMENTED | initial/maximum |
| `tw_nt_release_semaphore` | IMPLEMENTED | `STATUS_SEMAPHORE_LIMIT_EXCEEDED` on overflow |
| `tw_nt_wait_single` | IMPLEMENTED | ms timeout, `STATUS_TIMEOUT` |
| `tw_nt_wait_multiple` (any) | IMPLEMENTED | first-signaled index |
| `tw_nt_wait_multiple` (all) | UNSUPPORTED | `STATUS_NOT_IMPLEMENTED` — needs M5 WAIT_ALL |

## ntdll namespace

`ntdll.dll` is a registered module namespace. The M3 runtime does not yet
export `Nt*`/`Rtl*` stubs by name to guests; the NT layer is consumed by
kernel32 internally. A guest importing an unimplemented `ntdll` symbol fails
at load with "unresolved symbol" rather than binding a stub that returns
success. Named `Nt*` exports are a later milestone.
