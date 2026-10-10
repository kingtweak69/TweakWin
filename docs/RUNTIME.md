# M2 console runtime

The loader maps a PE and binds its imports. The runtime is everything the
guest calls after that. `loader/load.c` does not implement Win32. It only
asks `runtime/modules.c` for an address, and `tw_guest_readable` /
`tw_guest_writable` also accept ranges tracked by `runtime/vmem.c`.

One guest thread. `ExitProcess` is still how a run ends.

## What a guest can call

`kernel32.dll`, by name. Ordinals are TweakWin's, not a Windows DLL's.
Ordinals 1–3 are the M1 set and do not change.

| ord | export |
|---|---|
| 1 | GetStdHandle |
| 2 | WriteFile |
| 3 | ExitProcess |
| 4–5 | GetCommandLineA / W |
| 6–7 | GetModuleHandleA / W |
| 8–9 | GetModuleFileNameA / W |
| 10–11 | GetLastError / SetLastError |
| 12–15 | VirtualAlloc / VirtualFree / VirtualProtect / VirtualQuery |
| 16–20 | GetProcessHeap / HeapAlloc / HeapFree / HeapReAlloc / HeapSize |
| 21 | ReadFile |
| 22 | SetStdHandle |
| 23–24 | CreateFileA / W |
| 25–26 | CloseHandle / GetFileType |
| 27–34 | Get/SetEnvironmentVariable A/W, Get/FreeEnvironmentStrings A/W |
| 35–39 | Sleep, GetTickCount, GetTickCount64, QueryPerformanceCounter / Frequency |
| 40–41 | MultiByteToWideChar / WideCharToMultiByte |

`ntdll.dll` is a registered namespace with no exports. Nothing in M2 needs
one. A missing ntdll symbol is still "unresolved symbol", not "unknown DLL".

Calling anything else does not pretend to succeed. The import fails at load
time (exit 6) rather than binding a stub that returns TRUE.

## Handles

A `HANDLE` is an index into a table inside the runtime. It is not a Linux
file descriptor and not a pointer to a TweakWin object.

Stdin, stdout, and stderr keep the M1 values `0x10`, `0x14`, `0x18`. Those
are dups of the host descriptors, so `CloseHandle` on stdout does not close
the runtime's own stdout. Other handles are `0x20000 + index*256 + generation`
and are not reused with the same value until the generation wraps.

`GetFileType` reports `FILE_TYPE_DISK` for `CreateFile` results. A standard
handle is `FILE_TYPE_PIPE` or `FILE_TYPE_CHAR` depending on what the host
descriptor actually is.

## LastError

There is one last-error value, for the single guest thread. `SetLastError`
stores it. `GetLastError` returns it. Failed calls set a Win32 code from the
table below. Successful calls leave it alone, except `GetEnvironmentVariable`,
which sets 0 on success so an empty value (return 0) is not
`ERROR_ENVVAR_NOT_FOUND`.

| code | name | when |
|---|---|---|
| 2 | ERROR_FILE_NOT_FOUND | open of a missing file |
| 3 | ERROR_PATH_NOT_FOUND | missing parent, or a symlink at the final component |
| 5 | ERROR_ACCESS_DENIED | permission, directory, or a read on a write-only handle |
| 6 | ERROR_INVALID_HANDLE | closed, wrong type, or unknown |
| 8 | ERROR_NOT_ENOUGH_MEMORY | allocation cap |
| 24 | ERROR_BAD_LENGTH | `VirtualQuery` buffer shorter than 48 bytes |
| 29 / 30 | ERROR_WRITE_FAULT / ERROR_READ_FAULT | host `write` / `read` failed |
| 80 | ERROR_FILE_EXISTS | `CREATE_NEW` on an existing file |
| 87 | ERROR_INVALID_PARAMETER | bad flags, NULL where it is not allowed |
| 122 | ERROR_INSUFFICIENT_BUFFER | module path or environment buffer too small |
| 123 | ERROR_INVALID_NAME | path rejected by the M2 rules |
| 126 | ERROR_MOD_NOT_FOUND | `GetModuleHandle` miss |
| 203 | ERROR_ENVVAR_NOT_FOUND | environment miss |
| 487 | ERROR_INVALID_ADDRESS | `VirtualAlloc` with a non-NULL address |
| 998 | ERROR_NOACCESS | guest pointer failed validation |
| 1004 | ERROR_INVALID_FLAGS | conversion flags other than the error-on-invalid bit |
| 1113 | ERROR_NO_UNICODE_TRANSLATION | byte sequence is not UTF-8 |

## Guest memory

Every pointer a guest passes in is checked before it is used:

- the range must sit inside one mapped PE region or one runtime allocation
- the protection bits must allow the access (`PROT_READ`, and `PROT_WRITE` for outputs)
- a NUL-terminated ANSI string is read one byte at a time, at most 32768 bytes, and the address must not wrap
- a UTF-16 string must be 2-aligned and is read one code unit at a time, same cap

`VirtualAlloc` memory, heap blocks, the command line, and environment blocks
are tracked by the runtime. Host `malloc` memory and the host stack are not
guest memory. A guest never receives a pointer to a handle-table slot, an
environment entry, or any other TweakWin structure.

Heap and blob objects are visible only for their requested size. `VirtualAlloc`
exposes the whole committed pages, which is what `VirtualQuery.RegionSize`
reports. A guard page sits under each heap block and is not part of that size.

## Virtual memory

`VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, protect)` only.
`size` must be 1 .. 64 MiB. A non-NULL address fails with
`ERROR_INVALID_ADDRESS`. Any allocation type other than commit+reserve fails.

Accepted protection: `PAGE_NOACCESS`, `PAGE_READONLY`, `PAGE_READWRITE`,
`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`. `PAGE_EXECUTE_READWRITE` is rejected.
M2 does not create a writable and executable mapping.

`VirtualFree(addr, 0, MEM_RELEASE)` releases the whole allocation.
`MEM_DECOMMIT` is not implemented. `addr` must be the pointer `VirtualAlloc`
returned, including after `VirtualProtect` has split the region.

`VirtualProtect` changes a page-aligned range that lies entirely inside one
uniformly protected span of a single `VirtualAlloc` region. After a split,
a later call cannot cross that boundary. It does not change the PE image
or a heap block.

`VirtualQuery` writes a 48-byte x64 `MEMORY_BASIC_INFORMATION`
(`PartitionId` is 0). Tracked regions report `MEM_COMMIT`. PE image regions
report `MEM_IMAGE`. Anything else is reported as one free page
(`MEM_FREE`, `PAGE_NOACCESS`). That is an approximation: M2 does not walk the
host address space.

Caps: 256 regions, 64 MiB per allocation, 256 MiB total.

## Heap

`GetProcessHeap` returns the one process heap. `HeapAlloc` /
`HeapReAlloc` / `HeapFree` / `HeapSize` accept that handle only.
`HEAP_NO_SERIALIZE` is ignored (one thread). `HEAP_ZERO_MEMORY` zeroes new
bytes. `HEAP_GENERATE_EXCEPTIONS` is rejected. `HeapFree(NULL)` returns TRUE.
`HEAP_REALLOC_IN_PLACE_ONLY` fails instead of moving the block.
A zero-byte `HeapAlloc` returns a unique pointer whose `HeapSize` is 0.

## Command line

```
tweakwin run program.exe arg1 arg2
```

`GetCommandLineA/W` return one string for the life of the run:

- `argv[0]` has `/` rewritten to `\`. It is not canonicalized and it is not
  given a drive letter.
- later arguments are copied as the user typed them
- arguments are joined with a single space
- an argument is quoted when it is empty or contains a space, tab, or `"`
- inside quotes, backslashes follow the `CommandLineToArgvW` rules: a quote
  is preceded by `2n+1` backslashes, and a trailing run of `n` backslashes
  is emitted as `2n` so the closing quote stays a closer

`GetCommandLineW` is the UTF-16 form of that same string. The buffers are
writable guest memory. They are not the host `argv` pointers.

## Environment

The guest does not see the host environment. A host variable is copied in
only when its name starts with `TWEAKWIN_GUEST_`. The prefix is removed, so
`TWEAKWIN_GUEST_FOO=bar` is guest `FOO=bar`.

Names are ASCII, without `=`, at most 255 characters. Values are UTF-8, at
most 4096 bytes. Lookup is case-insensitive for A–Z. At most 64 variables.
A value that is not valid UTF-8 is not imported.

`SetEnvironmentVariable` with a NULL value deletes. An empty string stores an
empty value. `GetEnvironmentStrings` returns a snapshot
(`name=value\0` … `\0`, or the UTF-16 equivalent). `FreeEnvironmentStrings`
accepts only a pointer that call returned.

## Files

`CreateFileA/W` opens a host file. The path rules are the whole filesystem
story for M2:

- relative to the runtime's current directory
- `\` and `/` are separators
- `.` is allowed, `..` is not
- no leading slash, no drive letter, no `\\`, no `:`
- no `< > | * ? "` and no byte below 0x20
- no trailing slash
- the final component is opened with `O_NOFOLLOW` (a symlink there fails)
- a symlink in a parent directory is followed by the host `open`. M2 does
  not walk the path itself. Do not point the working directory at a tree
  where an untrusted guest should be unable to follow a directory symlink
- `lpSecurityAttributes` and `hTemplateFile` must be NULL
- `dwShareMode` is ignored
- access is `GENERIC_READ`, `GENERIC_WRITE`, or both
- dispositions: `CREATE_NEW`, `CREATE_ALWAYS`, `OPEN_EXISTING`, `OPEN_ALWAYS`,
  `TRUNCATE_EXISTING`
- `FILE_FLAG_*` (including overlapped) is rejected. Attribute bits in the low
  byte are ignored
- synchronous only. `ReadFile` / `WriteFile` reject a non-NULL overlapped pointer

`ReadFile` may return a short count at EOF. `WriteFile` fails if it cannot
write every requested byte. A zero-length transfer succeeds and does not
touch the buffer.

## Time

`QueryPerformanceFrequency` is 1_000_000_000. The counter is
`CLOCK_MONOTONIC` in nanoseconds, so it is monotonic and it is not the
Windows boot tick. `GetTickCount` / `GetTickCount64` are that counter in
milliseconds; the 32-bit form wraps. `Sleep(0)` yields. `Sleep(n)` is
`nanosleep` and restarts on `EINTR`.

## Strings

`CP_ACP` and `CP_UTF8` are both strict UTF-8. That is TweakWin policy, not a
claim that a Windows ANSI code page is UTF-8. No other code page is accepted.
Invalid sequences fail with `ERROR_NO_UNICODE_TRANSLATION`. There is no
default-character substitution, and `WideCharToMultiByte` rejects a non-NULL
default-character pointer.

## M4: Windows namespace and registry

**Namespace** (`runtime/winfs.c`). The guest sees one drive, `C:`, rooted at
`$TWEAKWIN_FS_ROOT` or, by default, the directory containing the EXE. Paths are
normalised lexically (`/` and `\` accepted, `.` and `..` resolved, `..` clamped at
the root, UNC / `\\?\` / other drives / invalid characters rejected) and then
walked component by component with `O_NOFOLLOW`; a symlink anywhere is refused
(`ERROR_ACCESS_DENIED`), never followed. Matching is case-insensitive; an
exact-case match wins, an ambiguous match is refused. The current directory is
virtual. Exposed through `GetFileAttributesA/W`, `FindFirstFileA/W`,
`FindNextFileA/W`, `FindClose`, `Get/SetCurrentDirectoryA` and DLL search.
`CreateFile` keeps the M2 relative-path policy. Residual risk: the final path
component is handed to the host as a path string after the check, so a racing
host process that swaps a checked component for a symlink is not defended
against (intermediate directories are opened with `openat`).

**Registry** (`runtime/registry.c`, `advapi32/`). Isolated, in-memory,
non-persistent HKCU and HKLM trees. Never reads or writes any host registry.
Names are case-insensitive; limits: 1024 subkeys, 1024 values per key, depth 64,
1 MiB per value. `REG_DWORD` needs exactly 4 bytes, `REG_QWORD` 8; string
types are stored as UTF-16 so the A and W entry points agree. Errors:
`ERROR_FILE_NOT_FOUND` (missing key/value), `ERROR_MORE_DATA` (small buffer,
required size returned), `ERROR_INVALID_HANDLE` (closed key, unsupported root),
`ERROR_INVALID_PARAMETER` (bad reserved/options/type size). Anything not listed
(RegEnum*, RegDeleteKey, RegGetValue, persistence) is simply not exported, so
importing it fails at load.

## Still not implemented

Fibers, TLS callbacks in DLLs, frame-based SEH, delay-load binding, console
modes, overlapped and async I/O, pipes, namespace-aware `CreateFile`, registry
persistence, GUI, COM, and every kernel32 export not in the table above. `ntdll` has no exports on purpose.
