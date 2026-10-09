# PEB / TEB (x86-64)

TweakWin builds a real x86-64 Windows process/thread environment in guest
memory and points GS at the TEB, which is what a Windows x64 guest reads.
Layout offsets are in `rt/winnt.h`; construction is `rt/teb.c`.

## Three different things, kept separate

- **Architectural GS base** — the linear address the CPU adds to a
  `GS:`-relative access. TweakWin sets it to the TEB with the backend's
  `tw_kb_tls_set(GS, teb)`. The host C library uses FS, so pointing GS at
  the guest TEB never disturbs it. FS is intentionally not offered to guests
  on the host backend.
- **TEB.ThreadLocalStoragePointer** (`GS:[0x58]`) — per-thread array of
  implicit (PE) TLS blocks, indexed by the TLS directory's allocated index.
- **TEB.TlsSlots** (`GS:[0x1480]`) — the 64 `TlsAlloc`/`TlsGetValue` slots.

They are related but never the same storage. See `EXCEPTIONS.md` and the
TLS section of this tree for how each is populated.

## TEB fields TweakWin populates

`NtTib.StackBase`, `NtTib.StackLimit`, `NtTib.Self` (`GS:[0x30]`),
`NtTib.ExceptionList` (= -1, chain end), `ClientId` (process + thread id),
`ProcessEnvironmentBlock` (`GS:[0x60]`), `LastErrorValue` (`GS:[0x68]`),
`ThreadLocalStoragePointer`, and the TLS slots. Everything else is
zero-filled to the documented 0x1838-byte size.

`LastErrorValue` is the real per-thread LastError once the rt environment is
active: `GetLastError`/`SetLastError` read and write this field for the
calling thread. The legacy global remains only for host unit tests that run
without a TEB.

## PEB fields TweakWin populates

`ImageBaseAddress`, `Ldr`, `ProcessParameters`, `ProcessHeap`,
`NumberOfProcessors` (1), OS version (10.0.19041, platform 2). Size 0x7C8.

`ProcessParameters` (RTL_USER_PROCESS_PARAMETERS) carries the standard
handles and the `CommandLine` / `ImagePathName` UNICODE_STRINGs pointing at
the UTF-16 command line. `Ldr` (PEB_LDR_DATA) has the three circular module
lists populated with two entries — the image and `kernel32.dll` — each a
LDR_DATA_TABLE_ENTRY with `DllBase`, `SizeOfImage`, and Full/Base name
UNICODE_STRINGs.

## Demonstrated

`peb-m3.exe` (clang + lld-link, no CRT) reads `GS:[0x30]` and `GS:[0x60]`,
walks `PEB -> ProcessParameters -> CommandLine`, writes the command line,
and exits with its UTF-16 length — all from the guest, unaided. `test_rt.c`
pins the structure offsets, the circular loader list, and per-thread
LastError.

## Not yet

`ProcessParameters.Environment` points at the UTF-16 environment block, but
`CurrentDirectory`, the full DLL search path, process/thread affinity, and
the activation-context stack are zero. These are filled by later milestones
as programs need them.
