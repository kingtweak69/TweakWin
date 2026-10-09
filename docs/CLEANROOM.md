# Clean-room record

TweakWin is implemented independently. This file records what each component
was built from, so the provenance can be checked later.

## Rules

- No Wine source code is read, copied, or paraphrased. No other
  compatibility layer's implementation is used as a reference either.
- Allowed sources: Microsoft's published documentation (PE/COFF
  specification, Windows SDK / Win32 API docs), observable behaviour of real
  Windows, conformance programs we write ourselves, and analysis of the
  applications TweakWin needs to support.
- Third-party *tools* may be used as black-box test oracles (e.g. comparing
  parse results with `pefile`), never as implementation references.

## Milestone 0: PE parser (`loader/pe/`)

| area | source |
|---|---|
| DOS header, `e_lfanew`, PE signature | Microsoft PE Format spec: "MS-DOS Stub", "Signature" |
| COFF file header, machine types, characteristics | PE Format spec: "COFF File Header" |
| Optional header (PE32+ layout, alignment rules, DllCharacteristics, subsystems) | PE Format spec: "Optional Header" and its sub-sections |
| Section table, long section names | PE Format spec: "Section Table", "COFF String Table" |
| Import directory, ILT/IAT, hint/name table | PE Format spec: "The .idata Section" |
| Delay-load imports | PE Format spec: "Delay-Load Import Tables" |
| Export directory, EAT, name/ordinal tables, forwarders | PE Format spec: "The .edata Section" |
| Base relocations | PE Format spec: "The .reloc Section" |
| TLS directory, callbacks | PE Format spec: "The .tls Section" |
| Exception directory (x64 RUNTIME_FUNCTION, unwind version) | PE Format spec: "The .pdata Section"; x64 exception handling docs |
| Resource directory tree | PE Format spec: "The .rsrc Section" |

Test fixtures are generated from scratch by `tools/mkpe.py`, or compiled from
our own sources in `tests/fixtures/src/` with zig's clang + MinGW-w64
headers and import libraries (build tooling only; nothing from them is
linked into TweakWin).

`pefile` is used only in `tests/integration/test_cli.py` as an independent
oracle.

## Milestone 1: PE loader + minimal console runtime

| area | source |
|---|---|
| Mapping `SizeOfImage`, copying sections, BSS zero-fill | PE Format spec: "Section Table", "Optional Header" (`SizeOfImage`, `SizeOfHeaders`, `VirtualSize` / `SizeOfRawData`) |
| `IMAGE_REL_BASED_DIR64` / `ABSOLUTE` | PE Format spec: "The .reloc Section" |
| IAT patching, import-by-name and by-ordinal | PE Format spec: "The .idata Section"; Win32 DLL name matching (case-insensitive) |
| Microsoft x64 calling convention (RCX, RDX, R8, R9, 32-byte shadow space, 16-byte stack alignment) | Microsoft x64 ABI documentation; `ms_abi` is a compiler annotation, not copied from any compatibility runtime |
| `GetStdHandle` (`STD_INPUT/OUTPUT/ERROR_HANDLE`) | Win32 API docs: GetStdHandle |
| `WriteFile` (synchronous, console handles only) | Win32 API docs: WriteFile |
| `ExitProcess` | Win32 API docs: ExitProcess |

No Wine, Proton, ReactOS, Bottles, or CrossOver sources were opened for
this milestone. Host `mmap` / `mprotect` are used as the Linux equivalent of
mapping a PE image; the layout and protections follow the PE spec, not
another project's loader.

## Milestone 2: console runtime

| area | source |
|---|---|
| `HANDLE` is an opaque value, not a pointer the caller dereferences | Win32 API docs: handle types, `CloseHandle`, `GetStdHandle`, `SetStdHandle`, `GetFileType` |
| `GetLastError` / `SetLastError` are per-thread | Win32 API docs: `GetLastError`, System Error Codes |
| `VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery` and `MEMORY_BASIC_INFORMATION` (48 bytes on x64) | Win32 API docs: memory management |
| `HeapAlloc` / `HeapFree` / `HeapReAlloc` / `HeapSize` / `GetProcessHeap`, including `HeapFree(NULL)` | Win32 API docs: heap functions |
| `CreateFile` dispositions, access masks, `ReadFile` / `WriteFile` synchronous behavior | Win32 API docs: file management |
| `GetCommandLine` and the quote / backslash rules | Win32 API docs: `GetCommandLine`, `CommandLineToArgvW` ("Parsing C Command-Line Arguments") |
| Environment block layout (`name=value\0` … `\0`) and A/W case-insensitivity | Win32 API docs: `GetEnvironmentVariable`, `GetEnvironmentStrings` |
| `MultiByteToWideChar` / `WideCharToMultiByte` return counts, `CP_UTF8` | Win32 API docs: Unicode and character set functions |
| `Sleep`, `GetTickCount`, `QueryPerformanceCounter` | Win32 API docs: time functions |
| Microsoft x64 register assignment for the new exports | Microsoft x64 ABI documentation |

The M2 path rules (relative only, no `..`, no drive letters), the UTF-8
ANSI policy, the QPC frequency of 1e9, and the TweakWin ordinal numbers are
TweakWin policy. They are documented in [RUNTIME.md](RUNTIME.md) and are not
copied from another runtime.

No Wine, Proton, ReactOS, Bottles, or CrossOver sources were opened for
this milestone. Host `open` / `read` / `write` / `mmap` / `clock_gettime`
are the Linux operations underneath the documented Win32 behavior.
