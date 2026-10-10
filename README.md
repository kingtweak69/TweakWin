# TweakWin

Clean-room Windows compatibility runtime for TweakOS.

**Status: Milestone 3 — process runtime over a TweakKernel backend.** On top
of the M2 console runtime, TweakWin now builds a real x86-64 Windows
process/thread environment (PEB/TEB with a GS-based TEB), Windows TLS,
threads, synchronization (events, semaphores, waits), and an SEH foundation
(vectored exception handlers + translated unhandled filter) — all over a
narrow kernel backend ([backend/kb.h](backend/kb.h)) that is implemented
twice: a Linux host backend and a freestanding TweakKernel M4 backend. The
backend contract is proven on the released TweakKernel `v0.5.0-m4` under
QEMU. It does not yet run general Windows applications (no DLL loader,
registry, Windows filesystem namespace, or frame-based `__try`/`__except`);
Bottles remains the fallback for ordinary Windows programs. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

```
$ tweakwin run build/fixtures/hello-m1.exe
Hello from TweakWin M1
$ tweakwin run build/fixtures/args-m2.exe hello "a b"
build\fixtures\args-m2.exe hello "a b"
$ echo $?
0
```

## Build and test

Needs a C11 compiler, make, and python3. Nothing from Wine, no Debian Wine
packages, no APT source changes.

```
make                 # build/tweakwin
make test            # unit + integration + sanitizer mutation sweep + installcheck
make install         # PREFIX=/usr/local by default
```

Optional:

- `pip install ziglang` (or a system `zig`) → `make test` also builds and
  checks compiler-built Windows binaries from `tests/fixtures/src/`
  (parser fixtures, the M1 guest `hello_m1.c`, and the M2 guests
  `*_m2.c`). Without zig those extra checks are skipped.
- `pip install pefile` → integration tests cross-check imports, delay
  imports, exports, sections, TLS callbacks and relocation counts against an
  independent parser. Skipped if not installed.
- `make fuzz FUZZ_TIME=600` → libFuzzer run (clang with compiler-rt; on
  Debian: the `libclang-rt-*-dev` package matching your clang).

## CLI

| command | status |
|---|---|
| `tweakwin inspect FILE.exe` | implemented |
| `tweakwin doctor` | implemented |
| `tweakwin --version` | implemented |
| `tweakwin run FILE.exe [arg ...]` | implemented (M2 console runtime) |

`run` builds a Windows command line from the arguments (quoting is
documented in [docs/RUNTIME.md](docs/RUNTIME.md)). The guest does not
inherit the host environment. Only variables named `TWEAKWIN_GUEST_*` are
copied, with that prefix removed.

Exit status: if the guest starts, the process status is the guest
`ExitProcess` code. Otherwise `1` loader/I/O, `2` malformed, `3`
unsupported, `5` unresolved DLL, `6` unresolved symbol, `7` runtime
(guest returned without `ExitProcess`), `64` usage. Details:
[docs/LOADER.md](docs/LOADER.md).

Debug logging: `TWEAKWIN_DEBUG=loader,imports tweakwin run app.exe`
(categories: loader, imports, memory, handles, filesystem, registry, thread,
user32, gdi, network, all).

## What M0 parses

DOS header, PE signature, COFF header, PE32+ optional header, section table
(including `/NNN` long names from the COFF string table), data directories,
imports (by name and ordinal), delay imports, exports (named, ordinal-only,
forwarders), base relocations, TLS directory + callbacks, exception
directory (`.pdata`), resource tree summary, overlay, and machine
validation.

Every read is bounds-checked; see [docs/PE-LIMITS.md](docs/PE-LIMITS.md)
for the validation rules and hard caps. Untrusted strings from the binary are
escaped on output so a hostile import name can't emit terminal control
sequences.

## What M1 runs

A Windows x86-64 PE32+ **console** executable whose imports are a subset of
`GetStdHandle`, `WriteFile`, and `ExitProcess`. The image is mapped
(`SizeOfImage`), relocated (`DIR64`), IAT-patched through an internal module
registry, protected W^X, then entered with the Microsoft x64 ABI. See
[docs/LOADER.md](docs/LOADER.md).

## What M2 adds

One guest thread and a real runtime beside the loader (the loader does not
implement Win32):

- process state: command line A/W, module handle / file name, last-error
- memory: `VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery`,
  one process heap
- files: `CreateFileA/W`, `ReadFile`, `CloseHandle`, `GetFileType`,
  `SetStdHandle`, on a documented relative-path policy
- environment blocks, `Sleep`, tick count, QPC, UTF-8 / UTF-16 conversion

`ntdll.dll` is a registered namespace with no exports. An unimplemented
import fails at load time. It is not bound to a stub that returns success.
The exact contract, including what is refused, is
[docs/RUNTIME.md](docs/RUNTIME.md).

## What M4 adds

- A dynamic DLL loader: `LoadLibraryA/W/ExA/ExW`, `GetProcAddress`,
  `FreeLibrary`, `GetModuleHandleA/W`, dependency chains, forwarders,
  relocation, `DllMain` lifecycle with rollback ([docs/LOADER.md](docs/LOADER.md)).
- A contained Windows namespace (`C:\`, case-insensitive, symlink-safe) with
  attributes, enumeration and DLL search, and an isolated in-memory registry
  ([docs/RUNTIME.md](docs/RUNTIME.md)).
- Fixtures are real clang/lld-link PE binaries (`tools/build-pe.sh`; the script
  finds `/usr/lib/llvm-*/bin` if the LLVM tools are not on `PATH`).

Host backend only: nothing M4 is claimed on TweakKernel
([docs/KERNEL-REQUIREMENTS.md](docs/KERNEL-REQUIREMENTS.md)).

## Layout

```
backend/          THE kernel contract (kb.h); host + TweakKernel M4 impls
nt/               NTSTATUS domains (status.c) and NT synchronization (sync.c)
rt/               PEB/TEB, Windows TLS, threads, SEH, Win32 object table
cli/              tweakwin command (inspect, doctor, run)
common/           arena allocator, debug categories
loader/pe/        PE/COFF parser (M0)
loader/load.c     PE32+ mapper, DIR64 relocs, IAT patch, guest entry
runtime/          M2 process state, handles, guest memory, M4 module loader, winfs, registry
advapi32/         M4 registry exports
kernel32/         kernel32 exports (M1 console, M2 surface, M3 sync/thread/TLS/SEH)
include/tweakwin/ version
tests/unit/       C unit tests (ASan + UBSan)
tests/backend/    one backend-conformance suite run on host and on M4
tests/m4/         boots TweakKernel v0.5.0-m4 under QEMU with the suite
tests/integration/ CLI tests, golden outputs, M3 acceptance, pefile cross-check
tests/fuzz/       deterministic mutation sweep + libFuzzer harness
tests/fixtures/src/ sources for compiler-built Windows fixtures (zig or clang+lld-link)
tools/            mkpe.py, build-hello.sh (zig), build-pe.sh (clang+lld-link)
packaging/        notes for the future tweakwin-0.3.0-m3.tweak
docs/             architecture, backend requirements, PEB/TEB, exceptions, API tables
```

The remaining spec directories (`ntdll/` exports, `user32/`, `registry/`,
`filesystem/`, `ipc/`) get created by the milestones that fill them. M2
file and environment policy lives in `kernel32/` and `runtime/`, not in a
Windows namespace.

## Clean-room

See [docs/CLEANROOM.md](docs/CLEANROOM.md). Short version: built from
Microsoft's published PE/COFF specification and Win32 / x64 ABI docs;
no Wine source consulted.
