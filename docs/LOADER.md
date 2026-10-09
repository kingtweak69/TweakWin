# PE32+ loader (Milestone 1)

The loader (`loader/load.c`) maps a PE32+ image the M0 parser has already
accepted, resolves imports through TweakWin-owned modules, and transfers
control to the guest entry point. Every PE is still treated as hostile.

## Sequence

1. Parse with `tw_pe_load_file` (M0).
2. Reject DLLs, non-console subsystems, and entry points that are missing
   or not in an executable section.
3. `mmap` `SizeOfImage` (page-rounded). Prefer `ImageBase`; if that address
   is taken (or tests ask for it), map elsewhere and apply relocations.
4. Copy headers and each section (`min(VirtualSize, SizeOfRawData)` bytes
   from `PointerToRawData`). Virtual tails past raw data stay zero (BSS).
5. Apply `IMAGE_REL_BASED_DIR64`. Skip `ABSOLUTE`. Any other type is
   unsupported at load time.
6. Patch each non-delay IAT slot through the module registry
   (`runtime/modules.c`). Unknown DLL / unknown symbol are distinct errors.
7. `mprotect` header pages read-only and each section according to its
   characteristics. `W+X` is reduced to `RX` after fixups (W^X).
8. Map a guest stack with a `PROT_NONE` guard page.
9. Enter the guest with Microsoft x64 ABI alignment (RSP ≡ 8 mod 16, as
   after a CALL). Host APIs are `ms_abi`.

Guest pointers passed to Win32 calls must fall inside a mapped region with
the required protection, or inside a runtime allocation (`VirtualAlloc`,
heap, command line, environment block). There is no shell-out on guest
strings. The Win32 surface itself is documented in
[RUNTIME.md](RUNTIME.md); the loader only maps, relocates, binds, and enters.

## Relocations

| type | parser | loader |
|---|---|---|
| ABSOLUTE | accepted | ignored |
| DIR64 | accepted | applied (`+= delta`) |
| HIGH / LOW / HIGHLOW | warning | unsupported (exit 3) |
| anything else | malformed (exit 2) | — |

An image with no relocation directory can only run at `ImageBase`.
That includes compiler-built programs that are purely RIP-relative and
simply omit `.reloc`. TweakWin will not guess that an image is safe to
slide.

## Modules

Registered namespaces:

- `kernel32.dll` — ordinals 1–3 are `GetStdHandle`, `WriteFile`, `ExitProcess`. Further exports are the M2 console runtime; the list and the ordinals are in [RUNTIME.md](RUNTIME.md)
- `ntdll.dll` — namespace only (no exports)

DLL names are matched case-insensitively. Function names are
case-sensitive. Those ordinals belong to the TweakWin-owned module, not
to any particular Windows `kernel32` build. Name imports are the M1
contract. Delay-load descriptors are not patched (Windows does that at
first use).

## Stack

Guest stack is `SizeOfStackReserve`, clamped to 64 KiB..8 MiB, with a
`PROT_NONE` guard page below the usable stack. The entry stub leaves
`RSP ≡ 8 (mod 16)`, matching a Windows x64 CALL.

## CLI exit codes

If the guest starts and calls `ExitProcess`, `tweakwin run` returns the low
8 bits of that code. Host errors only apply when the guest does not start,
or starts but returns from the entry point:

| code | meaning |
|---|---|
| 0–255 | guest `ExitProcess` code, when the guest actually ran |
| 1 | I/O, mmap, or generic loader failure |
| 2 | malformed PE |
| 3 | unsupported PE feature (including HIGHLOW relocs, DLLs, non-console) |
| 5 | unresolved DLL |
| 6 | unresolved symbol |
| 7 | guest returned from the entry point without `ExitProcess` |
| 64 | usage |

Host failures always print `tweakwin: PATH: <kind>: <detail>` on stderr.
A guest `ExitProcess(2)` therefore looks like a clean run with status 2 and
empty stderr.

## Tests vs. execution fixtures

| file | origin | purpose |
|---|---|---|
| `hello.exe`, `tweaktest.dll`, `bad/*` | `tools/mkpe.py` | parser only |
| `hello-m1.exe`, `exit42.exe`, `load/*` | `tools/mkpe.py` | real x86-64, run by the loader |
| `hello-m1-real.exe` | zig + `tests/fixtures/src/hello_m1.c` | compiler-generated execution fixture |
| `*-m2.exe` | `tools/mkpe.py` | M2 console guests (args, env, memory, heap, file, timer) |
| `*-m2-real.exe` | zig + `tests/fixtures/src/*_m2.c` | compiler-generated M2 guests (skipped if zig is absent) |
| `hello-real.exe`, `hello-crt.exe` | zig | parser cross-check (CRT imports; not runnable) |
