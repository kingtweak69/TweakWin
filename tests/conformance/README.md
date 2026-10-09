# Windows-side conformance tests

Each Win32 API TweakWin implements gets a small program here that is
intended to run on **real Windows** and print what it observes (return
values, `GetLastError()`, output bytes). The same program then runs under
TweakWin, and the two transcripts must match.

There is no Windows host in this build, so there is still no recorded
Windows transcript. The TweakWin-side behaviour is covered by
`tests/unit/test_loader.c`, `tests/unit/test_runtime.c`, and
`tests/integration/test_cli.py`.

M1 program: `tests/fixtures/src/hello_m1.c` and synthetic `hello-m1.exe`.

```
Hello from TweakWin M1
```

exit status 0.

M2 programs, synthetic (`tools/mkpe.py`) and, when zig is installed,
compiler-built (`tests/fixtures/src/*_m2.c`):

| guest | observes |
|---|---|
| `args-m2.exe` | `GetCommandLineA` with Windows quoting |
| `env-m2.exe` | `TWEAKWIN_GUEST_TWTEST` via `GetEnvironmentVariableA` |
| `mem-m2.exe` | `VirtualAlloc`, `VirtualProtect`, `VirtualFree` |
| `heap-m2.exe` | `GetProcessHeap`, `HeapAlloc`, `HeapFree` |
| `file-m2.exe` | `CreateFileA` + `WriteFile` of `tweakwin-m2\n` to `build/m2-out.txt` |
| `timer-m2.exe` | `QueryPerformanceCounter` increases across `Sleep(5)` |

The path, environment, and UTF-8 policies those programs depend on are
TweakWin's, written down in `docs/RUNTIME.md`. A Windows transcript would
not match the path or environment policy byte for byte; it would match
return values, `GetLastError` codes, and the quoting rules.
