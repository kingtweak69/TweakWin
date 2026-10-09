#!/usr/bin/env python3
"""
M3 runtime acceptance: run the clang/lld-link-built PEs end to end through
tweakwin and check output + exit code. Skips cleanly when the LLVM PE
toolchain (and therefore the fixtures) is absent.

  test_m3.py TWEAKWIN_BINARY FIXTURE_DIR
"""
import os
import subprocess
import sys

passed = 0
failed = 0


def ok(cond, what):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {what}", file=sys.stderr)


def run(exe, *args):
    p = subprocess.run([BIN, "run", exe, *args], capture_output=True, timeout=60)
    return p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1")


def case(name, args, want_rc, want_out_substrings):
    exe = os.path.join(FIX, name)
    if not os.path.exists(exe):
        print(f"skip: {name} (fixture not built; needs clang/lld-link)")
        return
    rc, out, err = run(exe, *args)
    ok(rc == want_rc, f"{name} rc={rc} want {want_rc} (stderr: {err.strip()})")
    for s in want_out_substrings:
        ok(s in out, f"{name} output contains {s!r} (got {out!r})")


def main():
    # PEB walk: exit code is the command-line length & 0xff; the guest also
    # echoes the command line it read from the PEB.
    exe = os.path.join(FIX, "peb-m3.exe")
    if os.path.exists(exe):
        rc, out, err = run(exe, "alpha", "b c")
        cmdline = out.strip().split("\n")[-1]
        ok(rc == (len(cmdline) & 0xFF), f"peb-m3 rc={rc} == len(cmdline)={len(cmdline)}")
        ok("peb-m3.exe" in out, f"peb-m3 echoes its command line (got {out!r})")
    else:
        print("skip: peb-m3.exe (fixture not built)")

    # Two threads, per-thread TLS, event + semaphore, join + exit codes.
    case("thread-m3.exe", [], 0, ["worker1", "worker2", "main"])

    # TLS stress: independent values across threads.
    case("tls-m3.exe", [], 0, ["tls-ok"])

    # Exception translation: access violation caught by a vectored handler.
    case("exc-m3.exe", [], 0, ["caught-av", "continued"])

    print(f"m3 acceptance: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: test_m3.py TWEAKWIN_BINARY FIXTURE_DIR", file=sys.stderr)
        sys.exit(2)
    BIN = sys.argv[1]
    FIX = sys.argv[2]
    sys.exit(main())
