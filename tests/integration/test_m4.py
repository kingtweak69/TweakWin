#!/usr/bin/env python3
"""
M4 acceptance: genuine EXE -> separately compiled DLL -> exported function,
dependency chains, forwarders, relocation, lifecycle, failure rollback, the
contained Windows namespace and the virtual registry. Every PE here is built
by clang/lld-link (tools/build-pe.sh); the test skips cleanly when the LLVM PE
tools (and therefore the fixtures) are absent.

  test_m4.py TWEAKWIN_BINARY FIXTURE_DIR
"""
import os
import random
import shutil
import subprocess
import sys
import tempfile

passed = 0
failed = 0


def ok(cond, what):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {what}", file=sys.stderr)


def run(exe, env=None, cwd=None):
    e = dict(os.environ)
    e.pop("TWEAKWIN_FS_ROOT", None)
    if env:
        e.update(env)
    p = subprocess.run([BIN, "run", exe], capture_output=True, timeout=120, env=e, cwd=cwd)
    return p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1")


def lines(out):
    return out.splitlines()


def in_order(out, wanted):
    ls = lines(out)
    pos = -1
    for w in wanted:
        try:
            pos = ls.index(w, pos + 1)
        except ValueError:
            return False
    return True


def main():
    global BIN, FIX
    BIN, FIX = os.path.abspath(sys.argv[1]), sys.argv[2]
    if not os.path.exists(os.path.join(FIX, "m4-main.exe")):
        print("skip: M4 fixtures not built; needs clang/lld-link/llvm-dlltool")
        return 0
    f = lambda n: os.path.join(FIX, n)

    # ---- primary gate: real EXE loads a real DLL and calls an export ------
    rc, out, err = run(f("m4-main.exe"))
    ok(rc == 0, f"m4-main rc={rc} ({err.strip()})")
    for s in ["m4_add(40,2)=42", "m4_mul(6,7)=42", "handle-match=1", "missing-proc=1",
              "missing-proc-err=127", "free=1", "gone=1", "missing-dll=1", "missing-dll-err=126"]:
        ok(s in lines(out), f"m4-main output has {s!r} (got {out!r})")
    ok(in_order(out, ["[base] attach", "m4_add(40,2)=42", "[base] detach", "gone=1"]),
       f"m4-main attach/call/detach ordering (got {out!r})")

    # ---- implicit imports through a 3-deep chain --------------------------
    rc, out, err = run(f("m4-impl.exe"))
    ok(rc == 3, f"m4-impl rc={rc} ({err.strip()})")
    ok(in_order(out, ["[base] attach", "[mid] attach", "[top] attach", "[exe] start",
                      "top_calc(5)=70", "m4_add(1,2)=3", "[top] detach", "[mid] detach",
                      "[base] detach-exit"]), f"m4-impl init/teardown order (got {out!r})")

    # ---- dynamic scenarios -------------------------------------------------
    rc, out, err = run(f("m4-dyn.exe"))
    ok(rc == 0, f"m4-dyn rc={rc} ({err.strip()})")
    want = ["top-loaded=1", "top_calc(5)=70", "forwarded(3,4)=7", "forwarded-is-base=1",
            "base-gone=1", "same-handle=1", "still-loaded=1", "unloaded=1",
            "extra-free=0", "extra-free-err=6", "cycle-next=2",
            "thread-tls=222", "main-tls=111", "thread-initial-tls=0", "thread-events=101",
            "fail-dll=1", "fail-dll-err=1114", "fail-not-resident=1",
            "missing-dep=1", "missing-dep-err=126", "bad-symbol=1", "bad-symbol-err=127",
            "bad-symbol-dep-rolled-back=1", "exe-as-dll=1", "exe-as-dll-err=193",
            "tls-dll=1", "tls-dll-err=193", "ex-unsupported=1", "ex-unsupported-err=50",
            "ex-badflags=1", "ex-badflags-err=87", "ex-altered=1",
            "loop-loaded=1", "loop-proc=1", "loop-proc-err=127",
            "dup-loaded=1", "dup-ids=12", "dup-bases-differ=1"]
    for s in want:
        ok(s in lines(out), f"m4-dyn output has {s!r}")
    ok(in_order(out, ["[base] attach", "[mid] attach", "[top] attach", "top-loaded=1",
                      "[top] detach", "[mid] detach", "[base] detach", "free-top=1"]),
       "m4-dyn chain attach/detach ordering")
    ok(lines(out).count("[base] attach") == lines(out).count("[base] detach"),
       "m4-dyn: every base attach has a matching detach (load/unload cycles)")
    ok("[fail] detach" not in lines(out), "m4-dyn: a DLL whose attach failed gets no detach")
    ok("[mid] detach" not in lines(out[out.index("fail-dll"):]), "m4-dyn: rollback quiet after failure")

    # ---- malformed / hostile DLLs placed where LoadLibrary finds them -----
    tmp = tempfile.mkdtemp(prefix="tw-m4-")
    try:
        shutil.copy(f("m4-main.exe"), tmp)
        good = open(f("m4_base.dll"), "rb").read()
        bad = os.path.join(tmp, "m4_base.dll")
        for n in (0, 2, 64, 100, 300, 700, len(good) // 2):
            open(bad, "wb").write(good[:n])
            rc, out, err = run(os.path.join(tmp, "m4-main.exe"))
            ok(rc == 1 and "load-failed=193" in out, f"truncated({n}) rejected, rc={rc} out={out!r}")
            ok("Sanitizer" not in err, f"truncated({n}) clean under sanitizers")
        rnd = random.Random(0x4D34)
        # Flip bytes in the headers and the export directory only, then load
        # with a probe that never calls an export. Guest faults (exit 255) are
        # acceptable; host signals and sanitizer reports are loader defects.
        shutil.copy(f("m4-probe.exe"), tmp)
        pe = int.from_bytes(good[0x3C:0x40], "little")
        nsec = int.from_bytes(good[pe + 6:pe + 8], "little")
        opt = int.from_bytes(good[pe + 20:pe + 22], "little")
        dd = pe + 24 + 112
        secs = []
        for k in range(nsec):
            o = pe + 24 + opt + 40 * k
            secs.append(tuple(int.from_bytes(good[o + x:o + x + 4], "little") for x in (12, 8, 20, 16)))
        hdr_end = int.from_bytes(good[pe + 24 + 60:pe + 24 + 64], "little")
        skip = set(range(pe + 24 + 16, pe + 24 + 20))        # entry point
        skip |= set(range(dd + 8, dd + 16)) | set(range(dd + 12 * 8, dd + 13 * 8))  # import, IAT
        skip |= set(range(dd + 5 * 8, dd + 6 * 8))            # base relocations
        targets = [i for i in range(hdr_end) if i not in skip]
        erva = int.from_bytes(good[dd:dd + 4], "little")
        esz = int.from_bytes(good[dd + 4:dd + 8], "little")
        for va, vsz, raw, rsz in secs:
            if va <= erva < va + vsz:
                targets += [raw + (erva - va) + i for i in range(min(esz, rsz))]
        crashes = 0
        for i in range(300):
            b = bytearray(good)
            for _ in range(rnd.randint(1, 6)):
                b[rnd.choice(targets)] = rnd.randrange(256)
            open(bad, "wb").write(b)
            rc, out, err = run(os.path.join(tmp, "m4-probe.exe"))
            if rc < 0 or rc not in (0, 1, 255) or "Sanitizer" in err or "sanitizer" in err:
                crashes += 1
                print(f"mutation {i}: rc={rc} {err[:200]}", file=sys.stderr)
        ok(crashes == 0, f"{crashes} byte-flipped DLLs misbehaved")

        # malformed forwarder target (no dot) in an otherwise valid DLL
        fx = tempfile.mkdtemp(prefix="tw-m4fx-")
        for n in os.listdir(FIX):
            if n.endswith((".exe", ".dll")):
                shutil.copy(f(n), os.path.join(fx, n))
        la = open(f("m4_loop_a.dll"), "rb").read()
        ok(b"m4_loop_b.b_f" in la, "loop_a carries its forwarder string")
        open(os.path.join(fx, "m4_loop_a.dll"), "wb").write(la.replace(b"m4_loop_b.b_f", b"m4_loop_bXb_f"))
        rc, out, err = run(os.path.join(fx, "m4-dyn.exe"))
        ok(rc == 0 and "loop-proc=1" in lines(out), f"malformed forwarder handled rc={rc} err={err.strip()}")
        shutil.rmtree(fx)
    finally:
        shutil.rmtree(tmp)

    # ---- Windows namespace: confinement, symlinks, case, enumeration ------
    root = tempfile.mkdtemp(prefix="tw-m4fs-")
    outside = tempfile.mkdtemp(prefix="tw-m4out-")
    try:
        os.makedirs(os.path.join(root, "data", "sub"))
        open(os.path.join(root, "data", "Hello.TXT"), "w").write("x")
        open(os.path.join(root, "data", "other.dat"), "w").write("y")
        open(os.path.join(outside, "passwd"), "w").write("secret")
        os.symlink(outside, os.path.join(root, "link"))
        os.symlink("/etc/passwd", os.path.join(root, "evil.txt"))
        shutil.copy(f("m4-fs.exe"), root)
        rc, out, err = run(os.path.join(root, "m4-fs.exe"), cwd="/")
        ok(rc == 0, f"m4-fs rc={rc} ({err.strip()})")
        L = lines(out)
        for s in ["C:\\data\\Hello.TXT attr=128", "c:\\DATA\\hello.txt attr=128",
                  "data\\sub attr=16", "C:\\data\\missing.txt err=2",
                  "C:\\link err=5", "C:\\link\\passwd err=5", "C:\\evil.txt err=5",
                  "\\\\?\\C:\\data err=123", "D:\\data err=3", "C:\\da|ta err=123",
                  "C:\\..\\..\\..\\etc\\passwd err=3",
                  "  Hello.TXT", "  other.dat", "  sub", "  find-err=5", "  find-err=3",
                  "cwd=C:\\", "cwd=C:\\data\\sub", "setcwd-bad=0", "..\\Hello.txt attr=128",
                  "dll-outside=1"]:
            ok(s in L, f"m4-fs has {s!r} (got {out!r})")
        ok(L.count("  Hello.TXT") == 2, "wildcard *.txt matched case-insensitively")

        # Namespace collision: two names differing only by case are refused
        # rather than resolved arbitrarily.
        os.makedirs(os.path.join(root, "dup"))
        open(os.path.join(root, "dup", "File.txt"), "w").write("1")
        open(os.path.join(root, "dup", "file.TXT"), "w").write("2")
        # (resolution policy is covered by the C unit test; here just make
        # sure the guest still runs with such a directory present)
        rc, out, err = run(os.path.join(root, "m4-fs.exe"), cwd="/")
        ok(rc == 0, "m4-fs tolerates a case-colliding directory")

        # TWEAKWIN_FS_ROOT overrides the default (the exe directory).
        alt = tempfile.mkdtemp(prefix="tw-m4alt-")
        os.makedirs(os.path.join(alt, "data"))
        open(os.path.join(alt, "data", "Hello.TXT"), "w").write("x")
        rc, out, err = run(os.path.join(root, "m4-fs.exe"), env={"TWEAKWIN_FS_ROOT": alt}, cwd="/")
        ok("C:\\data\\Hello.TXT attr=128" in lines(out) and "C:\\link err=2" in lines(out),
           f"TWEAKWIN_FS_ROOT is honoured (got {out!r})")
        shutil.rmtree(alt)
    finally:
        shutil.rmtree(root)
        shutil.rmtree(outside)

    # ---- registry ----------------------------------------------------------
    rc, out, err = run(f("m4-reg.exe"))
    ok(rc == 0, f"m4-reg rc={rc} ({err.strip()})")
    L = lines(out)
    for s in ["open-missing=2", "create=0", "disposition=1", "set-dword=0", "set-sz=0",
              "set-bad-dword=87", "get-dword=0", "  value=1234", "  type=4", "get-small=234",
              "  needed=6", "get-sz=0", "tweak", "get-size-only=0", "set-w=0",
              "get-w-as-a=0", "xy", "reopen=0", "get-via-reopen=0", "delete=0",
              "delete-again=2", "get-deleted=2", "close=0", "close-again=6",
              "use-closed=6", "bad-root=6", "bad-reserved=87"]:
        ok(s in L, f"m4-reg has {s!r} (got {out!r})")
    # not persistent: a second run starts with an empty registry
    rc, out2, err = run(f("m4-reg.exe"))
    ok(out2 == out, "registry is not persisted across runs")

    print(f"test_m4: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
