#!/usr/bin/env python3
"""
CLI integration tests for `tweakwin`.

  test_cli.py TWEAKWIN_BINARY FIXTURE_DIR

- golden output for the synthetic fixtures (tests/integration/expected/)
- every malformed/unsupported variant: exit code + diagnostic
- CLI contract (exit codes, usage, run)

- untrusted strings cannot inject terminal escapes
- TWEAKWIN_DEBUG categories
- cross-check against the independent `pefile` parser when it is installed
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(HERE, "expected")

passed = 0
failed = 0


def ok(cond, what):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {what}", file=sys.stderr)


def tw(*args, env=None):
    e = dict(os.environ)
    e.pop("TWEAKWIN_DEBUG", None)
    if env:
        e.update(env)
    p = subprocess.run([BIN, *args], capture_output=True, env=e, timeout=60)
    return p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1")


def normalize(out):
    return re.sub(r"^File: .*$", "File: <path>", out, flags=re.M)


def test_golden():
    for name in ("hello.exe", "tweaktest.dll"):
        rc, out, err = tw("inspect", os.path.join(FIX, name))
        ok(rc == 0, f"{name} exit 0 (got {rc}: {err.strip()})")
        exp_path = os.path.join(EXPECTED, name + ".txt")
        if os.environ.get("TWEAKWIN_UPDATE_GOLDEN"):
            with open(exp_path, "w") as f:
                f.write(normalize(out))
            continue
        with open(exp_path) as f:
            want = f.read()
        got = normalize(out)
        if got != want:
            import difflib
            sys.stderr.writelines(difflib.unified_diff(want.splitlines(True), got.splitlines(True),
                                                       "expected/" + name, "actual"))
        ok(got == want, f"{name} golden output")


def test_manifest():
    with open(os.path.join(FIX, "bad", "manifest.tsv")) as f:
        rows = [l.rstrip("\n").split("\t") for l in f if l.strip()]
    ok(len(rows) >= 40, "manifest has >= 40 variants")
    for name, code, needle in rows:
        rc, out, err = tw("inspect", os.path.join(FIX, "bad", name))
        ok(rc == int(code), f"{name}: exit {rc}, want {code} ({err.strip()})")
        if needle:
            ok(needle in (err if rc else out), f"{name}: '{needle}' in output")
        if rc:
            ok(err.startswith("tweakwin: "), f"{name}: diagnostic on stderr")


def test_contract():
    rc, out, _ = tw("--version")
    ok(rc == 0 and out.startswith("tweakwin 0.3.0"), "--version")
    rc, out, _ = tw("doctor")
    ok(rc == 0 and "PE parser: ready" in out, "doctor parser")
    ok("PE loader: ready" in out, "doctor loader")
    ok("relocations: DIR64" in out, "doctor relocs")
    ok("import resolver: ready" in out, "doctor resolver")
    ok("API modules: kernel32 console runtime, ntdll namespace" in out, "doctor modules")
    ok("filesystem: relative paths only" in out, "doctor filesystem")
    ok("environment: TWEAKWIN_GUEST_ prefix only" in out, "doctor environment")
    ok("Loader: not implemented" not in out, "doctor no longer reports loader unimplemented")
    rc, _, _ = tw()
    ok(rc == 64, "no args -> 64")
    rc, _, _ = tw("bogus")
    ok(rc == 64, "unknown command -> 64")
    rc, _, _ = tw("inspect")
    ok(rc == 64, "inspect without file -> 64")
    rc, _, _ = tw("run")
    ok(rc == 64, "run without file -> 64")
    rc, _, err = tw("inspect", os.path.join(FIX, "does-not-exist.exe"))
    ok(rc == 1 and "cannot open" in err, "missing file -> 1")
    rc, _, err = tw("inspect", FIX)
    ok(rc == 1 and "not a regular file" in err, "directory -> 1")


def test_run():
    hello = os.path.join(FIX, "hello-m1.exe")
    rc, out, err = tw("run", hello)
    ok(rc == 0, f"hello-m1 exit 0 (got {rc}: {err.strip()})")
    ok(out == "Hello from TweakWin M1\r\n" or out == "Hello from TweakWin M1\n"
       or out.endswith("Hello from TweakWin M1\r\n"),
       f"hello-m1 stdout {out!r}")
    ok("Hello from TweakWin M1" in out, "hello-m1 message")

    rc, _, err = tw("run", os.path.join(FIX, "exit42.exe"))
    ok(rc == 42, f"exit42 -> 42 (got {rc}: {err.strip()})")

    rc, _, err = tw("run", os.path.join(FIX, "hello.exe"))
    ok(rc == 7 and "entry point" in err, "placeholder hello.exe does not fake success")

    rc, _, err = tw("run", os.path.join(FIX, "tweaktest.dll"))
    ok(rc == 3 and "DLL" in err, "run dll -> 3")

    rc, _, err = tw("run", os.path.join(FIX, "load", "unknown-dll.exe"))
    ok(rc == 5 and "NOSUCH32.dll" in err, "unknown DLL -> 5")

    rc, _, err = tw("run", os.path.join(FIX, "load", "unknown-sym.exe"))
    ok(rc == 6 and "NoSuchProcX" in err, "unknown symbol -> 6")

    rc, _, err = tw("run", os.path.join(FIX, "load", "highlow-reloc.exe"))
    ok(rc == 3 and "HIGHLOW" in err, "unsupported reloc -> 3")

    rc, _, err = tw("run", os.path.join(FIX, "bad", "reloc-target-oob.exe"))
    ok(rc == 2 and "outside the image" in err, "invalid reloc target -> 2")

    rc, _, err = tw("run", os.path.join(FIX, "load", "entry-zero.exe"))
    ok(rc == 1 and "entry point" in err, "missing entry -> 1")

    rc, _, err = tw("run", os.path.join(FIX, "load", "entry-nx.exe"))
    ok(rc == 1 and "executable" in err, "non-executable entry -> 1")

    rc, out, err = tw("run", os.path.join(FIX, "load", "no-reloc.exe"))
    ok(rc == 0 and out == "Hello from TweakWin M1\r\n", f"no-reloc stdout {out!r} err {err!r}")

    rc, _, err = tw("run", os.path.join(FIX, "bad", "not-mz.exe"))
    ok(rc == 2, "run malformed -> 2")

    real = os.path.join(FIX, "hello-m1-real.exe")
    if os.path.exists(real):
        rc, out, err = tw("run", real)
        ok(rc == 0 and "Hello from TweakWin M1" in out, f"hello-m1-real (got {rc}: {err.strip()})")
    else:
        print("skip: hello-m1-real.exe (zig not installed)")


def test_m2():
    def guest(name, *args, env=None):
        return tw("run", os.path.join(FIX, name), *args, env=env)

    rc, out, err = guest("args-m2.exe", "hello", "a b")
    ok(rc == 0 and out.endswith('hello "a b"'), f"args-m2 {out!r} {err!r}")
    rc, out, err = guest("env-m2.exe", env={"TWEAKWIN_GUEST_TWTEST": "hello-env"})
    ok(rc == 0 and out == "hello-env", f"env-m2 {out!r} {err!r}")
    rc, out, err = guest("mem-m2.exe")
    ok(rc == 0 and out == "mem-ok\r\n", f"mem-m2 {out!r} {err!r}")
    rc, out, err = guest("heap-m2.exe")
    ok(rc == 0 and out == "heap-ok\r\n", f"heap-m2 {out!r} {err!r}")
    out_path = os.path.join("build", "m2-out.txt")
    if os.path.exists(out_path):
        os.remove(out_path)
    rc, out, err = guest("file-m2.exe")
    ok(rc == 0 and out == "file-ok\r\n", f"file-m2 {out!r} {err!r}")
    try:
        with open(out_path, "rb") as f:
            data = f.read()
        ok(data == b"tweakwin-m2\n", f"file bytes {data!r}")
    except OSError as e:
        ok(False, f"file missing: {e}")
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
    rc, out, err = guest("timer-m2.exe")
    ok(rc == 0 and out == "timer-ok\r\n", f"timer-m2 {out!r} {err!r}")

    real = os.path.join(FIX, "args-m2-real.exe")
    if os.path.exists(real):
        rc, out, err = tw("run", real, "hello", "a b")
        ok(rc == 0 and 'hello "a b"' in out, f"args-m2-real {out!r} {err!r}")
        for name, needle in (
            ("env-m2-real.exe", "hello-env"),
            ("mem-m2-real.exe", "mem-ok"),
            ("heap-m2-real.exe", "heap-ok"),
            ("file-m2-real.exe", "file-ok"),
            ("timer-m2-real.exe", "timer-ok"),
        ):
            path = os.path.join(FIX, name)
            extra = {"TWEAKWIN_GUEST_TWTEST": "hello-env"} if name.startswith("env") else None
            rc, out, err = tw("run", path, env=extra)
            ok(rc == 0 and needle in out, f"{name} {out!r} {err!r}")
    else:
        print("skip: M2 zig fixtures (zig not installed)")


def test_escapes():
    with open(os.path.join(FIX, "hello.exe"), "rb") as f:
        data = bytearray(f.read())
    i = data.find(b"GetStdHandle")
    data[i] = 0x1B
    data[i + 1] = ord("[")
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as t:
        t.write(data)
        path = t.name
    try:
        rc, out, _ = tw("inspect", path)
        ok(rc == 0, "escape fixture parses")
        ok("\x1b" not in out, "no raw ESC in output")
        ok("\\x1b[tStdHandle" in out, "ESC rendered as \\x1b")
    finally:
        os.unlink(path)


def test_debug():
    rc, _, err = tw("inspect", os.path.join(FIX, "hello.exe"), env={"TWEAKWIN_DEBUG": "loader,imports"})
    ok(rc == 0, "debug run exit 0")
    ok("[tweakwin:loader] PE32+" in err, "loader debug category")
    ok("[tweakwin:imports] import KERNEL32.dll: 3 function(s)" in err, "imports debug category")
    rc, _, err = tw("inspect", os.path.join(FIX, "hello.exe"), env={"TWEAKWIN_DEBUG": "nope"})
    ok(rc == 0 and "unknown debug category 'nope'" in err, "unknown debug category warns")


# ---------------------------------------------------------------- pefile cross-check

def parse_output(out):
    """Pull imports/exports/sections/tls out of `tweakwin inspect` text."""
    res = {"imports": {}, "delay": {}, "exports": [], "sections": [], "tls_callbacks": 0, "relocs": 0}
    block = None
    cur = None
    for line in out.splitlines():
        if line == "Imports:":
            block = "imports"; continue
        if line == "Delay imports:":
            block = "delay"; continue
        if line.startswith("Exports:"):
            block = "exports"; continue
        if line == "Sections:":
            block = "sections"; continue
        m = re.match(r"TLS: .*, (\d+) callbacks?$", line)
        if m:
            res["tls_callbacks"] = int(m.group(1))
        m = re.match(r"Relocations: \d+ blocks?, (\d+) entr", line)
        if m:
            res["relocs"] = int(m.group(1))
        if not line.startswith("  "):
            block = None
            continue
        if block in ("imports", "delay"):
            if line.startswith("    "):
                res[block][cur].append(line.strip())
            elif line.strip() != "(none)":
                cur = line.strip()
                res[block][cur] = []
        elif block == "exports":
            m = re.match(r"  #(\d+)\s+(.*?)(?: -> (.*)| @ RVA 0x([0-9a-f]+))$", line)
            if m:
                name = None if m.group(2) == "(by ordinal)" else m.group(2)
                res["exports"].append((int(m.group(1)), name, m.group(3)))
        elif block == "sections":
            res["sections"].append(line.split()[0])
    return res


def test_pefile():
    # pefile fills in names for some well-known ordinal imports (ws2_32,
    # oleaut32) from a built-in table; compare the raw ordinal instead.
    try:
        import pefile
    except ImportError:
        print("skip: pefile not installed (pip install pefile) -- cross-check skipped")
        return
    names = ["hello.exe", "tweaktest.dll", "hello-real.exe", "hello-crt.exe", "tweakdll.dll"]
    for name in names:
        path = os.path.join(FIX, name)
        if not os.path.exists(path):
            continue
        rc, out, err = tw("inspect", path)
        ok(rc == 0, f"pefile xcheck: {name} parses")
        mine = parse_output(out)
        pe = pefile.PE(path)

        ok(mine["sections"] == [s.Name.rstrip(b"\0").decode() for s in pe.sections], f"{name}: sections")

        want = {}
        for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            want[d.dll.decode()] = [f"#{i.ordinal}" if getattr(i, "import_by_ordinal", False) or not i.name else i.name.decode()
                                  for i in d.imports]
        ok(mine["imports"] == want, f"{name}: imports\n  mine={mine['imports']}\n  pefile={want}")

        wantd = {}
        for d in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            wantd[d.dll.decode()] = [f"#{i.ordinal}" if getattr(i, "import_by_ordinal", False) or not i.name else i.name.decode()
                                  for i in d.imports]
        ok(mine["delay"] == wantd, f"{name}: delay imports\n  mine={mine['delay']}\n  pefile={wantd}")

        wante = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                wante.append((s.ordinal, s.name.decode() if s.name else None,
                              s.forwarder.decode() if s.forwarder else None))
        ok(sorted(mine["exports"], key=str) == sorted(wante, key=str),
           f"{name}: exports\n  mine={mine['exports']}\n  pefile={wante}")

        ncb = 0
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            while pe.get_qword_at_rva(rva + 8 * ncb):
                ncb += 1
        ok(mine["tls_callbacks"] == ncb, f"{name}: TLS callbacks {mine['tls_callbacks']} vs {ncb}")

        nrel = sum(len(b.entries) for b in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []))
        ok(mine["relocs"] == nrel, f"{name}: relocation entries {mine['relocs']} vs {nrel}")


def main():
    global BIN, FIX
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(64)
    BIN, FIX = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    test_golden()
    test_manifest()
    test_contract()
    test_run()
    test_m2()
    test_escapes()
    test_debug()
    test_pefile()
    print(f"integration ({os.path.basename(BIN)}): {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
