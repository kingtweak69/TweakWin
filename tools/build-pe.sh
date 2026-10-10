#!/bin/sh
# Build the clang/lld-link acceptance PEs in tests/fixtures/src/*_m3.c into
# OUTDIR. Uses the host clang + lld-link + llvm-dlltool only: no zig, no
# Microsoft libraries. Import libraries are synthesised from .def files.
# Skips (exit 0) when the LLVM PE tools are missing.
set -eu
out="${1:-build/fixtures}"
here="$(cd "$(dirname "$0")/.." && pwd)"
src="$here/tests/fixtures/src"
mkdir -p "$out"

have() { command -v "$1" >/dev/null 2>&1; }
# Debian/Ubuntu install the unversioned LLVM tools under /usr/lib/llvm-N/bin.
if ! have lld-link; then
    for d in /usr/lib/llvm-*/bin; do
        [ -x "$d/lld-link" ] && PATH="$d:$PATH" && break
    done
fi
CLANG=${CLANG:-clang}
LLD=${LLD:-lld-link}
DLLTOOL=${DLLTOOL:-llvm-dlltool}
if ! have "$CLANG" || ! have "$LLD" || ! have "$DLLTOOL"; then
    echo "build-pe: clang/lld-link/llvm-dlltool not all present; skipping" >&2
    exit 0
fi

"$DLLTOOL" -m i386:x86-64 -d "$src/kernel32.def" -l "$out/kernel32.lib" >/dev/null 2>&1

cflags_pe="--target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -Os -Wall"
$CLANG $cflags_pe -c -o "$out/tlssup.obj" "$src/tlssup.c"

build() { # src entry base
    s="$1"; e="$2"; base="$3"
    name="$(basename "$s" .c)"
    "$CLANG" $cflags_pe -c -o "$out/$name.obj" "$src/$s"
    "$LLD" /entry:"$e" /subsystem:console /nodefaultlib ${base:+/base:"$base"} \
        /out:"$out/${name%_m3}-m3.exe" "$out/$name.obj" "$out/tlssup.obj" "$out/kernel32.lib" >/dev/null 2>&1
    rm -f "$out/$name.obj"
}

build_if() { if [ -f "$src/$1" ]; then build "$@"; fi; }
build_if peb_m3.c start 0x140000000
build_if tls_m3.c start 0x140000000
build_if exc_m3.c start 0x140000000
build_if thread_m3.c start 0x140000000

# ---- M4: genuine DLLs and the EXEs that load them -------------------------
"$DLLTOOL" -m i386:x86-64 -d "$src/advapi32.def" -l "$out/advapi32.lib" >/dev/null 2>&1

dll() { # name base [extra link args...]; objects from $out/name.obj
    name="$1"; base="$2"; shift 2
    "$LLD" /dll /entry:DllMain /nodefaultlib /base:"$base" /def:"$src/$name.def" \
        /implib:"$out/$name.lib" /out:"$out/$name.dll" "$out/$name.obj" "$@" >/dev/null 2>&1
}
obj() { # outname source [clang flags]
    o="$1"; s="$2"; shift 2
    "$CLANG" $cflags_pe "$@" -c -o "$out/$o.obj" "$src/$s"
}

obj m4_base m4_base.c
dll m4_base 0x10000000 "$out/kernel32.lib"
# Import library that binds m4_mul by ordinal, plus bogus exports for the
# unresolved-symbol and missing-DLL fixtures.
"$DLLTOOL" -m i386:x86-64 -d "$src/m4_base_ord.def" -l "$out/m4_base_ord.lib" >/dev/null 2>&1
"$DLLTOOL" -m i386:x86-64 -d "$src/m4_base_bad.def" -l "$out/m4_base_bad.lib" >/dev/null 2>&1
"$DLLTOOL" -m i386:x86-64 -d "$src/no_such_dll.def" -l "$out/no_such_dll.lib" >/dev/null 2>&1

obj m4_mid m4_mid.c
dll m4_mid 0x10100000 "$out/kernel32.lib" "$out/m4_base_ord.lib"
obj m4_top m4_top.c
dll m4_top 0x10200000 "$out/kernel32.lib" "$out/m4_mid.lib"

obj m4_fail m4_fail.c
dll m4_fail 0x10300000 "$out/kernel32.lib"
obj m4_loop_a m4_stub.c
dll m4_loop_a 0x10400000 "$out/kernel32.lib"
obj m4_loop_b m4_stub.c
dll m4_loop_b 0x10500000 "$out/kernel32.lib"
obj m4_missing m4_imp.c -DIMPORT_FN=nothing
dll m4_missing 0x10600000 "$out/kernel32.lib" "$out/no_such_dll.lib"
obj m4_badsym m4_imp.c -DIMPORT_FN=m4_nonexistent
dll m4_badsym 0x10700000 "$out/kernel32.lib" "$out/m4_base_bad.lib"
obj m4_dupa m4_dup.c -DDUPID=1
dll m4_dupa 0x30000000 "$out/kernel32.lib"
obj m4_dupb m4_dup.c -DDUPID=2
dll m4_dupb 0x30000000 "$out/kernel32.lib"
obj m4_tlsdll m4_tlsdll.c
dll m4_tlsdll 0x10800000 "$out/kernel32.lib" "$out/tlssup.obj"

exe() { # name source [libs...]
    name="$1"; s="$2"; shift 2
    obj "$name" "$s"
    "$LLD" /entry:start /subsystem:console /nodefaultlib /base:0x140000000 \
        /out:"$out/${name}.exe" "$out/$name.obj" "$out/kernel32.lib" "$@" >/dev/null 2>&1
}
exe m4-main m4_main.c
exe m4-impl m4_impl.c "$out/m4_top.lib" "$out/m4_base.lib"
exe m4-dyn m4_dyn.c
exe m4-fs m4_fs.c
exe m4-reg m4_reg.c "$out/advapi32.lib"
exe m4-probe m4_probe.c
rm -f "$out"/*.obj

echo "build-pe: wrote M3 + M4 acceptance PEs to $out"
