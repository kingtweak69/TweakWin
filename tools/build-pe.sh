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

echo "build-pe: wrote M3 acceptance PEs to $out"
