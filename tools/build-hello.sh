#!/bin/sh
# Build tests/fixtures/src/hello.c as a real x86-64 Windows console PE using
# zig's bundled clang + MinGW headers/import libs. Optional: tests that need
# the output skip when it is missing.
#
#   sh tools/build-hello.sh OUTDIR
#
# zig comes from the distro, https://ziglang.org, or `pip install ziglang`.
set -eu
out="${1:-build/fixtures}"
mkdir -p "$out"
here="$(cd "$(dirname "$0")/.." && pwd)"

if command -v zig >/dev/null 2>&1; then
    ZIG="zig"
elif python3 -c "import ziglang" >/dev/null 2>&1; then
    ZIG="python3 -m ziglang"
else
    echo "build-hello: zig not found (install zig or: pip install ziglang); skipping" >&2
    exit 0
fi

# Image base 0x20000000 is free both normally and under ASan (the usual
# Windows default 0x140000000 sits in ASan's shadow gap). These objects are
# RIP-relative and may ship with an empty relocation directory, so they have
# to actually land on ImageBase.
$ZIG cc -target x86_64-windows-gnu -O2 -fno-stack-protector -c \
    -o "$out/hello-real.obj" "$here/tests/fixtures/src/hello.c"
$ZIG cc -target x86_64-windows-gnu -nostdlib \
    -Wl,--image-base,0x20000000 \
    -Wl,--entry=start -Wl,--subsystem,console \
    -o "$out/hello-real.exe" "$out/hello-real.obj" -lkernel32
rm -f "$out/hello-real.obj"

$ZIG cc -target x86_64-windows-gnu -O2 -fno-stack-protector -c \
    -o "$out/hello-m1-real.obj" "$here/tests/fixtures/src/hello_m1.c"
$ZIG cc -target x86_64-windows-gnu -nostdlib \
    -Wl,--image-base,0x20000000 \
    -Wl,--entry=start -Wl,--subsystem,console \
    -o "$out/hello-m1-real.exe" "$out/hello-m1-real.obj" -lkernel32
rm -f "$out/hello-m1-real.obj"

# M2 CRT-less guests. Bases stay in the low range that ASan leaves free.
build_m2() {
    src="$1"
    dest="$2"
    base="$3"
    $ZIG cc -target x86_64-windows-gnu -O2 -fno-stack-protector -c \
        -o "$out/$dest.obj" "$here/tests/fixtures/src/$src"
    $ZIG cc -target x86_64-windows-gnu -nostdlib \
        -Wl,--image-base,"$base" \
        -Wl,--entry=start -Wl,--subsystem,console \
        -o "$out/$dest" "$out/$dest.obj" -lkernel32
    rm -f "$out/$dest.obj"
}
build_m2 args_m2.c  args-m2-real.exe  0x21000000
build_m2 env_m2.c   env-m2-real.exe   0x22000000
build_m2 mem_m2.c   mem-m2-real.exe   0x23000000
build_m2 heap_m2.c  heap-m2-real.exe  0x24000000
build_m2 file_m2.c  file-m2-real.exe  0x25000000
build_m2 timer_m2.c timer-m2-real.exe 0x26000000

# a normal CRT-linked exe and a DLL with exports + TLS (parse-only fixtures)
$ZIG cc -target x86_64-windows-gnu -O2 -o "$out/hello-crt.exe" "$here/tests/fixtures/src/hello_crt.c"
$ZIG cc -target x86_64-windows-gnu -O2 -shared -o "$out/tweakdll.dll" "$here/tests/fixtures/src/tweakdll.c"
rm -f "$out"/*.pdb "$out"/*.lib
rm -f "$out/hello-real.pdb" "$out/hello-m1-real.pdb"
echo "build-hello: wrote hello-real.exe, hello-m1-real.exe, M2 guests, hello-crt.exe, tweakdll.dll to $out"
