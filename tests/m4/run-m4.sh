#!/bin/sh
# Run TweakWin code on the real TweakKernel M4 under QEMU.
#
#   sh tests/m4/run-m4.sh [KERNEL_DIR]
#
# KERNEL_DIR is a TweakKernel checkout at v0.5.0-m4 (378bc548...). It is
# never modified: the tree is copied into build/m4/kernel, and only that
# copy is changed so its boot launches the TweakWin test image instead of
# the kernel's own acceptance processes. Skips (exit 0) when the kernel
# tree, QEMU, or OVMF is missing, unless TWEAKWIN_REQUIRE_M4=1.
set -eu
here="$(cd "$(dirname "$0")/../.." && pwd)"
kdir="${1:-${TWEAKKERNEL_DIR:-$here/../../tweakkernel}}"
want=378bc5480f87e000111afc7da61fdec81a8d9110
out="$here/build/m4"

skip() {
    echo "m4: skip: $*" >&2
    if [ "${TWEAKWIN_REQUIRE_M4:-0}" = 1 ]; then exit 1; fi
    exit 0
}

[ -f "$kdir/Makefile" ] && [ -f "$kdir/user/start.S" ] || skip "no TweakKernel tree at $kdir"
command -v qemu-system-x86_64 >/dev/null 2>&1 || skip "qemu-system-x86_64 not installed"
[ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] || [ -f /usr/share/ovmf/OVMF_CODE_4M.fd ] || [ -n "${OVMF_CODE:-}" ] || skip "OVMF not installed"
if [ -d "$kdir/.git" ]; then
    head=$(git -C "$kdir" rev-parse HEAD)
    [ "$head" = "$want" ] || skip "TweakKernel at $head, expected v0.5.0-m4 $want"
fi

rm -rf "$out"
mkdir -p "$out/kernel"
(cd "$kdir" && tar --exclude=./build --exclude=./.git -cf - .) | (cd "$out/kernel" && tar -xf -)
k="$out/kernel"

# The TweakWin image: TweakKernel's crt0 and link script, our code.
cflags="-std=c11 -ffreestanding -fno-stack-protector -mno-red-zone -mgeneral-regs-only -m64 \
 -fno-pic -fno-pie -fno-builtin -fno-asynchronous-unwind-tables -Wall -Wextra -Werror -O2"
mkdir -p "$k/build/user"
gcc $cflags -nostdlib -static -no-pie -Wl,-z,max-page-size=0x1000 -Wl,--build-id=none \
    -T "$k/user/user.ld" -o "$k/build/user/tweakwin_kb.elf" \
    "$k/user/start.S" "$here/tests/m4/kbtest_main.c" "$here/tests/backend/kb_conformance.c" \
    "$here/backend/kb_tweakkernel.c"

# Boot only the TweakWin image (copy only).
python3 - "$k" <<'PY'
import pathlib, re, sys
k = pathlib.Path(sys.argv[1])
acc = k / "kernel/core/accept.c"
s = acc.read_text()
s = s.replace("int accept_boot(void) {",
    "extern const unsigned char user_tweakwin_kb_elf[];\n"
    "extern const unsigned int user_tweakwin_kb_elf_len;\n"
    "int accept_boot(void) {\n"
    "    if (!proc_create(\"tweakwin-kb\", user_tweakwin_kb_elf, user_tweakwin_kb_elf_len, 0, -1)) return -1;\n"
    "    return 0;\n", 1)
acc.write_text(s)
mk = k / "Makefile"
m = mk.read_text()
m = m.replace("$(M3_IMAGES) $(M4_IMAGES) scripts/embed_user.py", "$(M3_IMAGES) $(M4_IMAGES) $(BUILD)/user/tweakwin_kb.elf scripts/embed_user.py", 1)
m = m.replace("$(BUILD)/user/m2hold.elf $(M3_IMAGES) $(M4_IMAGES)\n", "$(BUILD)/user/m2hold.elf $(M3_IMAGES) $(M4_IMAGES) $(BUILD)/user/tweakwin_kb.elf\n", 1)
mk.write_text(m)
PY
grep -q tweakwin_kb "$k/Makefile" || { echo "m4: could not patch the kernel copy's Makefile" >&2; exit 1; }

make -C "$k" -s all >"$out/build.log" 2>&1 || { tail -40 "$out/build.log" >&2; exit 1; }

code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
[ -f "$code" ] || code=/usr/share/ovmf/OVMF_CODE_4M.fd
vars=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
[ -f "$vars" ] || vars=/usr/share/ovmf/OVMF_VARS_4M.fd
cp "$vars" "$out/OVMF_VARS.fd"
log="$out/serial.log"
set +e
timeout "${QEMU_TIMEOUT:-60}" qemu-system-x86_64 -machine q35 -m 512M -smp 1 -cpu qemu64 \
    -no-reboot -no-shutdown -display none -vga std -nic none \
    -drive if=pflash,format=raw,readonly=on,file="$code" \
    -drive if=pflash,format=raw,file="$out/OVMF_VARS.fd" \
    -device qemu-xhci,id=xhci -drive id=disk,if=none,format=raw,file="$k/build/disk.img" \
    -device usb-storage,drive=disk,bootindex=0 -serial file:"$log" &
qpid=$!
i=0
while [ $i -lt "${QEMU_TIMEOUT:-60}" ]; do
    sleep 1
    i=$((i + 1))
    if grep -q -e "${M4_DONE_MARKER:-TWEAKWIN_M4_KB_OK}" -e "tweakwin-m4: FAIL" -e "PANIC" "$log" 2>/dev/null; then
        sleep 1
        break
    fi
done
kill $qpid 2>/dev/null
wait $qpid 2>/dev/null
set -e
grep -a -e "tweakwin" -e "kb:" -e "TWEAKWIN" -e "PANIC" -e "proc: fault" "$log" | sed 's/^/  /' || true
if grep -q "${M4_DONE_MARKER:-TWEAKWIN_M4_KB_OK}" "$log" && ! grep -q -e "kb: FAIL" -e "tweakwin-m4: FAIL" -e "PANIC" "$log"; then
    echo "m4: TweakWin backend conformance passed on TweakKernel v0.5.0-m4"
    exit 0
fi
echo "m4: FAILED (serial log: $log)" >&2
tail -30 "$log" >&2
exit 1
