# TweakWin build
#
#   make              build build/tweakwin
#   make test         unit + integration + sanitizer mutation sweep
#   make fuzz         libFuzzer run on the PE parser (clang), FUZZ_TIME seconds
#   make hello        build tests/fixtures/src/hello*.c with zig cc (optional)
#   make m4           run TweakWin code on TweakKernel v0.5.0-m4 under QEMU
#                     (TWEAKKERNEL_DIR=..., skips when the kernel/QEMU are absent)
#   make install      install to $(DESTDIR)$(PREFIX)/bin/tweakwin
#   make clean

CC      ?= cc
PREFIX  ?= /usr/local
PYTHON  ?= python3
FUZZ_TIME ?= 60
DESTDIR ?=

WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Werror
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_POSIX_C_SOURCE=200809L -fstack-protector-strong -D_FORTIFY_SOURCE=2 $(WARN)
SANFLAGS := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

B := build

BACKEND_SRC := backend/kb_host.c
NT_SRC := nt/status.c nt/sync.c
RT_SRC := rt/mem.c rt/teb.c rt/tls.c rt/object.c rt/thread.c rt/seh.c rt/run.c
LIB_SRC := $(BACKEND_SRC) $(NT_SRC) $(RT_SRC) common/arena.c common/debug.c \
           loader/pe/pe.c loader/pe/pe_names.c \
           loader/load.c \
           runtime/modules.c runtime/vmem.c runtime/handle.c runtime/process.c \
           runtime/gueststr.c runtime/utf.c runtime/winfs.c runtime/registry.c \
           kernel32/kernel32.c kernel32/k32_file.c kernel32/k32_mem.c kernel32/k32_proc.c \
           kernel32/k32_sync.c kernel32/k32_thread.c kernel32/k32_tls.c kernel32/k32_exc.c \
           kernel32/k32_module.c kernel32/k32_fs.c advapi32/advapi32.c
CLI_SRC := cli/main.c cli/inspect.c cli/run.c
HDRS    := $(wildcard backend/*.h rt/*.h nt/*.h common/*.h loader/*.h loader/pe/*.h runtime/*.h kernel32/*.h advapi32/*.h cli/*.h include/tweakwin/*.h)

.PHONY: all test unit integration sweep fixtures fuzz hello install installcheck clean m4 kbcheck

all: $(B)/tweakwin

$(B):
	mkdir -p $(B)

$(B)/tweakwin: $(LIB_SRC) $(CLI_SRC) $(HDRS) | $(B)
	$(CC) $(CFLAGS) -o $@ $(LIB_SRC) $(CLI_SRC) $(LDFLAGS) -lpthread

# The TweakKernel backend must stay freestanding and link-clean even though
# it only runs inside TweakKernel (tests/m4/).
$(B)/kb_tweakkernel.o: backend/kb_tweakkernel.c backend/kb.h backend/kb_m4_abi.h | $(B)
	$(CC) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -mno-red-zone -O2 $(WARN) -c -o $@ $<
	@if nm $@ | grep -q ' U '; then echo "kb_tweakkernel.o has undefined symbols:"; nm $@ | grep ' U '; exit 1; fi

kbcheck: $(B)/kb_tweakkernel.o

$(B)/test_kb: tests/backend/kb_conformance.c tests/backend/kb_host_main.c $(BACKEND_SRC) backend/kb.h | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/backend/kb_conformance.c tests/backend/kb_host_main.c $(BACKEND_SRC) -lpthread

m4:
	sh tests/m4/run-m4.sh $(TWEAKKERNEL_DIR)

# sanitizer builds used by the test suite
$(B)/tweakwin-asan: $(LIB_SRC) $(CLI_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ $(LIB_SRC) $(CLI_SRC) -lpthread

$(B)/test_pe: tests/unit/test_pe.c $(LIB_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_pe.c $(LIB_SRC) -lpthread

$(B)/test_loader: tests/unit/test_loader.c $(LIB_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_loader.c $(LIB_SRC) -lpthread

$(B)/test_m4ns: tests/unit/test_m4ns.c runtime/winfs.c runtime/registry.c runtime/utf.c $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_m4ns.c runtime/winfs.c runtime/registry.c runtime/utf.c

$(B)/test_nt: tests/unit/test_nt.c nt/status.c backend/kb.h nt/status.h nt/ntstatus.h | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_nt.c nt/status.c

$(B)/test_rt: tests/unit/test_rt.c $(BACKEND_SRC) $(RT_SRC) $(LIB_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_rt.c $(LIB_SRC) -lpthread

$(B)/test_seh: tests/unit/test_seh.c $(LIB_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_seh.c $(LIB_SRC) -lpthread

$(B)/test_abi: tests/unit/test_abi.c runtime/winapi.h | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_abi.c

$(B)/test_runtime: tests/unit/test_runtime.c $(LIB_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/unit/test_runtime.c $(LIB_SRC) -lpthread

$(B)/sweep: tests/fuzz/sweep.c $(LIB_SRC) $(HDRS) | $(B)
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(SANFLAGS) -o $@ tests/fuzz/sweep.c $(LIB_SRC) -lpthread

fixtures: | $(B)
	$(PYTHON) tools/mkpe.py $(B)/fixtures
	sh tools/build-hello.sh $(B)/fixtures
	sh tools/build-pe.sh $(B)/fixtures

unit: $(B)/test_kb kbcheck $(B)/test_nt $(B)/test_rt $(B)/test_seh $(B)/test_pe $(B)/test_loader $(B)/test_abi $(B)/test_runtime $(B)/test_m4ns fixtures
	$(B)/test_kb
	TWEAKWIN_KB_LIMITS=m4 $(B)/test_kb
	$(B)/test_nt
	$(B)/test_rt
	$(B)/test_seh
	$(B)/test_pe $(B)/fixtures
	$(B)/test_loader $(B)/fixtures
	$(B)/test_abi
	$(B)/test_runtime $(B)/fixtures
	$(B)/test_m4ns

integration: $(B)/tweakwin $(B)/tweakwin-asan fixtures
	$(PYTHON) tests/integration/test_cli.py $(B)/tweakwin-asan $(B)/fixtures
	$(PYTHON) tests/integration/test_cli.py $(B)/tweakwin $(B)/fixtures
	$(PYTHON) tests/integration/test_m3.py $(B)/tweakwin-asan $(B)/fixtures
	$(PYTHON) tests/integration/test_m3.py $(B)/tweakwin $(B)/fixtures
	$(PYTHON) tests/integration/test_m4.py $(B)/tweakwin-asan $(B)/fixtures
	$(PYTHON) tests/integration/test_m4.py $(B)/tweakwin $(B)/fixtures

sweep: $(B)/sweep fixtures
	$(B)/sweep $(B)/fixtures/hello.exe $(B)/fixtures/tweaktest.dll

test: unit integration sweep installcheck
	@echo "all tests passed"

$(B)/fuzz_pe: tests/fuzz/fuzz_pe.c $(LIB_SRC) $(HDRS) | $(B)
	clang -std=c11 -D_POSIX_C_SOURCE=200809L -g -O1 -fsanitize=fuzzer,address,undefined -o $@ tests/fuzz/fuzz_pe.c $(LIB_SRC)

fuzz: $(B)/fuzz_pe fixtures
	mkdir -p $(B)/corpus
	cp $(B)/fixtures/*.exe $(B)/fixtures/*.dll $(B)/corpus/
	$(B)/fuzz_pe -max_total_time=$(FUZZ_TIME) -max_len=65536 $(B)/corpus

hello: | $(B)
	sh tools/build-hello.sh $(B)/fixtures

install: $(B)/tweakwin
	install -Dm755 $(B)/tweakwin $(DESTDIR)$(PREFIX)/bin/tweakwin

installcheck: $(B)/tweakwin
	rm -rf $(B)/destdir
	$(MAKE) install DESTDIR=$(abspath $(B)/destdir) PREFIX=/usr
	test -x $(B)/destdir/usr/bin/tweakwin
	test $$(find $(B)/destdir -type f | wc -l) -eq 1
	@echo "installcheck: /usr/bin/tweakwin only"

clean:
	rm -rf $(B)
