#!/usr/bin/env python3
"""
Generate synthetic PE32+ test fixtures for TweakWin's parser tests.

Everything is built byte-by-byte from the published PE/COFF layout; no
compiler or Windows SDK needed. These images are for PARSER tests only:
the code sections contain placeholder bytes and are not meant to be run.

Usage: mkpe.py OUTDIR

Writes:
  hello.exe          console exe: KERNEL32 imports, .pdata, DIR64 relocs
                     (parser fixture; .text is a placeholder, not runnable)
  tweaktest.dll      DLL: exports (named/ordinal/forwarder), TLS callbacks,
                     delay imports, ordinal import, resources
  hello-m1.exe       runnable M1 console PE (real x86-64, no CRT)
  exit42.exe         runnable; ExitProcess(42)
  load/*.exe         loader error fixtures (parse as valid PE32+)
  bad/*.exe|*.dll    malformed and unsupported variants
  bad/manifest.tsv   name <TAB> expected exit code <TAB> expected substring
"""

import os
import struct
import sys

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

SCN_CODE = 0x00000020
SCN_IDATA = 0x00000040
SCN_UDATA = 0x00000080
SCN_X = 0x20000000
SCN_R = 0x40000000
SCN_W = 0x80000000

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION = 0, 1, 2, 3
DIR_BASERELOC, DIR_TLS, DIR_IAT, DIR_DELAY = 5, 9, 12, 13


def align(v, a):
    return (v + a - 1) & ~(a - 1)


class Section:
    def __init__(self, name, rva, chars):
        self.name = name
        self.rva = rva
        self.chars = chars
        self.data = bytearray()
        self.vsize = None

    def here(self, alignment=1):
        pad = align(len(self.data), alignment) - len(self.data)
        self.data += b"\0" * pad
        return self.rva + len(self.data)

    def put(self, blob, alignment=1):
        rva = self.here(alignment)
        self.data += blob
        return rva


class Layout:
    """Remembers where interesting header fields landed, for patching."""
    pass


def build_pe(sections, *, image_base, entry, subsystem, characteristics, dll_chars, dirs,
             machine=0x8664, magic=0x20B):
    lay = Layout()
    lfanew = 0x80
    ndirs = 16
    opt_size = 112 + ndirs * 8
    nsec = len(sections)
    hdr_end = lfanew + 4 + 20 + opt_size + 40 * nsec
    size_of_headers = align(hdr_end, FILE_ALIGN)

    raw_ptr = size_of_headers
    placed = []
    for s in sections:
        vsize = s.vsize if s.vsize is not None else len(s.data)
        raw_size = align(len(s.data), FILE_ALIGN) if s.data else 0
        placed.append((s, vsize, raw_ptr if raw_size else 0, raw_size))
        raw_ptr += raw_size
    size_of_image = align(max(s.rva + max(v, 1) for s, v, _, _ in placed), SECT_ALIGN)

    out = bytearray(raw_ptr)
    # DOS header + stub
    out[0:2] = b"MZ"
    struct.pack_into("<H", out, 2, 0x90)
    struct.pack_into("<I", out, 0x3C, lfanew)
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    out[0x40:0x40 + len(stub)] = stub

    out[lfanew:lfanew + 4] = b"PE\0\0"
    coff = lfanew + 4
    struct.pack_into("<HHIIIHH", out, coff, machine, nsec, 0, 0, 0, opt_size, characteristics)
    lay.coff = coff

    opt = coff + 20
    lay.opt = opt
    size_of_code = sum(r for s, _, _, r in placed if s.chars & SCN_CODE)
    size_of_idata = sum(r for s, _, _, r in placed if s.chars & SCN_IDATA)
    struct.pack_into("<HBBIIIII", out, opt, magic, 14, 38, size_of_code, size_of_idata, 0, entry, 0x1000)
    struct.pack_into("<QII", out, opt + 24, image_base, SECT_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHHI", out, opt + 40, 6, 0, 0, 0, 6, 0, 0)
    struct.pack_into("<III", out, opt + 56, size_of_image, size_of_headers, 0)
    struct.pack_into("<HH", out, opt + 68, subsystem, dll_chars)
    struct.pack_into("<QQQQ", out, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", out, opt + 104, 0, ndirs)
    for idx, (rva, size) in dirs.items():
        struct.pack_into("<II", out, opt + 112 + idx * 8, rva, size)

    sec_tab = opt + opt_size
    lay.sec_tab = sec_tab
    lay.sections = {}
    for i, (s, vsize, rp, rs) in enumerate(placed):
        h = sec_tab + i * 40
        name = s.name.encode()[:8].ljust(8, b"\0")
        struct.pack_into("<8sIIIIIIHHI", out, h, name, vsize, s.rva, rs, rp, 0, 0, 0, 0, s.chars)
        if rs:
            out[rp:rp + len(s.data)] = s.data
        lay.sections[s.name] = (h, rp)
    lay.size_of_image = size_of_image
    return out, lay


# ---------------------------------------------------------------- builders

def c_str(s):
    return s.encode() + b"\0"


def build_imports(sec, dlls):
    """dlls: [(name, [str | int])] -> (dir_rva, dir_size, iat_rva, iat_size, info)
    Layout: descriptors, then per-dll INT, IAT, then hint/name and DLL names."""
    ndesc = len(dlls) + 1
    desc_rva = sec.here(4)
    sec.data += b"\0" * (20 * ndesc)
    iat_start = None
    info = {}
    thunk_rvas = []
    for name, fns in dlls:
        int_rva = sec.put(b"\0" * (8 * (len(fns) + 1)), 8)
        iat_rva = sec.put(b"\0" * (8 * (len(fns) + 1)), 8)
        if iat_start is None:
            iat_start = iat_rva
        thunk_rvas.append((int_rva, iat_rva))
        info[name] = {"int": int_rva, "iat": iat_rva}
    iat_end = sec.here()
    for i, (name, fns) in enumerate(dlls):
        int_rva, iat_rva = thunk_rvas[i]
        for j, fn in enumerate(fns):
            if isinstance(fn, int):
                val = (1 << 63) | fn
            else:
                val = sec.put(struct.pack("<H", 0) + c_str(fn), 2)
            for base in (int_rva, iat_rva):
                off = base - sec.rva + j * 8
                struct.pack_into("<Q", sec.data, off, val)
        name_rva = sec.put(c_str(name))
        info[name]["name"] = name_rva
        d = desc_rva - sec.rva + i * 20
        struct.pack_into("<IIIII", sec.data, d, int_rva, 0, 0, name_rva, iat_rva)
    info["_desc"] = desc_rva
    return desc_rva, 20 * ndesc, iat_start, iat_end - iat_start, info


def build_exports(sec, dll_name, base, funcs):
    """funcs: list indexed by ordinal-base; each is None or (name|None, rva|None, forwarder|None)."""
    start = sec.here(4)
    nfunc = len(funcs)
    named = sorted([(f[0], i) for i, f in enumerate(funcs) if f and f[0]], key=lambda t: t[0].encode())
    dir_off = len(sec.data)
    sec.data += b"\0" * 40
    eat = sec.put(b"\0" * (4 * nfunc), 4)
    ent = sec.put(b"\0" * (4 * len(named)), 4)
    eot = sec.put(b"\0" * (2 * len(named)), 2)
    name_rva = sec.put(c_str(dll_name))
    for i, f in enumerate(funcs):
        if not f:
            continue
        _, rva, fwd = f
        if fwd:
            rva = sec.put(c_str(fwd))
        struct.pack_into("<I", sec.data, eat - sec.rva + 4 * i, rva)
    for k, (n, idx) in enumerate(named):
        nrva = sec.put(c_str(n))
        struct.pack_into("<I", sec.data, ent - sec.rva + 4 * k, nrva)
        struct.pack_into("<H", sec.data, eot - sec.rva + 2 * k, idx)
    size = sec.here() - start
    struct.pack_into("<IIHHIIIIIII", sec.data, dir_off, 0, 0, 0, 0, name_rva, base, nfunc, len(named), eat, ent, eot)
    return start, size, {"eat": eat, "ent": ent, "eot": eot, "dir": start}


def build_relocs(sec, targets):
    start = sec.here(4)
    pages = {}
    for t in sorted(targets):
        pages.setdefault(t & ~0xFFF, []).append(t & 0xFFF)
    info = []
    for page, offs in sorted(pages.items()):
        entries = [(10 << 12) | o for o in offs]
        if len(entries) % 2:
            entries.append(0)  # IMAGE_REL_BASED_ABSOLUTE padding
        block_rva = sec.here()
        blob = struct.pack("<II", page, 8 + 2 * len(entries)) + b"".join(struct.pack("<H", e) for e in entries)
        sec.data += blob
        info.append(block_rva)
    return start, sec.here() - start, info


def build_resources(sec):
    """root: named type "TWEAK" + id type 16 (VERSION); each -> id 1 -> lang 0x409 -> data."""
    base = sec.here(4)
    buf = bytearray()

    def dir_hdr(named, ids):
        return struct.pack("<IIHHHH", 0, 0, 0, 0, named, ids)

    # offsets (relative to base) laid out by hand
    ROOT = 0
    T1 = ROOT + 16 + 2 * 8          # "TWEAK" name-level dir
    T1L = T1 + 16 + 8               # lang-level dir
    T2 = T1L + 16 + 8               # VERSION name-level dir
    T2L = T2 + 16 + 8
    DE1 = T2L + 16 + 8              # data entries
    DE2 = DE1 + 16
    NAME = DE2 + 16                 # UTF-16 "TWEAK"
    name_blob = struct.pack("<H", 5) + "TWEAK".encode("utf-16-le")
    DATA1 = align(NAME + len(name_blob), 4)
    data1 = b"TweakWin resource payload\0"
    DATA2 = align(DATA1 + len(data1), 4)
    data2 = b"\0" * 64

    buf += dir_hdr(1, 1)
    buf += struct.pack("<II", 0x80000000 | NAME, 0x80000000 | T1)
    buf += struct.pack("<II", 16, 0x80000000 | T2)
    buf += dir_hdr(0, 1) + struct.pack("<II", 1, 0x80000000 | T1L)
    buf += dir_hdr(0, 1) + struct.pack("<II", 0x409, DE1)
    buf += dir_hdr(0, 1) + struct.pack("<II", 1, 0x80000000 | T2L)
    buf += dir_hdr(0, 1) + struct.pack("<II", 0x409, DE2)
    assert len(buf) == DE1
    buf += struct.pack("<IIII", base + DATA1, len(data1), 0, 0)
    buf += struct.pack("<IIII", base + DATA2, len(data2), 0, 0)
    buf += name_blob
    buf += b"\0" * (DATA1 - len(buf)) + data1
    buf += b"\0" * (DATA2 - len(buf)) + data2
    sec.data += buf
    return base, len(buf), {"root": base}


# ---------------------------------------------------------------- fixtures

def make_hello():
    base = 0x140000000
    text = Section(".text", 0x1000, SCN_CODE | SCN_X | SCN_R)
    rdata = Section(".rdata", 0x2000, SCN_IDATA | SCN_R)
    data = Section(".data", 0x3000, SCN_IDATA | SCN_R | SCN_W)
    pdata = Section(".pdata", 0x4000, SCN_IDATA | SCN_R)
    reloc = Section(".reloc", 0x5000, SCN_IDATA | SCN_R | 0x02000000)

    text.data += b"\x31\xc0\xc3" + b"\xcc" * 13  # placeholder: xor eax,eax; ret

    imp_rva, imp_size, iat_rva, iat_size, imp = build_imports(
        rdata, [("KERNEL32.dll", ["GetStdHandle", "WriteFile", "ExitProcess"])])
    msg_rva = rdata.put(b"Hello from TweakWin!\r\n\0")
    unwind_rva = rdata.put(b"\x01\x00\x00\x00", 4)

    data.data += struct.pack("<QQ", base + msg_rva, 0)
    pdata.data += struct.pack("<III", 0x1000, 0x1003, unwind_rva)
    rel_rva, rel_size, rel_blocks = build_relocs(reloc, [0x3000])

    dirs = {
        DIR_IMPORT: (imp_rva, imp_size),
        DIR_EXCEPTION: (0x4000, 12),
        DIR_BASERELOC: (rel_rva, rel_size),
        DIR_IAT: (iat_rva, iat_size),
    }
    img, lay = build_pe([text, rdata, data, pdata, reloc], image_base=base, entry=0x1000, subsystem=3,
                        characteristics=0x0022, dll_chars=0x8160, dirs=dirs)
    meta = {"imp": imp, "rel_blocks": rel_blocks, "reloc_sec": reloc, "rdata": rdata}
    return img, lay, meta


def make_dll():
    base = 0x180000000
    text = Section(".text", 0x1000, SCN_CODE | SCN_X | SCN_R)
    rdata = Section(".rdata", 0x2000, SCN_IDATA | SCN_R)
    data = Section(".data", 0x3000, SCN_IDATA | SCN_R | SCN_W)
    tls = Section(".tls", 0x4000, SCN_IDATA | SCN_R | SCN_W)
    rsrc = Section(".rsrc", 0x5000, SCN_IDATA | SCN_R)
    reloc = Section(".reloc", 0x6000, SCN_IDATA | SCN_R | 0x02000000)

    text.data += (b"\xb8\x01\x00\x00\x00\xc3" + b"\xcc" * 10) * 4  # placeholders at 0x1000/10/20/30

    imp_rva, imp_size, iat_rva, iat_size, imp = build_imports(
        rdata, [("KERNEL32.dll", ["GetTickCount"]), ("WS2_32.dll", [115])])

    exp_rva, exp_size, exp = build_exports(rdata, "tweaktest.dll", 1, [
        ("Alpha", 0x1000, None),
        ("Beta", 0x1010, None),
        None,
        (None, 0x1020, None),
        ("Gamma", None, "KERNEL32.GetTickCount"),
    ])

    # TLS: template in .tls, index in .data, callbacks array in .rdata
    tls.data += b"TLS-TEMPLATE-DAT"
    tls_index_rva = data.put(b"\0" * 8, 8)
    cb_rva = rdata.put(struct.pack("<QQQ", base + 0x1020, base + 0x1030, 0), 8)
    tls_dir_rva = rdata.put(struct.pack("<QQQQII", base + 0x4000, base + 0x4010, base + tls_index_rva,
                                        base + cb_rva, 0x10, 0x00500000), 8)

    # delay import: USER32.dll!MessageBoxW
    dl_handle = data.put(b"\0" * 8, 8)
    dl_iat = data.put(b"\0" * 16, 8)
    dl_int = rdata.put(b"\0" * 16, 8)
    dl_hn = rdata.put(struct.pack("<H", 0) + c_str("MessageBoxW"), 2)
    struct.pack_into("<Q", rdata.data, dl_int - rdata.rva, dl_hn)
    dl_name = rdata.put(c_str("USER32.dll"))
    dl_desc = rdata.put(struct.pack("<IIIIIIII", 1, dl_name, dl_handle, dl_iat, dl_int, 0, 0, 0) + b"\0" * 32, 4)

    rs_rva, rs_size, rs = build_resources(rsrc)

    reloc_targets = [cb_rva, cb_rva + 8, tls_dir_rva, tls_dir_rva + 8, tls_dir_rva + 16, tls_dir_rva + 24]
    rel_rva, rel_size, _ = build_relocs(reloc, reloc_targets)

    dirs = {
        DIR_EXPORT: (exp_rva, exp_size),
        DIR_IMPORT: (imp_rva, imp_size),
        DIR_RESOURCE: (rs_rva, rs_size),
        DIR_BASERELOC: (rel_rva, rel_size),
        DIR_TLS: (tls_dir_rva, 40),
        DIR_IAT: (iat_rva, iat_size),
        DIR_DELAY: (dl_desc, 64),
    }
    img, lay = build_pe([text, rdata, data, tls, rsrc, reloc], image_base=base, entry=0x1000, subsystem=2,
                        characteristics=0x2022, dll_chars=0x0160, dirs=dirs)
    meta = {"exp": exp, "cb_rva": cb_rva, "rsrc": rs, "rdata": rdata, "dl_desc": dl_desc}
    return img, lay, meta


# ---------------------------------------------------------------- executable M1 fixtures
# These contain real x86-64 instructions and ARE meant to be run by the loader.
# Parser-only fixtures (hello.exe, tweaktest.dll) stay above and must not be executed.


class Code:
    def __init__(self, rva):
        self.rva = rva
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []

    def here(self):
        return self.rva + len(self.buf)

    def emit(self, blob):
        self.buf += blob

    def label(self, name):
        self.labels[name] = len(self.buf)

    def rel8(self, name):
        self.fixups.append((len(self.buf), name))
        self.emit(b"\x00")

    def link(self):
        for pos, name in self.fixups:
            disp = self.labels[name] - (pos + 1)
            if not -128 <= disp <= 127:
                raise SystemExit(f"mkpe: rel8 {name} out of range ({disp})")
            self.buf[pos] = disp & 0xFF

    def call_mem(self, target_rva):
        # FF 15 disp32    call qword [rip+disp]
        disp = target_rva - (self.here() + 6)
        self.emit(b"\xFF\x15" + struct.pack("<i", disp))

    def mov_rdx_mem(self, target_rva):
        # 48 8B 15 disp32   mov rdx, [rip+disp]
        disp = target_rva - (self.here() + 7)
        self.emit(b"\x48\x8B\x15" + struct.pack("<i", disp))

    def lea_r9(self, target_rva):
        # 4C 8D 0D disp32   lea r9, [rip+disp]
        disp = target_rva - (self.here() + 7)
        self.emit(b"\x4C\x8D\x0D" + struct.pack("<i", disp))

    def rip(self, opcode, target_rva):
        disp = target_rva - (self.here() + len(opcode) + 4)
        self.emit(opcode + struct.pack("<i", disp))


def make_hello_m1(*, exit_code=0, message=b"Hello from TweakWin M1\r\n"):
    """Runnable console PE: GetStdHandle / WriteFile / ExitProcess.

    ImageBase is 0x20000000, not the usual 0x140000000. Both are valid;
    0x140000000 sits inside AddressSanitizer's reserved shadow gap, so a
    preferred-base test could never succeed under `make test`. The loader
    itself still accepts any free ImageBase, including 0x140000000.

    .data[0] holds the VA of the message (DIR64 reloc) so loading away from
    ImageBase is observable. The WriteFile 'written' out-param lives in the
    virtual tail past SizeOfRawData (BSS / zero-fill).
    """
    base = 0x20000000
    text = Section(".text", 0x1000, SCN_CODE | SCN_X | SCN_R)
    rdata = Section(".rdata", 0x2000, SCN_IDATA | SCN_R)
    data = Section(".data", 0x3000, SCN_IDATA | SCN_R | SCN_W)
    reloc = Section(".reloc", 0x4000, SCN_IDATA | SCN_R | 0x02000000)

    fns = ["GetStdHandle", "WriteFile", "ExitProcess"]
    imp_rva, imp_size, iat_rva, iat_size, imp = build_imports(rdata, [("KERNEL32.dll", fns)])
    msg_rva = rdata.put(message) if message else None

    iat_gsh = imp["KERNEL32.dll"]["iat"] + 0
    iat_wf = imp["KERNEL32.dll"]["iat"] + 8
    iat_ep = imp["KERNEL32.dll"]["iat"] + 16

    msg_va_rva = data.put(struct.pack("<Q", base + msg_rva if msg_rva is not None else 0), 8)
    data.vsize = 0x800  # BSS tail past the 0x200 file-aligned raw size
    written_rva = 0x3000 + 0x400

    c = Code(0x1000)
    c.emit(b"\x48\x83\xEC\x28")          # sub rsp, 0x28
    if message:
        c.emit(b"\xB9\xF5\xFF\xFF\xFF")  # mov ecx, -11  (STD_OUTPUT_HANDLE)
        c.call_mem(iat_gsh)
        c.emit(b"\x48\x89\xC1")          # mov rcx, rax
        c.mov_rdx_mem(msg_va_rva)
        c.emit(b"\x41\xB8" + struct.pack("<I", len(message)))  # mov r8d, msglen
        c.lea_r9(written_rva)
        c.emit(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")  # mov qword [rsp+20h], 0
        c.call_mem(iat_wf)
    c.emit(b"\xB9" + struct.pack("<I", exit_code))  # mov ecx, exit_code
    c.call_mem(iat_ep)
    c.emit(b"\xCC")
    text.data += c.buf

    rel_rva, rel_size, rel_blocks = build_relocs(reloc, [msg_va_rva])
    dirs = {
        DIR_IMPORT: (imp_rva, imp_size),
        DIR_BASERELOC: (rel_rva, rel_size),
        DIR_IAT: (iat_rva, iat_size),
    }
    img, lay = build_pe([text, rdata, data, reloc], image_base=base, entry=0x1000, subsystem=3,
                        characteristics=0x0022, dll_chars=0x8160, dirs=dirs)
    meta = {
        "imp": imp,
        "rdata": rdata,
        "reloc_sec": reloc,
        "rel_blocks": rel_blocks,
        "msg_va_rva": msg_va_rva,
        "msg_rva": msg_rva,
        "written_rva": written_rva,
        "iat_rva": iat_rva,
    }
    return img, lay, meta


def make_exit42():
    return make_hello_m1(exit_code=42, message=None)


def m1_variants(hello, hlay, hmeta):
    """Loader-specific fixtures. They parse as valid PE32+."""
    out = []

    def patch(src, off, fmt, *vals):
        b = bytearray(src)
        struct.pack_into(fmt, b, off, *vals)
        return b

    H = hello
    imp = hmeta["imp"]
    rd = hmeta["rdata"]

    # unknown DLL: rewrite KERNEL32.dll -> NOSUCH32.dll (same length)
    name_off = rva_to_off(hlay, ".rdata", rd.rva, imp["KERNEL32.dll"]["name"])
    b = bytearray(H)
    b[name_off:name_off + len("KERNEL32.dll")] = b"NOSUCH32.dll"
    out.append(("unknown-dll.exe", bytes(b)))

    int_rva = imp["KERNEL32.dll"]["int"]
    int_off = rva_to_off(hlay, ".rdata", rd.rva, int_rva)
    ep_thunk = struct.unpack_from("<Q", H, int_off + 16)[0]
    hn_off = rva_to_off(hlay, ".rdata", rd.rva, ep_thunk)
    b = bytearray(H)
    b[hn_off + 2:hn_off + 2 + len("ExitProcess")] = b"NoSuchProcX"
    out.append(("unknown-sym.exe", bytes(b)))

    # HIGHLOW reloc: parser warns, loader refuses to apply
    blk = rva_to_off(hlay, ".reloc", hmeta["reloc_sec"].rva, hmeta["rel_blocks"][0])
    out.append(("highlow-reloc.exe", bytes(patch(H, blk + 8, "<H", (3 << 12) | 0))))

    # entry point cleared: parser warns, loader refuses
    out.append(("entry-zero.exe", bytes(patch(H, hlay.opt + 16, "<I", 0))))

    # .text is no longer executable
    text_h, _ = hlay.sections[".text"]
    chars = struct.unpack_from("<I", H, text_h + 36)[0]
    out.append(("entry-nx.exe", bytes(patch(H, text_h + 36, "<I", chars & ~SCN_X))))

    # relocation directory removed; can run only at ImageBase
    out.append(("no-reloc.exe", bytes(patch(H, hlay.opt + 112 + 5 * 8, "<II", 0, 0))))

    return out

def rva_to_off(lay, sec_name, sec_rva, rva):
    _, raw = lay.sections[sec_name]
    return raw + (rva - sec_rva)


def variants(hello, hlay, hmeta, dll, dlay, dmeta):
    out = []

    def v(name, blob, code, needle):
        out.append((name, bytes(blob), code, needle))

    def patch(src, off, fmt, *vals):
        b = bytearray(src)
        struct.pack_into(fmt, b, off, *vals)
        return b

    H = hello
    coff, opt, st = hlay.coff, hlay.opt, hlay.sec_tab

    v("empty.exe", b"", 2, "too small")
    v("not-mz.exe", b"ZM" + H[2:], 2, "missing MZ")
    v("lfanew-oob.exe", patch(H, 0x3C, "<I", 0xFFFFFF00), 2, "e_lfanew")
    v("bad-pe-sig.exe", patch(H, coff - 4, "<I", 0x00004550 ^ 0x0101), 2, "missing PE signature")
    v("i386.exe", patch(H, coff, "<H", 0x014C), 3, "i386")
    v("arm64.exe", patch(H, coff, "<H", 0xAA64), 3, "arm64")
    v("pe32.exe", patch(H, opt, "<H", 0x010B), 3, "PE32 (32-bit)")
    v("no-opt-header.exe", patch(H, coff + 16, "<H", 0), 2, "no optional header")
    v("opt-truncated.exe", H[:opt + 40], 2, "optional header")
    v("not-executable.exe", patch(H, coff + 18, "<H", 0x0020), 2, "EXECUTABLE_IMAGE")
    v("too-many-sections.exe", patch(H, coff + 2, "<H", 200), 2, "too many sections")
    v("section-table-oob.exe", patch(H, coff + 2, "<H", 95), 2, "section table")
    v("file-align-npot.exe", patch(H, opt + 36, "<I", 0x300), 2, "not a power of two")
    v("sect-lt-file-align.exe", patch(H, opt + 32, "<I", 0x100), 2, "FileAlignment")
    v("zero-image-size.exe", patch(H, opt + 56, "<I", 0), 2, "SizeOfImage is zero")
    v("entry-oob.exe", patch(H, opt + 16, "<I", 0x100000), 2, "entry point")
    v("image-base-overflow.exe", patch(H, opt + 24, "<Q", 0xFFFFFFFFFFFFF000), 2, "overflows")

    text_h = st + 0 * 40
    rdata_h = st + 1 * 40
    data_h = st + 2 * 40
    v("raw-past-eof.exe", patch(H, data_h + 16, "<I", 0x100000), 2, "extends past end of file")
    v("section-overlap.exe", patch(H, rdata_h + 12, "<I", 0x1000), 2, "overlaps")
    v("section-misaligned.exe", patch(H, text_h + 12, "<I", 0x1004), 2, "not SectionAlignment-aligned")
    v("section-past-image.exe", patch(H, opt + 56, "<I", 0x3000), 2, "past SizeOfImage")
    v("section-over-headers.exe", patch(H, opt + 60, "<I", 0x1200), 2, "overlaps the headers")

    imp = hmeta["imp"]
    rd = hmeta["rdata"]
    desc_off = rva_to_off(hlay, ".rdata", rd.rva, imp["_desc"])
    v("import-dllname-oob.exe", patch(H, desc_off + 12, "<I", 0x7FFFFFF0), 2, "invalid DLL name")
    v("import-no-iat.exe", patch(H, desc_off + 16, "<I", 0), 2, "no import address table")
    int_off = rva_to_off(hlay, ".rdata", rd.rva, imp["KERNEL32.dll"]["int"])
    v("import-thunk-reserved.exe", patch(H, int_off, "<Q", 0x0000000100002000), 2, "reserved bits")
    v("import-hintname-oob.exe", patch(H, int_off, "<Q", 0x7FFFFFF0), 2, "out of bounds")
    # make the DLL name run to the end of .rdata's raw data without a NUL
    b = bytearray(H)
    name_off = rva_to_off(hlay, ".rdata", rd.rva, imp["KERNEL32.dll"]["name"])
    _, rdata_raw = hlay.sections[".rdata"]
    for i in range(name_off, rdata_raw + 0x200):
        b[i] = 0x41
    struct.pack_into("<I", b, rdata_h + 8, 0x200)  # VirtualSize == raw size, so no zero-fill terminator
    v("import-name-unterminated.exe", b, 2, "invalid DLL name")

    rel_sec = hmeta["reloc_sec"]
    blk = rva_to_off(hlay, ".reloc", rel_sec.rva, hmeta["rel_blocks"][0])
    v("reloc-zero-block.exe", patch(H, blk + 4, "<I", 0), 2, "invalid size")
    v("reloc-bad-type.exe", patch(H, blk + 8, "<H", (5 << 12) | 0x10), 2, "not valid for x86-64")
    v("reloc-target-oob.exe", patch(patch(H, blk, "<I", 0x5000), blk + 8, "<H", (10 << 12) | 0xFFC), 2,
      "outside the image")
    v("reloc-page-oob.exe", patch(H, blk, "<I", 0x10000000), 2, "outside the image")

    D = dll
    dd = dlay.opt + 112
    em = dmeta["exp"]
    drd = dmeta["rdata"]
    exp_off = rva_to_off(dlay, ".rdata", drd.rva, em["dir"])
    v("export-huge.dll", patch(D, exp_off + 20, "<I", 0x10000000), 2, "claims")
    eot_off = rva_to_off(dlay, ".rdata", drd.rva, em["eot"])
    v("export-bad-ordinal.dll", patch(D, eot_off, "<H", 99), 2, "maps to function index")
    eat_off = rva_to_off(dlay, ".rdata", drd.rva, em["eat"])
    v("export-rva-oob.dll", patch(D, eat_off, "<I", 0x7FFF0000), 2, "outside the image")
    cb_off = rva_to_off(dlay, ".rdata", drd.rva, dmeta["cb_rva"])
    v("tls-callback-oob.dll", patch(D, cb_off, "<Q", 0x1000), 2, "TLS callback VA")
    v("tls-dir-oob.dll", patch(D, dd + 9 * 8, "<I", 0x7FFFF000), 2, "TLS directory")
    dl_off = rva_to_off(dlay, ".rdata", drd.rva, dmeta["dl_desc"])
    v("delay-no-int.dll", patch(D, dl_off + 16, "<I", 0), 2, "no name table")
    v("delay-name-oob.dll", patch(D, dl_off + 4, "<I", 0x7FFFFFF0), 2, "invalid DLL name")

    # resource problems are warnings, not rejections
    root_off = rva_to_off(dlay, ".rsrc", 0x5000, dmeta["rsrc"]["root"])
    v("rsrc-loop.dll", patch(D, root_off + 16 + 12, "<I", 0x80000000), 0, "resource tree")
    v("rsrc-oob.dll", patch(D, root_off + 16 + 12, "<I", 0x80000000 | 0x7FFFFF00), 0, "resource tree")
    return out


def make_guest(image_base, imports, blobs, data_bytes, emit):
    """CRT-less console PE. RIP-relative, no relocation directory, fixed ImageBase."""
    text = Section(".text", 0x1000, SCN_CODE | SCN_X | SCN_R)
    rdata = Section(".rdata", 0x2000, SCN_IDATA | SCN_R)
    data = Section(".data", 0x3000, SCN_IDATA | SCN_R | SCN_W)
    imp_rva, imp_size, iat_rva, iat_size, imp = build_imports(rdata, [("KERNEL32.dll", imports)])
    placed = {}
    for name, blob in blobs.items():
        placed[name] = rdata.put(blob)
    data.put(b"\0" * data_bytes)
    iat = {}
    base = imp["KERNEL32.dll"]["iat"]
    for i, name in enumerate(imports):
        iat[name] = base + i * 8
    c = Code(0x1000)
    emit(c, iat, placed, 0x3000)
    c.link()
    text.data += c.buf
    dirs = {
        DIR_IMPORT: (imp_rva, imp_size),
        DIR_IAT: (iat_rva, iat_size),
    }
    img, _lay = build_pe([text, rdata, data], image_base=image_base, entry=0x1000, subsystem=3,
                         characteristics=0x0022, dll_chars=0x8160, dirs=dirs)
    return img


def _exit_imm(c, iat, code):
    c.emit(b"\xB9" + struct.pack("<I", code))
    c.call_mem(iat["ExitProcess"])


def _write_const(c, iat, msg_rva, msg_len, written_rva):
    c.emit(b"\xB9\xF5\xFF\xFF\xFF")
    c.call_mem(iat["GetStdHandle"])
    c.emit(b"\x48\x89\xC1")
    c.rip(b"\x48\x8D\x15", msg_rva)
    c.emit(b"\x41\xB8" + struct.pack("<I", msg_len))
    c.lea_r9(written_rva)
    c.emit(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")
    c.call_mem(iat["WriteFile"])


def emit_args(c, iat, blobs, data):
    c.emit(b"\x48\x83\xEC\x28")
    c.emit(b"\xB9\xF5\xFF\xFF\xFF")
    c.call_mem(iat["GetStdHandle"])
    c.emit(b"\x49\x89\xC4")
    c.call_mem(iat["GetCommandLineA"])
    c.emit(b"\x49\x89\xC5")
    c.emit(b"\x45\x31\xC0")
    c.label("len")
    c.emit(b"\x43\x80\x7C\x05\x00\x00")
    c.emit(b"\x74"); c.rel8("write")
    c.emit(b"\x41\xFF\xC0")
    c.emit(b"\xEB"); c.rel8("len")
    c.label("write")
    c.emit(b"\x4C\x89\xE1")
    c.emit(b"\x4C\x89\xEA")
    c.emit(b"\x45\x89\xC0")  # r8d = r8d already length; keep r8d
    c.lea_r9(data)
    c.emit(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")
    c.call_mem(iat["WriteFile"])
    c.emit(b"\x31\xC9")
    c.call_mem(iat["ExitProcess"])
    c.emit(b"\xCC")


def emit_env(c, iat, blobs, data):
    c.emit(b"\x48\x83\xEC\x28")
    c.rip(b"\x48\x8D\x0D", blobs["name"])
    c.rip(b"\x48\x8D\x15", data)
    c.emit(b"\x41\xB8\x40\x00\x00\x00")
    c.call_mem(iat["GetEnvironmentVariableA"])
    c.emit(b"\x85\xC0")
    c.emit(b"\x75"); c.rel8("ok")
    _exit_imm(c, iat, 3)
    c.label("ok")
    c.emit(b"\x41\x89\xC4")
    c.emit(b"\xB9\xF5\xFF\xFF\xFF")
    c.call_mem(iat["GetStdHandle"])
    c.emit(b"\x48\x89\xC1")
    c.rip(b"\x48\x8D\x15", data)
    c.emit(b"\x45\x89\xE0")
    c.lea_r9(data + 64)
    c.emit(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")
    c.call_mem(iat["WriteFile"])
    c.emit(b"\x31\xC9")
    c.call_mem(iat["ExitProcess"])
    c.emit(b"\xCC")


def emit_mem(c, iat, blobs, data):
    c.emit(b"\x48\x83\xEC\x28")
    c.emit(b"\x31\xC9")
    c.emit(b"\xBA\x00\x10\x00\x00")
    c.emit(b"\x41\xB8\x00\x30\x00\x00")
    c.emit(b"\x41\xB9\x04\x00\x00\x00")
    c.call_mem(iat["VirtualAlloc"])
    c.emit(b"\x48\x85\xC0")
    c.emit(b"\x75"); c.rel8("aok")
    _exit_imm(c, iat, 1)
    c.label("aok")
    c.emit(b"\x49\x89\xC4")
    c.emit(b"\xC6\x00\x41")
    c.emit(b"\x4C\x89\xE1")
    c.emit(b"\xBA\x00\x10\x00\x00")
    c.emit(b"\x41\xB8\x02\x00\x00\x00")
    c.lea_r9(data)
    c.call_mem(iat["VirtualProtect"])
    c.emit(b"\x85\xC0")
    c.emit(b"\x75"); c.rel8("pok")
    _exit_imm(c, iat, 2)
    c.label("pok")
    c.emit(b"\x4C\x89\xE1")
    c.emit(b"\x31\xD2")
    c.emit(b"\x41\xB8\x00\x80\x00\x00")
    c.call_mem(iat["VirtualFree"])
    c.emit(b"\x85\xC0")
    c.emit(b"\x75"); c.rel8("fok")
    _exit_imm(c, iat, 3)
    c.label("fok")
    _write_const(c, iat, blobs["msg"], len(b"mem-ok\r\n"), data + 8)
    c.emit(b"\x31\xC9")
    c.call_mem(iat["ExitProcess"])
    c.emit(b"\xCC")


def emit_heap(c, iat, blobs, data):
    c.emit(b"\x48\x83\xEC\x28")
    c.call_mem(iat["GetProcessHeap"])
    c.emit(b"\x49\x89\xC5")
    c.emit(b"\x48\x89\xC1")
    c.emit(b"\xBA\x08\x00\x00\x00")
    c.emit(b"\x41\xB8\x10\x00\x00\x00")
    c.call_mem(iat["HeapAlloc"])
    c.emit(b"\x48\x85\xC0")
    c.emit(b"\x75"); c.rel8("hok")
    _exit_imm(c, iat, 1)
    c.label("hok")
    c.emit(b"\x49\x89\xC4")
    c.emit(b"\xC6\x00\x48")
    c.emit(b"\x4C\x89\xE9")
    c.emit(b"\x31\xD2")
    c.emit(b"\x4D\x89\xE0")
    c.call_mem(iat["HeapFree"])
    c.emit(b"\x85\xC0")
    c.emit(b"\x75"); c.rel8("fok")
    _exit_imm(c, iat, 2)
    c.label("fok")
    _write_const(c, iat, blobs["msg"], len(b"heap-ok\r\n"), data)
    c.emit(b"\x31\xC9")
    c.call_mem(iat["ExitProcess"])
    c.emit(b"\xCC")


def emit_file(c, iat, blobs, data):
    payload = b"tweakwin-m2\n"
    c.emit(b"\x48\x83\xEC\x38")
    c.rip(b"\x48\x8D\x0D", blobs["name"])
    c.emit(b"\xBA\x00\x00\x00\x40")
    c.emit(b"\x45\x31\xC0")
    c.emit(b"\x45\x31\xC9")
    c.emit(b"\x48\xC7\x44\x24\x20\x02\x00\x00\x00")
    c.emit(b"\x48\xC7\x44\x24\x28\x80\x00\x00\x00")
    c.emit(b"\x48\xC7\x44\x24\x30\x00\x00\x00\x00")
    c.call_mem(iat["CreateFileA"])
    c.emit(b"\x48\x83\xF8\xFF")
    c.emit(b"\x75"); c.rel8("opened")
    _exit_imm(c, iat, 4)
    c.label("opened")
    c.emit(b"\x49\x89\xC4")
    c.emit(b"\x4C\x89\xE1")
    c.rip(b"\x48\x8D\x15", blobs["payload"])
    c.emit(b"\x41\xB8" + struct.pack("<I", len(payload)))
    c.lea_r9(data)
    c.emit(b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00")
    c.call_mem(iat["WriteFile"])
    c.emit(b"\x4C\x89\xE1")
    c.call_mem(iat["CloseHandle"])
    _write_const(c, iat, blobs["msg"], len(b"file-ok\r\n"), data)
    c.emit(b"\x31\xC9")
    c.call_mem(iat["ExitProcess"])
    c.emit(b"\xCC")


def emit_timer(c, iat, blobs, data):
    c.emit(b"\x48\x83\xEC\x28")
    c.rip(b"\x48\x8D\x0D", data)
    c.call_mem(iat["QueryPerformanceFrequency"])
    c.emit(b"\x85\xC0")
    c.emit(b"\x75"); c.rel8("fok")
    _exit_imm(c, iat, 1)
    c.label("fok")
    c.rip(b"\x48\x8D\x0D", data + 8)
    c.call_mem(iat["QueryPerformanceCounter"])
    c.emit(b"\xB9\x05\x00\x00\x00")
    c.call_mem(iat["Sleep"])
    c.rip(b"\x48\x8D\x0D", data + 16)
    c.call_mem(iat["QueryPerformanceCounter"])
    c.rip(b"\x48\x8B\x05", data + 16)
    c.rip(b"\x48\x3B\x05", data + 8)
    c.emit(b"\x77"); c.rel8("tok")
    _exit_imm(c, iat, 2)
    c.label("tok")
    _write_const(c, iat, blobs["msg"], len(b"timer-ok\r\n"), data + 32)
    c.emit(b"\x31\xC9")
    c.call_mem(iat["ExitProcess"])
    c.emit(b"\xCC")


def m2_fixtures():
    """Name, image, for the M2 guest programs."""
    out = []
    out.append(("args-m2.exe", make_guest(
        0x21000000,
        ["GetStdHandle", "GetCommandLineA", "WriteFile", "ExitProcess"],
        {}, 16, emit_args)))
    out.append(("env-m2.exe", make_guest(
        0x22000000,
        ["GetEnvironmentVariableA", "GetStdHandle", "WriteFile", "ExitProcess"],
        {"name": b"TWTEST\0"}, 80, emit_env)))
    out.append(("mem-m2.exe", make_guest(
        0x23000000,
        ["VirtualAlloc", "VirtualProtect", "VirtualFree", "GetStdHandle", "WriteFile", "ExitProcess"],
        {"msg": b"mem-ok\r\n"}, 16, emit_mem)))
    out.append(("heap-m2.exe", make_guest(
        0x24000000,
        ["GetProcessHeap", "HeapAlloc", "HeapFree", "GetStdHandle", "WriteFile", "ExitProcess"],
        {"msg": b"heap-ok\r\n"}, 16, emit_heap)))
    out.append(("file-m2.exe", make_guest(
        0x25000000,
        ["CreateFileA", "WriteFile", "CloseHandle", "GetStdHandle", "ExitProcess"],
        {"name": b"build/m2-out.txt\0", "payload": b"tweakwin-m2\n", "msg": b"file-ok\r\n"},
        16, emit_file)))
    out.append(("timer-m2.exe", make_guest(
        0x26000000,
        ["QueryPerformanceFrequency", "QueryPerformanceCounter", "Sleep",
         "GetStdHandle", "WriteFile", "ExitProcess"],
        {"msg": b"timer-ok\r\n"}, 48, emit_timer)))
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(64)
    outdir = sys.argv[1]
    os.makedirs(os.path.join(outdir, "bad"), exist_ok=True)

    hello, hlay, hmeta = make_hello()
    dll, dlay, dmeta = make_dll()
    hello_m1, m1lay, m1meta = make_hello_m1()
    exit42, _, _ = make_exit42()
    with open(os.path.join(outdir, "hello.exe"), "wb") as f:
        f.write(hello)
    with open(os.path.join(outdir, "tweaktest.dll"), "wb") as f:
        f.write(dll)
    with open(os.path.join(outdir, "hello-m1.exe"), "wb") as f:
        f.write(hello_m1)
    with open(os.path.join(outdir, "exit42.exe"), "wb") as f:
        f.write(exit42)

    load_dir = os.path.join(outdir, "load")
    os.makedirs(load_dir, exist_ok=True)
    for name, blob in m1_variants(hello_m1, m1lay, m1meta):
        with open(os.path.join(load_dir, name), "wb") as f:
            f.write(blob)

    for name, blob in m2_fixtures():
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(blob)

    rows = []
    for name, blob, code, needle in variants(hello, hlay, hmeta, dll, dlay, dmeta):
        with open(os.path.join(outdir, "bad", name), "wb") as f:
            f.write(blob)
        rows.append(f"{name}\t{code}\t{needle}")
    with open(os.path.join(outdir, "bad", "manifest.tsv"), "w") as f:
        f.write("\n".join(rows) + "\n")
    print(f"mkpe: wrote hello.exe, hello-m1.exe, exit42.exe, tweaktest.dll, "
          f"6 M2 guests, {len(rows)} parser variants and loader fixtures to {outdir}")


if __name__ == "__main__":
    main()
