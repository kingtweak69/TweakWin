# PE parser validation rules and limits

The parser (`loader/pe/pe.c`) treats every input as hostile. All offsets and
sizes from the file are checked in 64-bit arithmetic before use, and every
read goes through a bounds-checked helper.

## Fatal (image rejected, exit 2)

These would make an image unloadable or unsafe to load, so M1's loader relies
on them having been checked.

- File under 64 bytes, no `MZ`, `e_lfanew` out of range, no `PE\0\0`
- No optional header, optional header truncated, unknown optional magic
- `IMAGE_FILE_EXECUTABLE_IMAGE` not set
- Optional header smaller than PE32+ fixed part, or too small for its data directories
- `SectionAlignment` / `FileAlignment` not a power of two; `SectionAlignment < FileAlignment`;
  low-alignment image (`SectionAlignment < 4 KiB`) with `FileAlignment != SectionAlignment`
- `SizeOfImage == 0`; `ImageBase + SizeOfImage` overflows; `SizeOfHeaders` zero or larger than `SizeOfImage`
- Entry point RVA outside `SizeOfImage`
- More than 96 sections; section table past end of file
- Section raw data past end of file; `VirtualAddress` not aligned; section past `SizeOfImage`;
  section overlapping the headers or the previous section (sections must be ascending)
- Import descriptor / thunk / hint-name / DLL name out of bounds or unterminated;
  descriptor without an IAT; name thunk with reserved bits set; no terminator within 4096 descriptors
- Delay-import descriptor problems (same rules; legacy VA-based descriptors are converted)
- Export directory out of bounds; more than 65536 functions or names; name mapping to a
  nonexistent function index; export RVA outside the image; bad forwarder string
- Relocation directory not file-backed; block size < 8, odd, or past the directory;
  block page outside the image; target outside the image; relocation type other than
  ABSOLUTE/HIGH/LOW/HIGHLOW/DIR64
- TLS directory out of bounds; raw data range inverted or outside the image;
  index VA or callback VA outside the image; more than 1024 callbacks

## Warnings (image accepted, listed under `Warnings:`)

- `NumberOfRvaAndSizes > 16` (extra entries ignored)
- `FileAlignment` outside 0x200–0x10000; `SizeOfImage` not section-aligned; `ImageBase` not 64 KiB aligned
- `SizeOfHeaders` past end of file; section table past `SizeOfHeaders`
- Stack/heap commit larger than reserve
- Empty sections; writable + executable sections
- Entry point outside any section or in a non-executable section; EXE without an entry point
- Data directory extending past `SizeOfImage`; security directory past end of file
- Ordinal import with reserved bits; empty import name; DLL descriptor importing nothing
- Export ordinals above 16 bits
- HIGH/LOW/HIGHLOW relocations in an x86-64 image; relocation block not 32-bit aligned;
  `RELOCS_STRIPPED` set alongside a relocation directory
- Exception directory: size not a multiple of 12, not file-backed, invalid ranges,
  bad unwind info, unsorted
- Resource tree: out of bounds, deeper than 8 levels, more than 100,000 nodes, data entry outside
  the image (summary marked partial)
- .NET/CLR image (needs a managed runtime)

## Unsupported (exit 3)

- Machine other than AMD64 (i386, ARM64, ARMNT, ARM64EC, IA64, ...)
- PE32 (32-bit) or ROM optional header

## Hard caps

| limit | value |
|---|---|
| file size | 2 GiB |
| sections | 96 |
| import descriptors (each of normal / delay) | 4096 |
| imported functions total | 1,000,000 |
| export functions / names | 65,536 each |
| TLS callbacks | 1024 |
| RUNTIME_FUNCTION entries examined | 4,194,304 |
| resource tree depth / nodes | 8 / 100,000 |
| import/export name length | 4096 |
| DLL name length | 256 |
| warnings kept | 64 (rest counted) |

## Known simplifications

- Data inside a section is read up to `min(SizeOfRawData, VirtualSize)`; bytes
  past that are zero-fill. `PointerToRawData` is used exactly as stored (no
  rounding down to 512 bytes).
- A section with `VirtualSize == 0` uses `SizeOfRawData` as its extent.
- Directory `Size` fields for imports/TLS aren't used to bound walks; walks stop at
  terminators, and every read is bounds-checked.
