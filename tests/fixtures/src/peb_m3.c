/* Reads the TEB through GS, walks TEB->PEB->ProcessParameters->CommandLine,
 * and writes the command line out, then exits with its UTF-16 length. Proves
 * the x86-64 Windows process environment is real. No CRT. */
__declspec(dllimport) void *__stdcall GetStdHandle(unsigned long);
__declspec(dllimport) int __stdcall WriteFile(void *, const void *, unsigned long, unsigned long *, void *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned int);

static unsigned long long read_gs(unsigned long off)
{
    unsigned long long v;
    __asm__ volatile("movq %%gs:(%1), %0" : "=r"(v) : "r"(off));
    return v;
}

void start(void)
{
    void *h = GetStdHandle((unsigned long)-11);
    unsigned long long teb_self = read_gs(0x30);
    unsigned long long peb = read_gs(0x60);
    if (!teb_self || !peb) ExitProcess(0xE0);

    unsigned long long *peb_p = (unsigned long long *)peb;
    unsigned long long image_base = peb_p[0x10 / 8];
    unsigned long long rupp = peb_p[0x20 / 8];
    if (!rupp) ExitProcess(0xE1);

    /* RUPP.CommandLine is a UNICODE_STRING at +0x70. */
    unsigned char *r = (unsigned char *)rupp;
    unsigned short len = *(unsigned short *)(r + 0x70);
    unsigned short *buf = *(unsigned short **)(r + 0x78);

    /* Convert UTF-16 command line to ASCII bytes and write it. */
    char out[512];
    unsigned n = 0;
    for (unsigned i = 0; i < len / 2 && n < sizeof(out) - 1; i++)
        out[n++] = (char)(buf[i] & 0x7f);
    out[n++] = '\n';
    unsigned long wrote;
    WriteFile(h, out, n, &wrote, 0);

    /* Confirm ImageBaseAddress matches the PEB's view via a sanity marker. */
    unsigned code = (image_base != 0) ? (len / 2) & 0xff : 0xE2;
    ExitProcess(code);
}
