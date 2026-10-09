/* Minimal CRT-free TLS support: defines the .tls section bounds, the TLS
 * callback array markers, _tls_index, and the IMAGE_TLS_DIRECTORY64 that
 * lld-link publishes as the PE's TLS data directory. This is the small
 * piece the Microsoft CRT's tlssup.c normally supplies; TweakWin's loader
 * then applies the directory per thread. */
typedef unsigned long ULONG;
typedef unsigned long long ULONGLONG;

#pragma section(".tls", long, read, write)
#pragma section(".tls$ZZZ", long, read, write)
__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;

typedef void(__stdcall *PIMAGE_TLS_CALLBACK)(void *, ULONG, void *);
#pragma section(".CRT$XLA", long, read)
#pragma section(".CRT$XLZ", long, read)
__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = 0;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = 0;

ULONG _tls_index = 0;

typedef struct {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;
    ULONG SizeOfZeroFill;
    ULONG Characteristics;
} IMAGE_TLS_DIRECTORY64;

__declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)(void *)&_tls_start,
    (ULONGLONG)(void *)&_tls_end,
    (ULONGLONG)(void *)&_tls_index,
    (ULONGLONG)(void *)&__xl_a + sizeof(void *),
    0,
    0,
};
