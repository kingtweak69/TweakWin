#ifndef TWEAKWIN_WINNT_H
#define TWEAKWIN_WINNT_H

/*
 * x86-64 Windows process/thread environment layout, from public Microsoft
 * documentation and the published winnt.h / ntddk field order. These are
 * the offsets a Windows x86-64 guest expects to find through GS, so they
 * are ABI, not a TweakWin invention. Only the fields TweakWin populates
 * are named; the rest of each block is zero-filled to the documented size.
 *
 * ARCHITECTURAL TLS BASE vs WINDOWS TLS SLOTS vs TEB LAYOUT are distinct:
 *   - the architectural GS base is the linear address the CPU adds to a
 *     GS-relative access; TweakWin points it at the TEB (tw_kb_tls_set GS).
 *   - TEB.ThreadLocalStoragePointer (GS:[0x58]) points at the per-thread
 *     array of PE/implicit-TLS blocks indexed by the TLS directory's index.
 *   - TEB.TlsSlots (GS:[0x1480]) are the 64 TlsAlloc/TlsGetValue slots.
 * They are related but never the same storage.
 */

#include <stdint.h>

/* ---- TEB (x64) field offsets ---- */
#define TEB_NtTib_ExceptionList      0x0000
#define TEB_NtTib_StackBase          0x0008
#define TEB_NtTib_StackLimit         0x0010
#define TEB_NtTib_SubSystemTib       0x0018
#define TEB_NtTib_FiberData          0x0020
#define TEB_NtTib_ArbitraryUserPtr   0x0028
#define TEB_NtTib_Self               0x0030
#define TEB_EnvironmentPointer       0x0038
#define TEB_ClientId_Process         0x0040
#define TEB_ClientId_Thread          0x0048
#define TEB_ActiveRpcHandle          0x0050
#define TEB_ThreadLocalStoragePointer 0x0058
#define TEB_ProcessEnvironmentBlock  0x0060
#define TEB_LastErrorValue           0x0068
#define TEB_CountOfOwnedCritSec      0x006C
#define TEB_CsrClientThread          0x0070
#define TEB_StackBase_User           0x1478 /* DeallocationStack region */
#define TEB_TlsSlots                 0x1480 /* 64 * 8 bytes */
#define TEB_TlsExpansionSlots        0x1780
#define TEB_SIZE                     0x1838
#define TEB_TLS_SLOTS                64

/* ---- PEB (x64) ---- */
#define PEB_InheritedAddressSpace    0x0000
#define PEB_BeingDebugged            0x0002
#define PEB_ImageBaseAddress         0x0010
#define PEB_Ldr                      0x0018
#define PEB_ProcessParameters        0x0020
#define PEB_ProcessHeap              0x0030
#define PEB_NumberOfProcessors       0x00B8
#define PEB_OSMajorVersion           0x0118
#define PEB_OSMinorVersion           0x011C
#define PEB_OSBuildNumber            0x0120 /* u16 */
#define PEB_OSPlatformId             0x0124
#define PEB_SessionId                0x01D4
#define PEB_SIZE                     0x07C8

/* ---- RTL_USER_PROCESS_PARAMETERS (x64) ---- */
#define RUPP_MaximumLength           0x0000
#define RUPP_Length                  0x0004
#define RUPP_Flags                   0x0008
#define RUPP_ConsoleHandle           0x0010
#define RUPP_StandardInput           0x0020
#define RUPP_StandardOutput          0x0028
#define RUPP_StandardError           0x0030
#define RUPP_CurrentDirectory_Dos    0x0038 /* UNICODE_STRING + Handle (CURDIR) */
#define RUPP_CurrentDirectory_Handle 0x0048
#define RUPP_DllPath                 0x0050 /* UNICODE_STRING */
#define RUPP_ImagePathName           0x0060 /* UNICODE_STRING */
#define RUPP_CommandLine             0x0070 /* UNICODE_STRING */
#define RUPP_Environment             0x0080
#define RUPP_SIZE                    0x0410

/* ---- PEB_LDR_DATA (x64) ---- */
#define LDR_Length                       0x0000
#define LDR_Initialized                  0x0004
#define LDR_SsHandle                     0x0008
#define LDR_InLoadOrderModuleList        0x0010
#define LDR_InMemoryOrderModuleList      0x0020
#define LDR_InInitializationOrderModuleList 0x0030
#define LDR_EntryInProgress              0x0040
#define LDR_SIZE                         0x0058

/* ---- LDR_DATA_TABLE_ENTRY (x64) ---- */
#define LDE_InLoadOrderLinks            0x0000
#define LDE_InMemoryOrderLinks          0x0010
#define LDE_InInitializationOrderLinks  0x0020
#define LDE_DllBase                     0x0030
#define LDE_EntryPoint                  0x0038
#define LDE_SizeOfImage                 0x0040
#define LDE_FullDllName                 0x0048 /* UNICODE_STRING */
#define LDE_BaseDllName                 0x0058 /* UNICODE_STRING */
#define LDE_Flags                       0x0068
#define LDE_LoadCount                   0x006C /* u16 (ObsoleteLoadCount) */
#define LDE_HashLinks                   0x0078
#define LDE_SIZE                        0x0120

/* UNICODE_STRING: Length(u16) MaximumLength(u16) pad Buffer(ptr @ +8) */
#define UNICODE_STRING_SIZE 0x10

/* PE TLS directory (IMAGE_TLS_DIRECTORY64). */
typedef struct {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
} tw_image_tls_dir64;

/* IMAGE_LOAD_CONFIG security-cookie / CFG fields are not used yet. */

#endif
