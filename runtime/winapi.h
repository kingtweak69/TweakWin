#ifndef TWEAKWIN_WINAPI_H
#define TWEAKWIN_WINAPI_H

/*
 * Host-side stand-ins for Win32 types TweakWin implements.
 * Widths and calling convention match Microsoft's x64 ABI, not Linux SysV.
 * These are not a Windows SDK.
 */

#include <stdint.h>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define TW_MS_ABI __attribute__((ms_abi))
#else
#error "TweakWin requires GCC/Clang on x86-64 for the Microsoft ABI"
#endif

typedef void *TW_HANDLE;
typedef uint32_t TW_DWORD;
typedef int32_t TW_BOOL;
typedef uint32_t TW_UINT;
typedef uint64_t TW_SIZE_T;

#define TW_TRUE  1
#define TW_FALSE 0

#define TW_STD_INPUT_HANDLE  ((TW_DWORD) -10)
#define TW_STD_OUTPUT_HANDLE ((TW_DWORD) -11)
#define TW_STD_ERROR_HANDLE  ((TW_DWORD) -12)

#define TW_INVALID_HANDLE_VALUE ((TW_HANDLE)(intptr_t) -1)

/* M1 values. The handle table keeps issuing exactly these for the standard devices. */
#define TW_HANDLE_STDIN  ((TW_HANDLE)(uintptr_t)0x10)
#define TW_HANDLE_STDOUT ((TW_HANDLE)(uintptr_t)0x14)
#define TW_HANDLE_STDERR ((TW_HANDLE)(uintptr_t)0x18)

/* Win32 error codes used by the M2 surface. */
#define TW_ERROR_SUCCESS                 0u
#define TW_ERROR_FILE_NOT_FOUND          2u
#define TW_ERROR_PATH_NOT_FOUND          3u
#define TW_ERROR_ACCESS_DENIED           5u
#define TW_ERROR_NO_MORE_FILES           18u
#define TW_ERROR_PROC_NOT_FOUND          127u
#define TW_ERROR_BAD_EXE_FORMAT          193u
#define TW_ERROR_MORE_DATA               234u
#define TW_ERROR_BAD_PATHNAME            161u
#define TW_ERROR_DIRECTORY               267u
#define TW_ERROR_DLL_INIT_FAILED         1114u
#define TW_ERROR_INVALID_HANDLE          6u
#define TW_ERROR_NOT_ENOUGH_MEMORY       8u
#define TW_ERROR_WRITE_FAULT             29u
#define TW_ERROR_READ_FAULT              30u
#define TW_ERROR_BAD_LENGTH              24u
#define TW_ERROR_FILE_EXISTS             80u
#define TW_ERROR_INVALID_PARAMETER       87u
#define TW_ERROR_INSUFFICIENT_BUFFER     122u
#define TW_ERROR_INVALID_NAME            123u
#define TW_ERROR_MOD_NOT_FOUND           126u
#define TW_ERROR_ENVVAR_NOT_FOUND        203u
#define TW_ERROR_INVALID_ADDRESS         487u
#define TW_ERROR_NOACCESS                998u
#define TW_ERROR_INVALID_FLAGS           1004u
#define TW_ERROR_NO_UNICODE_TRANSLATION  1113u

#define TW_MEM_COMMIT  0x00001000u
#define TW_MEM_RESERVE 0x00002000u
#define TW_MEM_DECOMMIT 0x00004000u
#define TW_MEM_RELEASE 0x00008000u
#define TW_MEM_FREE    0x00010000u
#define TW_MEM_PRIVATE 0x00020000u
#define TW_MEM_IMAGE   0x01000000u

#define TW_PAGE_NOACCESS          0x01u
#define TW_PAGE_READONLY          0x02u
#define TW_PAGE_READWRITE         0x04u
#define TW_PAGE_EXECUTE           0x10u
#define TW_PAGE_EXECUTE_READ      0x20u
#define TW_PAGE_EXECUTE_READWRITE 0x40u

#define TW_HEAP_NO_SERIALIZE           0x00000001u
#define TW_HEAP_ZERO_MEMORY            0x00000008u
#define TW_HEAP_REALLOC_IN_PLACE_ONLY  0x00000010u

#define TW_GENERIC_READ  0x80000000u
#define TW_GENERIC_WRITE 0x40000000u

#define TW_CREATE_NEW        1u
#define TW_CREATE_ALWAYS     2u
#define TW_OPEN_EXISTING     3u
#define TW_OPEN_ALWAYS       4u
#define TW_TRUNCATE_EXISTING 5u

#define TW_FILE_ATTRIBUTE_NORMAL 0x00000080u
#define TW_FILE_FLAG_OVERLAPPED  0x40000000u

#define TW_FILE_TYPE_UNKNOWN 0u
#define TW_FILE_TYPE_DISK    1u
#define TW_FILE_TYPE_CHAR    2u
#define TW_FILE_TYPE_PIPE    3u

#define TW_MB_ERR_INVALID_CHARS 0x00000008u
#define TW_WC_ERR_INVALID_CHARS 0x00000080u


/* ---- synchronization / threads (added for the M3 runtime) ---- */
#define TW_WAIT_OBJECT_0 0x00000000u
#define TW_WAIT_TIMEOUT  0x00000102u
#define TW_WAIT_FAILED   0xFFFFFFFFu
#define TW_WAIT_ABANDONED_0 0x00000080u
#define TW_INFINITE      0xFFFFFFFFu
#define TW_MAXIMUM_WAIT_OBJECTS 64

#define TW_ERROR_NOT_SUPPORTED   50u
#define TW_ERROR_SEM_TOO_MANY    298u /* ERROR_TOO_MANY_POSTS */
#define TW_ERROR_CALL_NOT_IMPLEMENTED 120u
#define TW_ERROR_TOO_MANY_TLS_KEYS 1016u /* ERROR_NO_MORE_USER_HANDLES stand-in */

#define TW_TLS_OUT_OF_INDEXES_W 0xFFFFFFFFu
#define TW_STILL_ACTIVE 259u

/* x64 MEMORY_BASIC_INFORMATION is 48 bytes. See docs/RUNTIME.md. */
#define TW_MBI_SIZE 48u

#endif
