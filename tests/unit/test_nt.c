/* NTSTATUS layer: domain separation and the specific mappings the Win32
 * wrappers depend on. Built with ASan + UBSan by `make unit`. */
#include "../../backend/kb.h"
#include "../../nt/status.h"

#include <stdio.h>

static int g_pass, g_fail;
#define CHECK(c)                                                               \
    do {                                                                       \
        if (c) g_pass++;                                                       \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

int main(void)
{
    /* backend -> NTSTATUS, with context. */
    CHECK(tw_nt_from_kb(0, TW_KBC_GENERIC) == STATUS_SUCCESS);
    CHECK(tw_nt_from_kb(5, TW_KBC_GENERIC) == STATUS_SUCCESS); /* positive = success */
    CHECK(tw_nt_from_kb(TW_KB_EBADH, TW_KBC_HANDLE) == STATUS_INVALID_HANDLE);
    CHECK(tw_nt_from_kb(TW_KB_EPERM, TW_KBC_HANDLE) == STATUS_ACCESS_DENIED);
    CHECK(tw_nt_from_kb(TW_KB_EINVAL, TW_KBC_GENERIC) == STATUS_INVALID_PARAMETER);
    CHECK(tw_nt_from_kb(TW_KB_ENOSYS, TW_KBC_GENERIC) == STATUS_NOT_IMPLEMENTED);
    CHECK(tw_nt_from_kb(TW_KB_ENOMEM, TW_KBC_GENERIC) == STATUS_NO_MEMORY);
    CHECK(tw_nt_from_kb(TW_KB_ENOMEM, TW_KBC_HANDLE) == STATUS_INSUFFICIENT_RESOURCES);
    CHECK(tw_nt_from_kb(TW_KB_ENOMEM, TW_KBC_CREATE) == STATUS_INSUFFICIENT_RESOURCES);
    CHECK(tw_nt_from_kb(TW_KB_EFAULT, TW_KBC_GENERIC) == STATUS_ACCESS_VIOLATION);
    CHECK(tw_nt_from_kb(TW_KB_EFAULT, TW_KBC_VM) == STATUS_MEMORY_NOT_ALLOCATED);
    CHECK(tw_nt_from_kb(TW_KB_ESTATE, TW_KBC_VM) == STATUS_CONFLICTING_ADDRESSES);
    CHECK(tw_nt_from_kb(TW_KB_ESTATE, TW_KBC_GENERIC) == STATUS_INVALID_PARAMETER);
    CHECK(tw_nt_from_kb(TW_KB_ENOENT, TW_KBC_FILE) == STATUS_OBJECT_NAME_NOT_FOUND);
    CHECK(tw_nt_from_kb(TW_KB_EEXIST, TW_KBC_FILE) == STATUS_OBJECT_NAME_COLLISION);
    CHECK(tw_nt_from_kb(TW_KB_EISDIR, TW_KBC_FILE) == STATUS_FILE_IS_A_DIRECTORY);

    /* NTSTATUS -> Win32 LastError. */
    CHECK(tw_nt_to_win32(STATUS_SUCCESS) == 0);
    CHECK(tw_nt_to_win32(STATUS_INVALID_HANDLE) == 6);
    CHECK(tw_nt_to_win32(STATUS_ACCESS_DENIED) == 5);
    CHECK(tw_nt_to_win32(STATUS_ACCESS_VIOLATION) == 998);
    CHECK(tw_nt_to_win32(STATUS_INVALID_PARAMETER) == 87);
    CHECK(tw_nt_to_win32(STATUS_NO_MEMORY) == 8);
    CHECK(tw_nt_to_win32(STATUS_NOT_IMPLEMENTED) == 1);
    CHECK(tw_nt_to_win32(STATUS_OBJECT_NAME_NOT_FOUND) == 2);
    CHECK(tw_nt_to_win32(STATUS_OBJECT_PATH_NOT_FOUND) == 3);
    CHECK(tw_nt_to_win32(STATUS_OBJECT_NAME_COLLISION) == 183);
    CHECK(tw_nt_to_win32(STATUS_BUFFER_TOO_SMALL) == 122);
    CHECK(tw_nt_to_win32(STATUS_BUFFER_OVERFLOW) == 234);
    CHECK(tw_nt_to_win32(STATUS_TIMEOUT) == 1460);
    CHECK(tw_nt_to_win32(STATUS_DLL_NOT_FOUND) == 126);
    CHECK(tw_nt_to_win32(STATUS_ENTRYPOINT_NOT_FOUND) == 127);
    CHECK(tw_nt_to_win32(STATUS_INVALID_IMAGE_FORMAT) == 193);
    CHECK(tw_nt_to_win32(STATUS_NO_UNICODE_TRANSLATION) == 1113);
    CHECK(tw_nt_to_win32(STATUS_SEMAPHORE_LIMIT_EXCEEDED) == 298);
    CHECK(tw_nt_to_win32(STATUS_DIRECTORY_NOT_EMPTY) == 145);
    /* Unknown NTSTATUS -> no mapping. */
    CHECK(tw_nt_to_win32((NTSTATUS)0xC0DECAFE) == 317);

    CHECK(NT_SUCCESS(STATUS_SUCCESS));
    CHECK(NT_SUCCESS(STATUS_TIMEOUT));       /* 0x102 >= 0 */
    CHECK(!NT_SUCCESS(STATUS_ACCESS_DENIED));
    CHECK(tw_nt_status_name(STATUS_ACCESS_VIOLATION) != NULL);
    CHECK(tw_nt_status_name((NTSTATUS)0x12345678) == NULL);

    fprintf(stderr, "nt: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
