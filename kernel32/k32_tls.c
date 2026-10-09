/* kernel32 dynamic TLS: TlsAlloc / TlsFree / TlsGetValue / TlsSetValue over
 * the TEB TlsSlots (rt/tls.c). */
#include "k32priv.h"

#include "../rt/rt.h"

TW_DWORD TW_MS_ABI tw_k32_TlsAlloc(void)
{
    if (!tw_rt_active()) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_TLS_OUT_OF_INDEXES_W;
    }
    uint32_t idx = tw_rt_tls_alloc();
    if (idx == TW_TLS_OUT_OF_INDEXES) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return TW_TLS_OUT_OF_INDEXES_W;
    }
    return idx;
}

TW_BOOL TW_MS_ABI tw_k32_TlsFree(TW_DWORD index)
{
    if (tw_rt_tls_free(index) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return TW_TRUE;
}

void *TW_MS_ABI tw_k32_TlsGetValue(TW_DWORD index)
{
    int ok = 0;
    uint64_t v = tw_rt_tls_get(index, &ok);
    if (!ok) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    tw_set_last_error(TW_ERROR_SUCCESS);
    return (void *)(uintptr_t)v;
}

TW_BOOL TW_MS_ABI tw_k32_TlsSetValue(TW_DWORD index, void *value)
{
    if (tw_rt_tls_set(index, (uint64_t)(uintptr_t)value) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_FALSE;
    }
    return TW_TRUE;
}
