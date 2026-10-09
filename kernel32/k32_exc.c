/* kernel32 exception-handling surface: vectored exception handlers and the
 * top-level unhandled-exception filter, over the rt SEH dispatcher. Full
 * frame-based __try/__except is not provided (see docs/EXCEPTIONS.md). */
#include "k32priv.h"

#include "../rt/rt.h"

void *TW_MS_ABI tw_k32_AddVectoredExceptionHandler(TW_DWORD first, void *handler)
{
    if (!tw_rt_active() || !handler) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return NULL;
    }
    uint64_t cookie = tw_rt_veh_add(first != 0, (uint64_t)(uintptr_t)handler);
    if (!cookie) {
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return (void *)(uintptr_t)cookie;
}

TW_DWORD TW_MS_ABI tw_k32_RemoveVectoredExceptionHandler(void *handle)
{
    if (!tw_rt_active() || tw_rt_veh_remove((uint64_t)(uintptr_t)handle) != 0) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return 0;
    }
    return 1;
}

/* LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(filter) */
void *TW_MS_ABI tw_k32_SetUnhandledExceptionFilter(void *filter)
{
    uint64_t prev = tw_rt_set_unhandled_filter((uint64_t)(uintptr_t)filter);
    return (void *)(uintptr_t)prev;
}
