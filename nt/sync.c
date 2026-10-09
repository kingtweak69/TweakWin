#include "sync.h"

#include "status.h"

uint64_t tw_nt_ms_to_ns(uint32_t ms)
{
    if (ms == TW_INFINITE_MS) return TW_KB_INFINITE;
    return (uint64_t)ms * 1000000ull;
}

NTSTATUS tw_nt_create_event(tw_kh *out, int manual_reset, int initial_state)
{
    uint32_t flags = 0;
    if (manual_reset) flags |= TW_KB_EVENT_MANUAL;
    if (initial_state) flags |= TW_KB_EVENT_SIGNALED;
    tw_kh h = tw_kb_event_create(flags);
    if (h < 0) return tw_nt_from_kb(h, TW_KBC_CREATE);
    *out = h;
    return STATUS_SUCCESS;
}

NTSTATUS tw_nt_set_event(tw_kh h, int32_t *prev)
{
    int64_t r = tw_kb_event_set(h);
    if (r < 0) return tw_nt_from_kb(r, TW_KBC_HANDLE);
    if (prev) *prev = (int32_t)r;
    return STATUS_SUCCESS;
}

NTSTATUS tw_nt_reset_event(tw_kh h, int32_t *prev)
{
    int64_t r = tw_kb_event_reset(h);
    if (r < 0) return tw_nt_from_kb(r, TW_KBC_HANDLE);
    if (prev) *prev = (int32_t)r;
    return STATUS_SUCCESS;
}

NTSTATUS tw_nt_create_semaphore(tw_kh *out, int32_t initial, int32_t maximum)
{
    if (maximum <= 0 || initial < 0 || initial > maximum) return STATUS_INVALID_PARAMETER;
    tw_kh h = tw_kb_sem_create((uint32_t)initial, (uint32_t)maximum);
    if (h < 0) return tw_nt_from_kb(h, TW_KBC_CREATE);
    *out = h;
    return STATUS_SUCCESS;
}

NTSTATUS tw_nt_release_semaphore(tw_kh h, int32_t count, int32_t *prev)
{
    if (count <= 0) return STATUS_INVALID_PARAMETER;
    int64_t r = tw_kb_sem_release(h, (uint32_t)count);
    if (r < 0) {
        /* ESTATE here means the release would exceed the maximum. */
        if (r == TW_KB_ESTATE) return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        return tw_nt_from_kb(r, TW_KBC_HANDLE);
    }
    if (prev) *prev = (int32_t)r;
    return STATUS_SUCCESS;
}

NTSTATUS tw_nt_wait_single(tw_kh h, uint32_t ms, uint32_t *result)
{
    int64_t r = tw_kb_wait_one(h, tw_nt_ms_to_ns(ms));
    if (r == 0) {
        *result = TW_WAIT_OBJECT_0;
        return STATUS_SUCCESS;
    }
    if (r == TW_KB_WAIT_TIMEOUT) {
        *result = TW_WAIT_TIMEOUT;
        return STATUS_TIMEOUT;
    }
    return tw_nt_from_kb(r, TW_KBC_HANDLE);
}

NTSTATUS tw_nt_wait_multiple(const tw_kh *hs, uint32_t count, int wait_all, uint32_t ms,
                             uint32_t *result)
{
    if (wait_all) {
        /* TweakKernel M4 has no wait-all. Report it honestly rather than
         * emulating a racy poll loop that would not be atomic. When M5's
         * WAIT_ALL arrives, this becomes a single backend call behind the
         * TW_KB_CAP_WAIT_ALL check. */
        return STATUS_NOT_IMPLEMENTED;
    }
    int64_t r = tw_kb_wait_any(hs, count, tw_nt_ms_to_ns(ms));
    if (r >= 0 && (uint64_t)r < count) {
        *result = TW_WAIT_OBJECT_0 + (uint32_t)r;
        return STATUS_SUCCESS;
    }
    if (r == TW_KB_WAIT_TIMEOUT) {
        *result = TW_WAIT_TIMEOUT;
        return STATUS_TIMEOUT;
    }
    return tw_nt_from_kb(r, TW_KBC_HANDLE);
}
