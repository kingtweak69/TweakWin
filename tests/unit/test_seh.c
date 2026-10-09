/* SEH foundation + object table unit checks that need no PE: VEH
 * registration/removal ordering, unhandled-filter get/set, and the Win32
 * HANDLE <-> backend-handle object table (generation reuse, type, close).
 * Built with ASan + UBSan. */
#include "../../backend/kb.h"
#include "../../rt/object.h"
#include "../../rt/rt.h"

#include <stdio.h>

static int g_pass, g_fail;
#define CHECK(c)                                                               \
    do {                                                                       \
        if (c) g_pass++;                                                       \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

int main(void)
{
    CHECK(tw_kb_init() == TW_KB_OK);
    tw_obj_init();

    /* Object table: install an event, look it up, close it. */
    tw_kh e = tw_kb_event_create(0);
    CHECK(e > 0);
    void *h = tw_obj_install(e, TW_KB_TYPE_EVENT);
    CHECK(h != NULL);
    CHECK(tw_obj_is(h));
    CHECK(!tw_obj_is((void *)(uintptr_t)0x20004)); /* file-handle range, not ours */
    tw_kh kh = 0;
    int type = 0;
    CHECK(tw_obj_lookup(h, &kh, &type) == 0 && kh == e && type == TW_KB_TYPE_EVENT);
    CHECK(tw_obj_close(h) == 0);
    CHECK(tw_obj_lookup(h, &kh, &type) != 0);  /* stale */
    CHECK(tw_obj_close(h) != 0);
    /* Backend handle is closed with the slot. */
    CHECK(tw_kb_event_set(e) == TW_KB_EBADH);

    /* Generation changes on reuse so a stale HANDLE is rejected. */
    tw_kh e2 = tw_kb_event_create(0);
    void *h2 = tw_obj_install(e2, TW_KB_TYPE_EVENT);
    CHECK(h2 != NULL && h2 != h);
    tw_obj_close(h2);

    /* VEH add/remove and the unhandled filter (values are opaque here). */
    uint64_t c1 = tw_rt_veh_add(1, 0x140001000ull);
    uint64_t c2 = tw_rt_veh_add(0, 0x140002000ull);
    CHECK(c1 && c2 && c1 != c2);
    CHECK(tw_rt_veh_remove(c1) == 0);
    CHECK(tw_rt_veh_remove(c1) != 0); /* already removed */
    CHECK(tw_rt_veh_add(1, 0) == 0);  /* NULL handler rejected */
    CHECK(tw_rt_veh_remove(c2) == 0);

    CHECK(tw_rt_set_unhandled_filter(0x140003000ull) == 0);
    CHECK(tw_rt_set_unhandled_filter(0) == 0x140003000ull);

    tw_obj_reset();
    tw_rt_seh_reset();
    fprintf(stderr, "seh: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
