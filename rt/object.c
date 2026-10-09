#include "object.h"

#include <pthread.h>
#include <stdint.h>

#define OBJ_SLOTS 256
#define OBJ_BASE  0x40000u /* disjoint from runtime file handles (0x20000+) */

struct slot {
    int live;
    int type;
    uint8_t gen;
    tw_kh kh;
};

static struct slot g_slots[OBJ_SLOTS];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

int tw_obj_init(void)
{
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < OBJ_SLOTS; i++) g_slots[i].live = 0;
    pthread_mutex_unlock(&g_mu);
    return 0;
}

void tw_obj_reset(void)
{
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < OBJ_SLOTS; i++) {
        if (g_slots[i].live) {
            tw_kb_close(g_slots[i].kh);
            g_slots[i].live = 0;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

static void *encode(int idx, uint8_t gen)
{
    uint32_t v = OBJ_BASE + ((uint32_t)idx << 8) + (gen ? gen : 1);
    return (void *)(uintptr_t)v;
}

static int decode(void *h, uint8_t *gen)
{
    uint32_t v = (uint32_t)(uintptr_t)h;
    if ((uintptr_t)h != v) return -1;
    if (v < OBJ_BASE || v >= OBJ_BASE + (OBJ_SLOTS << 8)) return -1;
    *gen = (uint8_t)(v & 0xff);
    return (int)((v - OBJ_BASE) >> 8);
}

int tw_obj_is(void *h)
{
    uint8_t g;
    return decode(h, &g) >= 0;
}

void *tw_obj_install(tw_kh kh, int type)
{
    if (kh <= 0) return NULL;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < OBJ_SLOTS; i++) {
        if (!g_slots[i].live) {
            uint8_t gen = (uint8_t)(g_slots[i].gen + 1);
            if (gen == 0) gen = 1;
            g_slots[i].gen = gen;
            g_slots[i].live = 1;
            g_slots[i].type = type;
            g_slots[i].kh = kh;
            void *h = encode(i, gen);
            pthread_mutex_unlock(&g_mu);
            return h;
        }
    }
    pthread_mutex_unlock(&g_mu);
    tw_kb_close(kh);
    return NULL;
}

int tw_obj_lookup(void *h, tw_kh *kh, int *type)
{
    uint8_t gen;
    int idx = decode(h, &gen);
    if (idx < 0) return -1;
    pthread_mutex_lock(&g_mu);
    struct slot *s = &g_slots[idx];
    int rc = -1;
    if (s->live && s->gen == gen) {
        if (kh) *kh = s->kh;
        if (type) *type = s->type;
        rc = 0;
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int tw_obj_close(void *h)
{
    uint8_t gen;
    int idx = decode(h, &gen);
    if (idx < 0) return -1;
    pthread_mutex_lock(&g_mu);
    struct slot *s = &g_slots[idx];
    int rc = -1;
    if (s->live && s->gen == gen) {
        tw_kh kh = s->kh;
        s->live = 0;
        rc = tw_kb_close(kh) == 0 ? 0 : 0; /* closing the handle always frees the slot */
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}
