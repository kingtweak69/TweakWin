#include "arena.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_DEFAULT (64u * 1024u)
#define ALIGN 16u

struct chunk {
    struct chunk *next;
    size_t used;
    size_t cap;
    _Alignas(16) unsigned char mem[];
};

struct tw_arena {
    struct chunk *head;
};

struct tw_arena *tw_arena_new(void)
{
    return calloc(1, sizeof(struct tw_arena));
}

void tw_arena_free(struct tw_arena *a)
{
    if (!a) return;
    struct chunk *c = a->head;
    while (c) {
        struct chunk *n = c->next;
        free(c);
        c = n;
    }
    free(a);
}

void *tw_arena_alloc(struct tw_arena *a, size_t n)
{
    if (!a) return NULL;
    if (n == 0) n = 1;
    if (n > SIZE_MAX - ALIGN) return NULL;
    size_t need = (n + (ALIGN - 1)) & ~(size_t)(ALIGN - 1);

    struct chunk *c = a->head;
    if (!c || c->cap - c->used < need) {
        size_t cap = need > CHUNK_DEFAULT ? need : CHUNK_DEFAULT;
        if (cap > SIZE_MAX - sizeof(struct chunk)) return NULL;
        c = malloc(sizeof(struct chunk) + cap);
        if (!c) return NULL;
        c->used = 0;
        c->cap = cap;
        c->next = a->head;
        a->head = c;
    }
    void *p = c->mem + c->used;
    c->used += need;
    memset(p, 0, n);
    return p;
}

void *tw_arena_calloc(struct tw_arena *a, size_t count, size_t size)
{
    if (size != 0 && count > SIZE_MAX / size) return NULL;
    return tw_arena_alloc(a, count * size);
}

char *tw_arena_strndup(struct tw_arena *a, const char *s, size_t n)
{
    char *p = tw_arena_alloc(a, n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}
