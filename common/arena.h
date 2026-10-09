#ifndef TWEAKWIN_ARENA_H
#define TWEAKWIN_ARENA_H

#include <stddef.h>

/* Simple bump allocator: many small allocations, one free. */

struct tw_arena;

struct tw_arena *tw_arena_new(void);
void tw_arena_free(struct tw_arena *a);

/* Zeroed allocation. Returns NULL on overflow or OOM. */
void *tw_arena_alloc(struct tw_arena *a, size_t n);

/* Zeroed array allocation with overflow check. */
void *tw_arena_calloc(struct tw_arena *a, size_t count, size_t size);

char *tw_arena_strndup(struct tw_arena *a, const char *s, size_t n);

#endif
