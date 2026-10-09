#include "handle.h"

#include <unistd.h>

#define TW_HANDLE_SLOTS 64

struct tw_slot {
    int live;
    int kind;
    int fd;
    int readable;
    int writable;
    int owned;
    uint8_t gen;
    TW_HANDLE value;
};

static struct tw_slot g_slots[TW_HANDLE_SLOTS];
static TW_HANDLE g_std[3];
static int g_ready;

static int std_index(TW_DWORD n)
{
    if (n == TW_STD_INPUT_HANDLE) return 0;
    if (n == TW_STD_OUTPUT_HANDLE) return 1;
    if (n == TW_STD_ERROR_HANDLE) return 2;
    return -1;
}

static TW_HANDLE std_value(int i)
{
    if (i == 0) return TW_HANDLE_STDIN;
    if (i == 1) return TW_HANDLE_STDOUT;
    return TW_HANDLE_STDERR;
}

static struct tw_slot *find(TW_HANDLE h)
{
    if (!h || h == TW_INVALID_HANDLE_VALUE) return NULL;
    for (int i = 0; i < TW_HANDLE_SLOTS; i++) {
        if (g_slots[i].live && g_slots[i].value == h) return &g_slots[i];
    }
    return NULL;
}

int tw_handle_init(void)
{
    for (int i = 0; i < TW_HANDLE_SLOTS; i++) g_slots[i].live = 0;
    g_std[0] = g_std[1] = g_std[2] = NULL;
    g_ready = 1;
    return 0;
}

void tw_handle_shutdown(void)
{
    for (int i = 0; i < TW_HANDLE_SLOTS; i++) {
        if (g_slots[i].live && g_slots[i].kind == TW_HK_FILE && g_slots[i].owned && g_slots[i].fd >= 0)
            close(g_slots[i].fd);
        g_slots[i].live = 0;
    }
    g_std[0] = g_std[1] = g_std[2] = NULL;
    g_ready = 0;
}

static struct tw_slot *alloc_slot(void)
{
    for (int i = 3; i < TW_HANDLE_SLOTS; i++) {
        if (!g_slots[i].live) return &g_slots[i];
    }
    return NULL;
}

static TW_HANDLE encode(int index, uint8_t gen)
{
    /* 0x20000 + index*256 + gen. Never 0, -1, or the M1 std values. */
    uint32_t v = 0x20000u + ((uint32_t)index << 8) + (uint32_t)(gen ? gen : 1);
    return (TW_HANDLE)(uintptr_t)v;
}

int tw_handle_open_stdio(void)
{
    if (!g_ready && tw_handle_init() != 0) return -1;
    int fds[3];
    fds[0] = dup(STDIN_FILENO);
    fds[1] = dup(STDOUT_FILENO);
    fds[2] = dup(STDERR_FILENO);
    if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0) {
        for (int i = 0; i < 3; i++)
            if (fds[i] >= 0) close(fds[i]);
        return -1;
    }
    for (int i = 0; i < 3; i++) {
        struct tw_slot *s = &g_slots[i];
        s->live = 1;
        s->kind = TW_HK_FILE;
        s->fd = fds[i];
        s->owned = 1;
        s->readable = (i == 0);
        s->writable = (i != 0);
        s->gen = 1;
        s->value = std_value(i);
        g_std[i] = s->value;
    }
    return 0;
}

TW_HANDLE tw_handle_alloc_file(int fd, int readable, int writable)
{
    struct tw_slot *s = alloc_slot();
    if (!s || fd < 0) return NULL;
    uint8_t gen = (uint8_t)(s->gen + 1);
    if (gen == 0) gen = 1;
    s->gen = gen;
    s->live = 1;
    s->kind = TW_HK_FILE;
    s->fd = fd;
    s->owned = 1;
    s->readable = readable ? 1 : 0;
    s->writable = writable ? 1 : 0;
    s->value = encode((int)(s - g_slots), gen);
    return s->value;
}

TW_HANDLE tw_handle_alloc_heap(void)
{
    struct tw_slot *s = alloc_slot();
    if (!s) return NULL;
    uint8_t gen = (uint8_t)(s->gen + 1);
    if (gen == 0) gen = 1;
    s->gen = gen;
    s->live = 1;
    s->kind = TW_HK_HEAP;
    s->fd = -1;
    s->owned = 0;
    s->readable = 0;
    s->writable = 0;
    s->value = encode((int)(s - g_slots), gen);
    return s->value;
}

int tw_handle_kind(TW_HANDLE h)
{
    struct tw_slot *s = find(h);
    return s ? s->kind : TW_HK_EMPTY;
}

int tw_handle_fd(TW_HANDLE h, int *fd, int *readable, int *writable)
{
    struct tw_slot *s = find(h);
    if (!s || s->kind != TW_HK_FILE || s->fd < 0) return -1;
    if (fd) *fd = s->fd;
    if (readable) *readable = s->readable;
    if (writable) *writable = s->writable;
    return 0;
}

int tw_handle_is_heap(TW_HANDLE h)
{
    struct tw_slot *s = find(h);
    return s && s->kind == TW_HK_HEAP;
}

int tw_handle_close(TW_HANDLE h)
{
    struct tw_slot *s = find(h);
    if (!s || s->kind != TW_HK_FILE) return -1;
    if (s->owned && s->fd >= 0) close(s->fd);
    s->live = 0;
    s->fd = -1;
    s->owned = 0;
    return 0;
}

TW_HANDLE tw_std_get(TW_DWORD nStdHandle)
{
    int i = std_index(nStdHandle);
    if (i < 0) return TW_INVALID_HANDLE_VALUE;
    return g_std[i] ? g_std[i] : TW_INVALID_HANDLE_VALUE;
}

int tw_std_set(TW_DWORD nStdHandle, TW_HANDLE h)
{
    int i = std_index(nStdHandle);
    if (i < 0) return -1;
    if (tw_handle_kind(h) != TW_HK_FILE) return -1;
    g_std[i] = h;
    return 0;
}
