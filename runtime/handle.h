#ifndef TWEAKWIN_HANDLE_H
#define TWEAKWIN_HANDLE_H

/*
 * Windows HANDLE values are indexes into this table, never host file
 * descriptors and never pointers at TweakWin objects. Stdin/stdout/stderr
 * keep the M1 values 0x10/0x14/0x18.
 */

#include "winapi.h"

#include <stdint.h>

enum tw_handle_kind {
    TW_HK_EMPTY = 0,
    TW_HK_FILE = 1, /* host fd: a dup of stdio, or a CreateFile result */
    TW_HK_HEAP = 2
};

int tw_handle_init(void);
void tw_handle_shutdown(void);

/* Publish the three standard handles (dup'd host fds). Returns 0 on success. */
int tw_handle_open_stdio(void);

TW_HANDLE tw_handle_alloc_file(int fd, int readable, int writable);
TW_HANDLE tw_handle_alloc_heap(void);

int tw_handle_kind(TW_HANDLE h);

/* 0 and writes *fd when h is a live file. -1 otherwise. */
int tw_handle_fd(TW_HANDLE h, int *fd, int *readable, int *writable);

int tw_handle_is_heap(TW_HANDLE h);

/* Close a file handle and the host fd it owns. Heap handles are rejected. */
int tw_handle_close(TW_HANDLE h);

TW_HANDLE tw_std_get(TW_DWORD nStdHandle);
int tw_std_set(TW_DWORD nStdHandle, TW_HANDLE h);

#endif
