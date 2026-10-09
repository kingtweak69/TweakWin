#ifndef TWEAKWIN_RT_OBJECT_H
#define TWEAKWIN_RT_OBJECT_H

/*
 * Win32 HANDLE <-> backend handle bridge for kernel objects (events,
 * semaphores, threads, processes, sections). A Win32 HANDLE here is an
 * opaque table index, never the backend handle and never a pointer. File
 * and heap handles keep living in runtime/handle.c; these values are drawn
 * from a disjoint range so CloseHandle can tell them apart.
 *
 * The NT layer stores backend handles; the Win32 layer stores these HANDLE
 * values. Each table entry remembers the object type so type checks and
 * NtQueryObject-style calls are exact.
 */

#include "../backend/kb.h"

#include <stdint.h>

typedef void *TW_HANDLE2; /* same width as runtime TW_HANDLE */

/* Object kind mirrors the backend type. */
int tw_obj_init(void);
void tw_obj_reset(void);

/* Install a backend handle; returns a Win32 HANDLE value, or NULL (and the
 * backend handle is closed on failure). */
void *tw_obj_install(tw_kh kh, int type);

/* Resolve a Win32 HANDLE to its backend handle and type. 0 on success. */
int tw_obj_lookup(void *h, tw_kh *kh, int *type);

/* Close a kernel-object HANDLE (and its backend handle). -1 if not one. */
int tw_obj_close(void *h);

/* True if `h` is in the kernel-object range at all. */
int tw_obj_is(void *h);

#endif
