#ifndef TWEAKWIN_WINFS_H
#define TWEAKWIN_WINFS_H

/*
 * Contained Windows-facing filesystem namespace (M4).
 *
 * The guest sees one drive, C:, whose root is a single configured host
 * directory. Paths are normalised lexically (so ".." can never climb above
 * the root) and then walked component by component against the host with
 * O_NOFOLLOW: a symlink anywhere below the root is refused, never followed.
 * Components match case-insensitively; an exact-case match wins, and an
 * ambiguous case-insensitive match is refused.
 *
 * All strings here are UTF-8. Error codes are Win32 error numbers.
 */

#include <stddef.h>
#include <stdint.h>

#define TW_WINFS_PATH_MAX 4096u
#define TW_WINFS_INVALID_ATTRS 0xFFFFFFFFu

/* Explicit root (host directory). Returns 0, or -1 if it is not a directory.
 * An explicit root is not replaced by tw_winfs_default_root. */
int tw_winfs_set_root(const char *host_dir);
/* Root = directory containing the executable, unless one was set explicitly
 * or via TWEAKWIN_FS_ROOT. */
void tw_winfs_default_root(const char *exe_path);
const char *tw_winfs_root(void);
void tw_winfs_reset(void);

/* Absolute virtual path ("C:\dir\file") from an absolute or relative input.
 * Returns 0 or a Win32 error. */
uint32_t tw_winfs_normalize(const char *in, int allow_wildcards, char *out, size_t cap);

/* Resolve an existing entry to a confined host path. Returns 0 or a Win32
 * error (FILE_NOT_FOUND, PATH_NOT_FOUND, ACCESS_DENIED, INVALID_NAME). */
uint32_t tw_winfs_resolve(const char *vpath, char *host, size_t cap, uint32_t *attrs);

uint32_t tw_winfs_getcwd(char *out, size_t cap);
uint32_t tw_winfs_setcwd(const char *path);

/* Attributes of an existing entry, or TW_WINFS_INVALID_ATTRS with *err set. */
uint32_t tw_winfs_attributes(const char *path, uint32_t *err);

/* DLL search path (virtual directories). */
void tw_winfs_search_clear(void);
uint32_t tw_winfs_search_add(const char *vdir);
/* Find a regular file for a library name. Search order: application
 * directory (C:\), current directory, configured search paths. A name that
 * contains a separator or drive is resolved directly. */
uint32_t tw_winfs_search_dll(const char *name, char *host, size_t host_cap,
                             char *virt, size_t virt_cap);

/* Directory enumeration. */
typedef struct {
    char name[256];
    uint32_t attrs;
    uint64_t size;
    uint64_t mtime_unix;
} tw_winfs_entry;

typedef struct tw_winfs_find tw_winfs_find;
uint32_t tw_winfs_find_open(const char *pattern, tw_winfs_find **out, tw_winfs_entry *first);
int tw_winfs_find_next(tw_winfs_find *f, tw_winfs_entry *e); /* 1 got one, 0 done */
void tw_winfs_find_close(tw_winfs_find *f);

#endif
