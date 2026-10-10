#define _GNU_SOURCE
#include "winfs.h"

#include "winapi.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_SEARCH 16
#define MAX_COMPS 256
#define MAX_FIND_ENTRIES 65536

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_root[PATH_MAX];
static int g_root_explicit;
static char g_cwd[TW_WINFS_PATH_MAX] = "C:\\";
static char g_search[MAX_SEARCH][TW_WINFS_PATH_MAX];
static size_t g_nsearch;

static int lc(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static int ieq(const char *a, const char *b)
{
    while (*a && lc((unsigned char)*a) == lc((unsigned char)*b)) a++, b++;
    return *a == *b;
}

const char *tw_winfs_root(void)
{
    return g_root[0] ? g_root : NULL;
}

static int set_root_locked(const char *dir)
{
    char rp[PATH_MAX];
    struct stat st;
    if (!dir || !realpath(dir, rp) || stat(rp, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
    snprintf(g_root, sizeof g_root, "%s", rp);
    snprintf(g_cwd, sizeof g_cwd, "C:\\");
    return 0;
}

int tw_winfs_set_root(const char *host_dir)
{
    pthread_mutex_lock(&g_mu);
    int rc = set_root_locked(host_dir);
    if (rc == 0) g_root_explicit = 1;
    pthread_mutex_unlock(&g_mu);
    return rc;
}

void tw_winfs_default_root(const char *exe_path)
{
    pthread_mutex_lock(&g_mu);
    if (!g_root_explicit) {
        const char *env = getenv("TWEAKWIN_FS_ROOT");
        if (env && env[0] && set_root_locked(env) == 0) {
            g_root_explicit = 1;
        } else if (exe_path) {
            char dir[PATH_MAX];
            snprintf(dir, sizeof dir, "%s", exe_path);
            char *s = strrchr(dir, '/');
            if (s) {
                if (s == dir) s[1] = '\0';
                else *s = '\0';
            } else {
                snprintf(dir, sizeof dir, ".");
            }
            set_root_locked(dir);
        }
    }
    pthread_mutex_unlock(&g_mu);
}

void tw_winfs_reset(void)
{
    pthread_mutex_lock(&g_mu);
    g_root[0] = '\0';
    g_root_explicit = 0;
    snprintf(g_cwd, sizeof g_cwd, "C:\\");
    g_nsearch = 0;
    pthread_mutex_unlock(&g_mu);
}

/* ---- lexical normalisation ---- */

static int bad_char(unsigned char c, int allow_wild)
{
    if (c < 0x20) return 1;
    if (c == '<' || c == '>' || c == '"' || c == '|' || c == ':') return 1;
    if ((c == '*' || c == '?') && !allow_wild) return 1;
    return 0;
}

static uint32_t normalize_locked(const char *in, int allow_wild, char *out, size_t cap)
{
    if (!in || !in[0]) return TW_ERROR_INVALID_NAME;
    size_t len = strlen(in);
    if (len >= TW_WINFS_PATH_MAX) return TW_ERROR_INVALID_NAME;

    char work[TW_WINFS_PATH_MAX * 2];
    const char *p = in;
    int has_drive = 0;
    if (len >= 2 && in[1] == ':') {
        if (lc((unsigned char)in[0]) != 'c') return TW_ERROR_PATH_NOT_FOUND;
        p = in + 2;
        has_drive = 1;
    }
    int rooted = *p == '\\' || *p == '/';
    if (rooted && !has_drive && (p[1] == '\\' || p[1] == '/')) return TW_ERROR_INVALID_NAME; /* UNC, \\?\ */
    if (rooted) work[0] = '\0';
    else snprintf(work, sizeof work, "%s", g_cwd + 2);
    size_t wl = strlen(work);
    if (wl + 1 + strlen(p) + 1 >= sizeof work) return TW_ERROR_INVALID_NAME;
    work[wl++] = '\\';
    snprintf(work + wl, sizeof work - wl, "%s", p);

    const char *comps[MAX_COMPS];
    size_t lens[MAX_COMPS];
    size_t n = 0;
    char *s = work;
    while (*s) {
        while (*s == '\\' || *s == '/') s++;
        if (!*s) break;
        char *e = s;
        while (*e && *e != '\\' && *e != '/') e++;
        size_t l = (size_t)(e - s);
        for (size_t i = 0; i < l; i++)
            if (bad_char((unsigned char)s[i], allow_wild)) return TW_ERROR_INVALID_NAME;
        while (l > 0 && (s[l - 1] == '.' || s[l - 1] == ' ') ) {
            if (l == 1 && s[0] == '.') break;
            if (l == 2 && s[0] == '.' && s[1] == '.') break;
            l--;
        }
        if (l == 0) return TW_ERROR_INVALID_NAME;
        if (l == 1 && s[0] == '.') {
            /* current directory */
        } else if (l == 2 && s[0] == '.' && s[1] == '.') {
            if (n) n--;
        } else {
            if (n >= MAX_COMPS) return TW_ERROR_INVALID_NAME;
            comps[n] = s;
            lens[n] = l;
            n++;
        }
        s = *e ? e + 1 : e;
    }
    size_t o = 0;
    if (cap < 4) return TW_ERROR_INSUFFICIENT_BUFFER;
    out[o++] = 'C';
    out[o++] = ':';
    out[o++] = '\\';
    for (size_t i = 0; i < n; i++) {
        if (o + lens[i] + 2 > cap) return TW_ERROR_INSUFFICIENT_BUFFER;
        memcpy(out + o, comps[i], lens[i]);
        o += lens[i];
        if (i + 1 < n) out[o++] = '\\';
    }
    out[o] = '\0';
    return 0;
}

uint32_t tw_winfs_normalize(const char *in, int allow_wildcards, char *out, size_t cap)
{
    pthread_mutex_lock(&g_mu);
    uint32_t r = normalize_locked(in, allow_wildcards, out, cap);
    pthread_mutex_unlock(&g_mu);
    return r;
}

/* ---- host resolution ---- */

static uint32_t attrs_of(const struct stat *st)
{
    uint32_t a = S_ISDIR(st->st_mode) ? 0x10u : 0u;
    if (!(st->st_mode & 0222)) a |= 0x1u;
    if (a == 0) a = 0x80u;
    return a;
}

/* Find the entry of `dfd` matching `want` (exact first, then unique
 * case-insensitive). 0 ok, 1 missing, 2 ambiguous. */
static int match_entry(int dfd, const char *want, char *found, size_t cap, struct stat *st)
{
    if (strlen(want) < cap && fstatat(dfd, want, st, AT_SYMLINK_NOFOLLOW) == 0) {
        snprintf(found, cap, "%s", want);
        return 0;
    }
    int fd = openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return 1;
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return 1;
    }
    int hits = 0;
    char hit[256];
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (ieq(de->d_name, want)) {
            if (hits == 0) snprintf(hit, sizeof hit, "%s", de->d_name);
            hits++;
        }
    }
    closedir(d);
    if (hits == 0) return 1;
    if (hits > 1) return 2;
    if (fstatat(dfd, hit, st, AT_SYMLINK_NOFOLLOW) != 0) return 1;
    snprintf(found, cap, "%s", hit);
    return 0;
}

static uint32_t resolve_locked(const char *vpath, char *host, size_t cap, uint32_t *attrs)
{
    char norm[TW_WINFS_PATH_MAX];
    uint32_t e = normalize_locked(vpath, 0, norm, sizeof norm);
    if (e) return e;
    if (!g_root[0]) return TW_ERROR_PATH_NOT_FOUND;

    int dfd = open(g_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return TW_ERROR_PATH_NOT_FOUND;
    char hp[PATH_MAX];
    snprintf(hp, sizeof hp, "%s", g_root);
    struct stat st;
    if (fstat(dfd, &st) != 0) {
        close(dfd);
        return TW_ERROR_PATH_NOT_FOUND;
    }

    const char *s = norm + 3;
    while (*s) {
        const char *end = strchr(s, '\\');
        size_t l = end ? (size_t)(end - s) : strlen(s);
        char comp[256];
        if (l == 0 || l >= sizeof comp) {
            close(dfd);
            return TW_ERROR_INVALID_NAME;
        }
        memcpy(comp, s, l);
        comp[l] = '\0';
        char found[256];
        int m = match_entry(dfd, comp, found, sizeof found, &st);
        if (m != 0) {
            close(dfd);
            if (m == 2) return TW_ERROR_ACCESS_DENIED;
            return end ? TW_ERROR_PATH_NOT_FOUND : TW_ERROR_FILE_NOT_FOUND;
        }
        if (S_ISLNK(st.st_mode)) {
            close(dfd);
            return TW_ERROR_ACCESS_DENIED;
        }
        size_t hl = strlen(hp);
        if (hl + 1 + strlen(found) + 1 > sizeof hp) {
            close(dfd);
            return TW_ERROR_INVALID_NAME;
        }
        hp[hl] = '/';
        strcpy(hp + hl + 1, found);
        if (!end) break;
        if (!S_ISDIR(st.st_mode)) {
            close(dfd);
            return TW_ERROR_PATH_NOT_FOUND;
        }
        int nfd = openat(dfd, found, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dfd);
        if (nfd < 0) return TW_ERROR_ACCESS_DENIED;
        dfd = nfd;
        s = end + 1;
    }
    close(dfd);
    if (host) {
        if (strlen(hp) >= cap) return TW_ERROR_INSUFFICIENT_BUFFER;
        strcpy(host, hp);
    }
    if (attrs) *attrs = attrs_of(&st);
    return 0;
}

uint32_t tw_winfs_resolve(const char *vpath, char *host, size_t cap, uint32_t *attrs)
{
    pthread_mutex_lock(&g_mu);
    uint32_t r = resolve_locked(vpath, host, cap, attrs);
    pthread_mutex_unlock(&g_mu);
    return r;
}

uint32_t tw_winfs_attributes(const char *path, uint32_t *err)
{
    uint32_t a = 0;
    uint32_t e = tw_winfs_resolve(path, NULL, 0, &a);
    if (e) {
        if (err) *err = e;
        return TW_WINFS_INVALID_ATTRS;
    }
    return a;
}

uint32_t tw_winfs_getcwd(char *out, size_t cap)
{
    pthread_mutex_lock(&g_mu);
    size_t n = strlen(g_cwd);
    uint32_t r = 0;
    if (n + 1 > cap) r = TW_ERROR_INSUFFICIENT_BUFFER;
    else memcpy(out, g_cwd, n + 1);
    pthread_mutex_unlock(&g_mu);
    return r;
}

uint32_t tw_winfs_setcwd(const char *path)
{
    pthread_mutex_lock(&g_mu);
    char norm[TW_WINFS_PATH_MAX];
    uint32_t e = normalize_locked(path, 0, norm, sizeof norm);
    uint32_t attrs = 0;
    if (!e) e = resolve_locked(norm, NULL, 0, &attrs);
    if (!e && !(attrs & 0x10u)) e = TW_ERROR_DIRECTORY;
    if (!e) snprintf(g_cwd, sizeof g_cwd, "%s", norm);
    pthread_mutex_unlock(&g_mu);
    return e;
}

/* ---- DLL search ---- */

void tw_winfs_search_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_nsearch = 0;
    pthread_mutex_unlock(&g_mu);
}

uint32_t tw_winfs_search_add(const char *vdir)
{
    pthread_mutex_lock(&g_mu);
    uint32_t e = 0;
    if (g_nsearch >= MAX_SEARCH) {
        e = TW_ERROR_NOT_ENOUGH_MEMORY;
    } else {
        e = normalize_locked(vdir, 0, g_search[g_nsearch], sizeof g_search[0]);
        if (!e) g_nsearch++;
    }
    pthread_mutex_unlock(&g_mu);
    return e;
}

static uint32_t try_in_dir(const char *dir, const char *nm, char *host, size_t hc, char *virt, size_t vc);

static uint32_t try_file(const char *vpath, char *host, size_t hc, char *virt, size_t vc)
{
    uint32_t attrs = 0;
    uint32_t e = resolve_locked(vpath, host, hc, &attrs);
    if (e) return e;
    if (attrs & 0x10u) return TW_ERROR_FILE_NOT_FOUND;
    char norm[TW_WINFS_PATH_MAX];
    if (normalize_locked(vpath, 0, norm, sizeof norm)) return TW_ERROR_INVALID_NAME;
    if (strlen(norm) >= vc) return TW_ERROR_INSUFFICIENT_BUFFER;
    strcpy(virt, norm);
    return 0;
}

static uint32_t try_in_dir(const char *dir, const char *nm, char *host, size_t hc, char *virt, size_t vc)
{
    char cand[2 * TW_WINFS_PATH_MAX + 8];
    size_t dl = strnlen(dir, TW_WINFS_PATH_MAX);
    size_t nl = strnlen(nm, TW_WINFS_PATH_MAX);
    if (dl >= TW_WINFS_PATH_MAX || nl >= TW_WINFS_PATH_MAX) return TW_ERROR_INVALID_NAME;
    memcpy(cand, dir, dl);
    if (dl > 3) cand[dl++] = '\\';
    memcpy(cand + dl, nm, nl + 1);
    return try_file(cand, host, hc, virt, vc);
}

uint32_t tw_winfs_search_dll(const char *name, char *host, size_t hc, char *virt, size_t vc)
{
    if (!name || !name[0]) return TW_ERROR_INVALID_PARAMETER;
    char nm[TW_WINFS_PATH_MAX];
    size_t n = strlen(name);
    if (n + 5 >= sizeof nm) return TW_ERROR_INVALID_NAME;
    memcpy(nm, name, n + 1);
    const char *base = nm;
    for (const char *q = nm; *q; q++)
        if (*q == '\\' || *q == '/' || *q == ':') base = q + 1;
    if (!strchr(base, '.')) strcat(nm, ".dll");
    else if (nm[strlen(nm) - 1] == '.') nm[strlen(nm) - 1] = '\0';
    int has_path = base != nm;

    pthread_mutex_lock(&g_mu);
    uint32_t r;
    if (has_path) {
        r = try_file(nm, host, hc, virt, vc);
    } else {
        r = try_in_dir("C:\\", nm, host, hc, virt, vc);
        if (r == TW_ERROR_FILE_NOT_FOUND) r = try_in_dir(g_cwd, nm, host, hc, virt, vc);
        for (size_t i = 0; r != 0 && i < g_nsearch && i < MAX_SEARCH; i++)
            r = try_in_dir(g_search[i], nm, host, hc, virt, vc);
        if (r != 0) r = TW_ERROR_MOD_NOT_FOUND;
    }
    pthread_mutex_unlock(&g_mu);
    return r;
}

/* ---- enumeration ---- */

struct tw_winfs_find {
    tw_winfs_entry *ents;
    size_t n, pos;
};

static int wild_match(const char *p, const char *s)
{
    while (*p) {
        if (*p == '*') {
            while (*p == '*') p++;
            if (!*p) return 1;
            for (; *s; s++)
                if (wild_match(p, s)) return 1;
            return wild_match(p, s);
        }
        if (!*s) return 0;
        if (*p != '?' && lc((unsigned char)*p) != lc((unsigned char)*s)) return 0;
        p++, s++;
    }
    return *s == '\0';
}

static int cmp_entry(const void *a, const void *b)
{
    const tw_winfs_entry *x = a, *y = b;
    const char *p = x->name, *q = y->name;
    while (*p && lc((unsigned char)*p) == lc((unsigned char)*q)) p++, q++;
    int d = lc((unsigned char)*p) - lc((unsigned char)*q);
    return d ? d : strcmp(x->name, y->name);
}

static int name_ok(const char *nm)
{
    if (!nm[0]) return 0;
    for (const unsigned char *p = (const unsigned char *)nm; *p; p++)
        if (bad_char(*p, 0) || *p == '\\' || *p == '/') return 0;
    return 1;
}

uint32_t tw_winfs_find_open(const char *pattern, tw_winfs_find **out, tw_winfs_entry *first)
{
    *out = NULL;
    pthread_mutex_lock(&g_mu);
    char norm[TW_WINFS_PATH_MAX];
    uint32_t e = normalize_locked(pattern, 1, norm, sizeof norm);
    char *last = e ? NULL : strrchr(norm, '\\');
    char dir[TW_WINFS_PATH_MAX], pat[256];
    if (!e) {
        size_t dl = (size_t)(last - norm);
        if (dl <= 2) snprintf(dir, sizeof dir, "C:\\");
        else snprintf(dir, sizeof dir, "%.*s", (int)dl, norm);
        const char *pp = last + 1;
        if (!*pp || strlen(pp) >= sizeof pat) e = TW_ERROR_FILE_NOT_FOUND;
        else snprintf(pat, sizeof pat, "%s", strcmp(pp, "*.*") == 0 ? "*" : pp);
    }
    char host[PATH_MAX];
    uint32_t attrs = 0;
    if (!e) {
        /* A pattern naming a missing directory is PATH_NOT_FOUND. */
        e = resolve_locked(dir, host, sizeof host, &attrs);
        if (e == TW_ERROR_FILE_NOT_FOUND) e = TW_ERROR_PATH_NOT_FOUND;
        if (!e && !(attrs & 0x10u)) e = TW_ERROR_PATH_NOT_FOUND;
    }
    tw_winfs_find *f = NULL;
    if (!e) {
        f = calloc(1, sizeof *f);
        DIR *d = f ? opendir(host) : NULL;
        if (!d) {
            free(f);
            f = NULL;
            e = TW_ERROR_ACCESS_DENIED;
        } else {
            int dfd = dirfd(d);
            size_t cap = 0;
            struct dirent *de;
            int is_root = strcmp(dir, "C:\\") == 0;
            while ((de = readdir(d)) != NULL && !e) {
                const char *nm = de->d_name;
                int dots = strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0;
                if (dots && is_root) continue;
                if (!dots && !name_ok(nm)) continue;
                if (strlen(nm) >= sizeof f->ents[0].name || !wild_match(pat, nm)) continue;
                struct stat st;
                if (fstatat(dfd, nm, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
                if (S_ISLNK(st.st_mode)) continue; /* never expose links */
                if (f->n >= MAX_FIND_ENTRIES) break;
                if (f->n == cap) {
                    cap = cap ? cap * 2 : 16;
                    tw_winfs_entry *ne = realloc(f->ents, cap * sizeof *ne);
                    if (!ne) {
                        e = TW_ERROR_NOT_ENOUGH_MEMORY;
                        break;
                    }
                    f->ents = ne;
                }
                tw_winfs_entry *x = &f->ents[f->n++];
                snprintf(x->name, sizeof x->name, "%s", nm);
                x->attrs = attrs_of(&st);
                x->size = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
                x->mtime_unix = st.st_mtime > 0 ? (uint64_t)st.st_mtime : 0;
            }
            closedir(d);
            if (!e && f->n == 0) e = TW_ERROR_FILE_NOT_FOUND;
        }
    }
    pthread_mutex_unlock(&g_mu);
    if (e) {
        if (f) {
            free(f->ents);
            free(f);
        }
        return e;
    }
    qsort(f->ents, f->n, sizeof *f->ents, cmp_entry);
    *first = f->ents[0];
    f->pos = 1;
    *out = f;
    return 0;
}

int tw_winfs_find_next(tw_winfs_find *f, tw_winfs_entry *e)
{
    if (!f || f->pos >= f->n) return 0;
    *e = f->ents[f->pos++];
    return 1;
}

void tw_winfs_find_close(tw_winfs_find *f)
{
    if (!f) return;
    free(f->ents);
    free(f);
}
