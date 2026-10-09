#include "k32priv.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int host_path(const char *in, char *out, size_t cap)
{
    if (!in || !in[0]) return TW_ERROR_INVALID_NAME;
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (n + 1 >= cap) return TW_ERROR_INVALID_NAME;
        unsigned char c = *p;
        if (c < 0x20 || c == '<' || c == '>' || c == '|' || c == '*' || c == '?' || c == '"')
            return TW_ERROR_INVALID_NAME;
        if (c == ':') return TW_ERROR_INVALID_NAME;
        if (c == '\\') c = '/';
        out[n++] = (char)c;
    }
    out[n] = '\0';
    if (out[0] == '/') return TW_ERROR_INVALID_NAME;

    const char *s = out;
    while (*s) {
        const char *e = s;
        while (*e && *e != '/') e++;
        size_t len = (size_t)(e - s);
        if (len == 0) return TW_ERROR_INVALID_NAME;
        if (len == 2 && s[0] == '.' && s[1] == '.') return TW_ERROR_INVALID_NAME;
        if (*e == '\0') break;
        s = e + 1;
        if (*s == '\0') return TW_ERROR_INVALID_NAME; /* trailing slash */
    }
    return 0;
}

static TW_HANDLE create_common(const char *host, TW_DWORD access, void *sa,
                               TW_DWORD disp, TW_DWORD flags, TW_HANDLE templ)
{
    if (sa || templ) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
    if (flags & 0xFF000000u) {
        /* FILE_FLAG_* including OVERLAPPED. Attributes in the low bits are ignored. */
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        TW_DEBUG(TW_DBG_FILESYSTEM, "CreateFile: flags 0x%x are not supported", flags);
        return TW_INVALID_HANDLE_VALUE;
    }
    int rd = (access & TW_GENERIC_READ) != 0;
    int wr = (access & TW_GENERIC_WRITE) != 0;
    if (!rd && !wr) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
    int of = O_CLOEXEC | O_NOFOLLOW;
    if (rd && wr) of |= O_RDWR;
    else if (wr) of |= O_WRONLY;
    else of |= O_RDONLY;
    switch (disp) {
    case TW_CREATE_NEW:        of |= O_CREAT | O_EXCL; break;
    case TW_CREATE_ALWAYS:     of |= O_CREAT | O_TRUNC; break;
    case TW_OPEN_EXISTING:     break;
    case TW_OPEN_ALWAYS:       of |= O_CREAT; break;
    case TW_TRUNCATE_EXISTING: of |= O_TRUNC; break;
    default:
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
    int fd = open(host, of, 0666);
    if (fd < 0) {
        TW_DEBUG(TW_DBG_FILESYSTEM, "CreateFile '%s': %s", host, strerror(errno));
        if (errno == EEXIST) tw_set_last_error(TW_ERROR_FILE_EXISTS);
        else if (errno == EACCES || errno == EPERM || errno == EISDIR) tw_set_last_error(TW_ERROR_ACCESS_DENIED);
        else if (errno == ENOTDIR || errno == ELOOP) tw_set_last_error(TW_ERROR_PATH_NOT_FOUND);
        else if (errno == ENOENT) {
            tw_set_last_error(disp == TW_OPEN_EXISTING || disp == TW_TRUNCATE_EXISTING
                                  ? TW_ERROR_FILE_NOT_FOUND
                                  : TW_ERROR_PATH_NOT_FOUND);
        } else tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
    TW_HANDLE h = tw_handle_alloc_file(fd, rd, wr);
    if (!h) {
        close(fd);
        tw_set_last_error(TW_ERROR_NOT_ENOUGH_MEMORY);
        return TW_INVALID_HANDLE_VALUE;
    }
    TW_DEBUG(TW_DBG_FILESYSTEM, "CreateFile '%s' -> handle %p fd %d", host, (void *)h, fd);
    return h;
}

TW_HANDLE TW_MS_ABI tw_k32_CreateFileA(const char *lpFileName, TW_DWORD dwDesiredAccess,
                                       TW_DWORD dwShareMode, void *lpSecurityAttributes,
                                       TW_DWORD dwCreationDisposition,
                                       TW_DWORD dwFlagsAndAttributes, TW_HANDLE hTemplateFile)
{
    (void)dwShareMode;
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
    const char *gs = NULL;
    size_t glen = 0;
    if (!lpFileName ||
        tw_guest_cstr(im, (uint64_t)(uintptr_t)lpFileName, TW_GUEST_CSTR_MAX, &gs, &glen) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_INVALID_HANDLE_VALUE;
    }
    char host[4096];
    int pr = host_path(gs, host, sizeof host);
    if (pr) {
        tw_set_last_error((uint32_t)pr);
        return TW_INVALID_HANDLE_VALUE;
    }
    return create_common(host, dwDesiredAccess, lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
}

TW_HANDLE TW_MS_ABI tw_k32_CreateFileW(const uint16_t *lpFileName, TW_DWORD dwDesiredAccess,
                                       TW_DWORD dwShareMode, void *lpSecurityAttributes,
                                       TW_DWORD dwCreationDisposition,
                                       TW_DWORD dwFlagsAndAttributes, TW_HANDLE hTemplateFile)
{
    (void)dwShareMode;
    struct tw_loaded *im = tw_k32_guest();
    if (!tw_runtime_bound() || !im) {
        tw_set_last_error(TW_ERROR_INVALID_PARAMETER);
        return TW_INVALID_HANDLE_VALUE;
    }
    const uint16_t *gs = NULL;
    size_t units = 0;
    if (!lpFileName ||
        tw_guest_wstr(im, (uint64_t)(uintptr_t)lpFileName, TW_GUEST_CSTR_MAX, &gs, &units) != 0) {
        tw_set_last_error(TW_ERROR_NOACCESS);
        return TW_INVALID_HANDLE_VALUE;
    }
    uint8_t utf[4096];
    size_t need = 0;
    int rc = tw_utf16_to_utf8(gs, (int)units, utf, sizeof utf, &need, 1);
    if (rc != 0) {
        tw_set_last_error(rc == -1 ? TW_ERROR_NO_UNICODE_TRANSLATION : TW_ERROR_INVALID_NAME);
        return TW_INVALID_HANDLE_VALUE;
    }
    char host[4096];
    int pr = host_path((const char *)utf, host, sizeof host);
    if (pr) {
        tw_set_last_error((uint32_t)pr);
        return TW_INVALID_HANDLE_VALUE;
    }
    return create_common(host, dwDesiredAccess, lpSecurityAttributes, dwCreationDisposition,
                         dwFlagsAndAttributes, hTemplateFile);
}
