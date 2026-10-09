#ifndef TWEAKWIN_KB_H
#define TWEAKWIN_KB_H

/*
 * TweakWin kernel backend ("kb").
 *
 * This is the only layer that talks to a kernel. Everything above it (NT
 * layer, loader, Win32 DLLs) calls these functions and never sees a
 * syscall number. The contract is TweakKernel M4's (v0.5.0-m4, ABI 2):
 * process-local generation-checked handles with rights, wait-one/wait-any
 * satisfied at signal time in FIFO order, auto-reset consumption by exactly
 * one waiter, page-granular reserve/commit/decommit/release/protect with
 * W^X, sections whose writable and executable views are mutually
 * exclusive, and an exception handler that receives a 192-byte record on
 * the faulting thread's stack.
 *
 * Two implementations exist:
 *
 *   kb_tweakkernel.c  TweakKernel M4, raw SYSCALL (freestanding).
 *   kb_host.c         Linux host. Re-implements the M4 object model in
 *                     userspace so the layers above run the same code
 *                     paths they will run on TweakKernel. It does not
 *                     add M5 behaviour (no wait-all, no mutexes, ...).
 *
 * The host backend also provides "host services" (files, console streams,
 * spawning another personality process) that M4 does not have. They are
 * capability-gated (TW_KB_CAP_HOST_*) and return TW_KB_ENOSYS on M4.
 *
 * Results: 0 or a positive value is success; negative is a TW_KB_E* code.
 * The values match TweakKernel's -TWEAK_ERR_* so the M4 backend passes them
 * through unchanged. They are backend errors, not NTSTATUS and not Win32
 * error codes. nt/status.c translates them.
 */

#include <stddef.h>
#include <stdint.h>

/* ---- errors (== -TWEAK_ERR_*) ---- */
#define TW_KB_OK      0
#define TW_KB_ENOSYS (-1) /* call or feature not provided by this backend */
#define TW_KB_EFAULT (-2) /* address range not usable */
#define TW_KB_EINVAL (-3) /* argument rejected */
#define TW_KB_ENOMEM (-4) /* no memory, handle slot, region slot, ... */
#define TW_KB_EBADH  (-5) /* stale, zero, wrong-type or foreign handle */
#define TW_KB_EPERM  (-6) /* handle lacks the right */
#define TW_KB_EAGAIN (-7)
#define TW_KB_ESTATE (-8) /* object/range state forbids the call */
/* Host-service-only errors (never produced by the M4 backend). */
#define TW_KB_ENOENT  (-32)
#define TW_KB_EEXIST  (-33)
#define TW_KB_EACCES  (-34)
#define TW_KB_EISDIR  (-35)
#define TW_KB_ENOTDIR (-36)
#define TW_KB_EIO     (-37)
#define TW_KB_ELOOP   (-38)
#define TW_KB_ENOTEMPTY (-39)

/* Positive wait result. */
#define TW_KB_WAIT_TIMEOUT 0x102

/* Timeouts are nanoseconds. */
#define TW_KB_INFINITE (~(uint64_t)0)

typedef int64_t tw_kh; /* backend handle; > 0 when valid */

/* ---- object types and rights (TweakKernel M4 values) ---- */
#define TW_KB_TYPE_MAP       1
#define TW_KB_TYPE_PORT      2
#define TW_KB_TYPE_PROCESS   3
#define TW_KB_TYPE_THREAD    4
#define TW_KB_TYPE_EVENT     5
#define TW_KB_TYPE_SEMAPHORE 6
#define TW_KB_TYPE_SECTION   7

#define TW_KB_RIGHT_READ   1u
#define TW_KB_RIGHT_WRITE  2u
#define TW_KB_RIGHT_SEND   4u
#define TW_KB_RIGHT_RECV   8u
#define TW_KB_RIGHT_WAIT   16u
#define TW_KB_RIGHT_MANAGE 32u
#define TW_KB_RIGHT_SIGNAL 64u
#define TW_KB_RIGHT_EXEC   128u
#define TW_KB_RIGHT_QUERY  256u

/* ---- page protection (M4 encoding; W+X does not exist) ---- */
#define TW_KB_PROT_NONE 0u
#define TW_KB_PROT_R    1u
#define TW_KB_PROT_RW   3u
#define TW_KB_PROT_RX   5u

#define TW_KB_VM_COMMIT 1u /* vm_reserve flag */

#define TW_KB_VM_FREE      1u
#define TW_KB_VM_RESERVED  2u
#define TW_KB_VM_COMMITTED 3u

#define TW_KB_VMT_NONE    0u
#define TW_KB_VMT_FIXED   1u
#define TW_KB_VMT_PRIVATE 2u
#define TW_KB_VMT_SECTION 3u

#define TW_KB_EVENT_MANUAL   1u
#define TW_KB_EVENT_SIGNALED 2u

#define TW_KB_EXIT_NORMAL 1u
#define TW_KB_EXIT_FAULT  2u
#define TW_KB_EXIT_KILLED 3u

#define TW_KB_EXC_CONTINUE  0u
#define TW_KB_EXC_TERMINATE 1u

#define TW_KB_TLS_FS 0
#define TW_KB_TLS_GS 1

/* ---- fixed-width structures (M4 v1 layouts) ---- */

typedef struct {
    uint32_t size;   /* 32 */
    uint32_t reason; /* TW_KB_EXIT_* */
    int64_t status;  /* 32-bit status, sign-extended */
    uint64_t detail; /* fault vector for TW_KB_EXIT_FAULT */
    uint64_t id;     /* process or thread id */
} tw_kb_exitinfo;

typedef struct {
    uint64_t base, size;               /* page-aligned run of identical state/prot */
    uint64_t region_base, region_size; /* containing reservation, or free gap */
    uint32_t state;                    /* TW_KB_VM_FREE / RESERVED / COMMITTED */
    uint32_t prot;                     /* TW_KB_PROT_* (0 unless committed) */
    uint32_t type;                     /* TW_KB_VMT_* */
    uint32_t reserved;
} tw_kb_vminfo;

typedef struct {
    uint32_t size;    /* 192 */
    uint32_t version; /* 1 */
    uint64_t vector, error_code, fault_address;
    uint64_t rip, rsp, rflags;
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t reserved[2];
} tw_kb_excrec;

#define TW_KB_EXC_RECORD_SIZE 192u
#define TW_KB_EXC_VERSION 1u

/* x86 vectors as delivered in tw_kb_exc_record.vector */
#define TW_KB_VEC_DE 0
#define TW_KB_VEC_DB 1
#define TW_KB_VEC_BP 3
#define TW_KB_VEC_OF 4
#define TW_KB_VEC_BR 5
#define TW_KB_VEC_UD 6
#define TW_KB_VEC_NM 7
#define TW_KB_VEC_TS 10
#define TW_KB_VEC_NP 11
#define TW_KB_VEC_SS 12
#define TW_KB_VEC_GP 13
#define TW_KB_VEC_PF 14
#define TW_KB_VEC_MF 16
#define TW_KB_VEC_AC 17
#define TW_KB_VEC_XM 19

/* ---- capabilities ---- */

/* M4 baseline. Both backends set all of these. */
#define TW_KB_CAP_THREADS     (1ull << 0)
#define TW_KB_CAP_TLS_GS      (1ull << 1)
#define TW_KB_CAP_WAIT_ANY    (1ull << 2)
#define TW_KB_CAP_EVENTS      (1ull << 3)
#define TW_KB_CAP_SEMAPHORES  (1ull << 4)
#define TW_KB_CAP_DUP         (1ull << 5)
#define TW_KB_CAP_VM          (1ull << 6)
#define TW_KB_CAP_SECTIONS    (1ull << 7)
#define TW_KB_CAP_EXCEPTIONS  (1ull << 8)
#define TW_KB_CAP_FPU_SSE     (1ull << 9)

/* Expected from TweakKernel M5. Neither backend sets these today; the NT
 * layer checks them before taking a native path and otherwise uses the
 * documented M4 fallback (or STATUS_NOT_IMPLEMENTED). See
 * docs/KERNEL-REQUIREMENTS.md. */
#define TW_KB_CAP_WAIT_ALL         (1ull << 16)
#define TW_KB_CAP_MUTEX            (1ull << 17)
#define TW_KB_CAP_APC              (1ull << 18)
#define TW_KB_CAP_SUSPEND_RESUME   (1ull << 19)
#define TW_KB_CAP_THREAD_CONTEXT   (1ull << 20)
#define TW_KB_CAP_GROWABLE_HANDLES (1ull << 21)
#define TW_KB_CAP_NAMED_OBJECTS    (1ull << 22)
#define TW_KB_CAP_IMAGE_SECTIONS   (1ull << 23)
#define TW_KB_CAP_ASYNC_IO         (1ull << 24)
#define TW_KB_CAP_COMPLETION_QUEUE (1ull << 25)
#define TW_KB_CAP_XSAVE            (1ull << 26)

/* Host services: not part of any TweakKernel milestone. */
#define TW_KB_CAP_HOST_FILES   (1ull << 40)
#define TW_KB_CAP_HOST_CONSOLE (1ull << 41)
#define TW_KB_CAP_HOST_SPAWN   (1ull << 42)

#define TW_KB_CAPS_M4                                                                  \
    (TW_KB_CAP_THREADS | TW_KB_CAP_TLS_GS | TW_KB_CAP_WAIT_ANY | TW_KB_CAP_EVENTS |    \
     TW_KB_CAP_SEMAPHORES | TW_KB_CAP_DUP | TW_KB_CAP_VM | TW_KB_CAP_SECTIONS |        \
     TW_KB_CAP_EXCEPTIONS | TW_KB_CAP_FPU_SSE)

#define TW_KB_CAPS_M5                                                                  \
    (TW_KB_CAP_WAIT_ALL | TW_KB_CAP_MUTEX | TW_KB_CAP_APC | TW_KB_CAP_SUSPEND_RESUME | \
     TW_KB_CAP_THREAD_CONTEXT | TW_KB_CAP_GROWABLE_HANDLES | TW_KB_CAP_NAMED_OBJECTS | \
     TW_KB_CAP_IMAGE_SECTIONS | TW_KB_CAP_ASYNC_IO | TW_KB_CAP_COMPLETION_QUEUE |     \
     TW_KB_CAP_XSAVE)

typedef struct {
    const char *name;        /* "host-linux" or "tweakkernel-m4" */
    uint32_t abi_version;    /* TweakKernel ABI_INFO(0); 2 for M4 */
    uint32_t syscall_count;  /* ABI_INFO(1); 48 for M4 */
    uint64_t kernel_features;/* ABI_INFO(2) raw bits (host: synthetic) */
    uint64_t caps;           /* TW_KB_CAP_* */
    /* Limits the layers above must respect. */
    uint32_t max_handles;    /* per process (M4: 16) */
    uint32_t max_threads;    /* live threads per process (M4: 16) */
    uint32_t max_vm_regions; /* reservations + views + fixed (M4: 64) */
    uint32_t max_wait;       /* handles per wait_any (M4: 8) */
    uint64_t max_commit;     /* bytes per commit call (M4: 16 MiB) */
    uint64_t max_reserve;    /* bytes per reservation (M4: 64 GiB) */
    uint64_t max_section;    /* bytes per section (M4: 4 MiB) */
    uint64_t vm_min, vm_limit; /* usable [min, limit) */
    uint64_t timer_ns;       /* wait/sleep granularity (M4: 10 ms) */
} tw_kb_info_t;

/* ---- lifecycle ---- */

/* Idempotent. Detects capabilities. Returns TW_KB_OK or a TW_KB_E*. */
int tw_kb_init(void);
const tw_kb_info_t *tw_kb_info(void);
static inline int tw_kb_has(uint64_t cap);

/* ---- misc ---- */
int64_t tw_kb_debug_write(const void *buf, size_t len);
uint64_t tw_kb_time_ns(void);           /* monotonic */
int tw_kb_sleep_ns(uint64_t ns);        /* 0 yields */
uint64_t tw_kb_process_id(void);
uint64_t tw_kb_thread_id(void);

/* ---- threads ---- */

/* New thread in this process: starts at `entry` with RSP = `stack`,
 * RDI = `arg`, other GPRs zero, GS base = `gs_base`, fixed FP image. The
 * caller owns the stack memory and the return address on it. Returns a
 * thread handle (WAIT | QUERY | MANAGE). */
tw_kh tw_kb_thread_create(uint64_t entry, uint64_t stack, uint64_t arg, uint64_t gs_base);

/* Exit the calling thread. The last thread's exit ends the process. */
__attribute__((noreturn)) void tw_kb_thread_exit(int32_t status);

/* Run guest code on the *calling* thread: switch to `stack`, RDI = `arg`,
 * GS base = `gs_base`, jump to `entry`. Returns when the calling thread
 * later calls tw_kb_thread_exit (*how = 1) or tw_kb_process_exit while it
 * is the only thread (*how = 2), with that status. On TweakKernel the
 * thread/process really ends and this never returns. */
int32_t tw_kb_run_on_stack(uint64_t entry, uint64_t stack, uint64_t arg, uint64_t gs_base, int *how);

/* End the whole process with `status`. */
__attribute__((noreturn)) void tw_kb_process_exit(int32_t status);

int tw_kb_tls_set(int which, uint64_t base);
uint64_t tw_kb_tls_get(int which);

/* ---- waits and sync ---- */
int64_t tw_kb_wait_one(tw_kh h, uint64_t timeout_ns);
int64_t tw_kb_wait_any(const tw_kh *hs, uint32_t count, uint64_t timeout_ns);

tw_kh tw_kb_event_create(uint32_t flags);
int64_t tw_kb_event_set(tw_kh h);   /* previous state */
int64_t tw_kb_event_reset(tw_kh h); /* previous state */

tw_kh tw_kb_sem_create(uint32_t initial, uint32_t max);
int64_t tw_kb_sem_release(tw_kh h, uint32_t count); /* previous count */

/* ---- handles ---- */
tw_kh tw_kb_dup(tw_kh h, uint32_t rights, tw_kh target_process /* 0 = self */);
int64_t tw_kb_handle_info(tw_kh h); /* (type << 32) | rights */
int tw_kb_close(tw_kh h);
int tw_kb_exit_info(tw_kh h, tw_kb_exitinfo *out);
int tw_kb_process_terminate(tw_kh process, int32_t status);

/* ---- virtual memory ---- */
int64_t tw_kb_vm_reserve(uint64_t base, uint64_t size, uint32_t prot, uint32_t flags);
int tw_kb_vm_commit(uint64_t addr, uint64_t size, uint32_t prot);
int tw_kb_vm_decommit(uint64_t addr, uint64_t size);
int tw_kb_vm_release(uint64_t base);
int64_t tw_kb_vm_protect(uint64_t addr, uint64_t size, uint32_t prot); /* old prot */
int tw_kb_vm_query(uint64_t addr, tw_kb_vminfo *out);

/* ---- sections ---- */
tw_kh tw_kb_section_create(uint64_t size);
int64_t tw_kb_section_map(tw_kh section, uint64_t base, uint32_t prot, uint64_t offset, uint64_t size);
int tw_kb_section_unmap(uint64_t view_base);

/* ---- exceptions ---- */

/* Process-wide handler entry, or 0 to remove. Returns the previous entry.
 * The handler is entered on the faulting thread with RDI = record,
 * RSP = record - 8 (a zero return slot), RFLAGS = 0x202. It must call
 * tw_kb_exc_return. A fault while a thread is in its handler, or an
 * unwritable stack, ends the process (reason FAULT). */
uint64_t tw_kb_exc_handler(uint64_t entry);
/* CONTINUE resumes the (possibly edited) record context and does not
 * return on success. TERMINATE ends the process. Errors return. */
int tw_kb_exc_return(tw_kb_excrec *rec, uint32_t action);

/* ======================================================================
 * Host services (TW_KB_CAP_HOST_*). Not provided by TweakKernel M4.
 * Paths here are backend-native strings produced by the TweakWin VFS
 * (runtime/vfs.c); Win32 code never builds them.
 * ====================================================================== */

#define TW_KB_O_READ      0x01u
#define TW_KB_O_WRITE     0x02u
#define TW_KB_O_CREATE    0x04u
#define TW_KB_O_EXCL      0x08u
#define TW_KB_O_TRUNC     0x10u
#define TW_KB_O_APPEND    0x20u
#define TW_KB_O_NOFOLLOW  0x40u
#define TW_KB_O_DIRECTORY 0x80u

#define TW_KB_FT_UNKNOWN 0u
#define TW_KB_FT_FILE    1u
#define TW_KB_FT_DIR     2u
#define TW_KB_FT_CHAR    3u
#define TW_KB_FT_PIPE    4u

typedef struct {
    uint32_t type;      /* TW_KB_FT_* */
    uint32_t readonly;  /* owner write bit clear */
    uint64_t size;
    int64_t mtime_ns;   /* since 1970-01-01 UTC */
    int64_t atime_ns;
    int64_t ctime_ns;
} tw_kb_fstat;

/* File descriptors here are backend file ids (>= 0), not handles. */
int64_t tw_kb_file_open(const char *path, uint32_t flags);
int64_t tw_kb_file_read(int64_t fid, void *buf, uint64_t len);
int64_t tw_kb_file_write(int64_t fid, const void *buf, uint64_t len);
int64_t tw_kb_file_seek(int64_t fid, int64_t off, int whence); /* 0 set, 1 cur, 2 end */
int tw_kb_file_stat(int64_t fid, tw_kb_fstat *st);
int tw_kb_file_truncate(int64_t fid, uint64_t size);
int tw_kb_file_close(int64_t fid);
int64_t tw_kb_file_dup(int64_t fid);
int tw_kb_path_stat(const char *path, tw_kb_fstat *st, int follow);
int tw_kb_path_unlink(const char *path);
int tw_kb_path_mkdir(const char *path);
int tw_kb_path_rmdir(const char *path);
/* Directory listing: fills `name` with the next entry (no "." / ".."). 1 =
 * entry, 0 = end, negative = error. */
int tw_kb_dir_next(int64_t fid, char *name, size_t cap, uint32_t *type);
/* Case-insensitive helper: actual on-disk spelling of `leaf` inside `dir`. */
int tw_kb_dir_lookup_ci(const char *dir, const char *leaf, char *out, size_t cap);

/* Console streams: 0 stdin, 1 stdout, 2 stderr -> a new file id. */
int64_t tw_kb_console_stream(int which);
int tw_kb_file_is_terminal(int64_t fid);

/* Spawn another TweakWin personality process. `blob` is opaque startup
 * data for the child runtime; `std_fids` become the child's console
 * streams (-1 = inherit this process's). Returns a PROCESS handle
 * (WAIT | QUERY | MANAGE). */
tw_kh tw_kb_process_spawn(const void *blob, size_t len, const int64_t std_fids[3]);
/* In a child: the startup blob (owned by the backend). 1 = this process
 * was spawned by tw_kb_process_spawn, 0 = it was not. */
int tw_kb_process_startup_blob(void **blob, size_t *len);
/* Host only: called by the CLI's internal "__child FD" entry before
 * anything else, to adopt the startup channel. */
int tw_kb_host_adopt_child(int fd);


/* Fault attribution for memory the backend VM does not own (the legacy
 * loader's PE image and stack). The host backend consults these in its
 * exception path; TweakKernel M4 tracks the image itself, so its
 * implementation is a no-op returning TW_KB_OK. */
int tw_kb_fault_region_add(uint64_t base, uint64_t size, int writable);
void tw_kb_fault_region_clear(void);

/* ---- inline ---- */
static inline int tw_kb_has(uint64_t cap)
{
    const tw_kb_info_t *i = tw_kb_info();
    return i && (i->caps & cap) == cap;
}

#endif
