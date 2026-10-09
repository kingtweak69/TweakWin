/*
 * TweakKernel M4 user image: runs the backend conformance suite through
 * backend/kb_tweakkernel.c (real SYSCALLs). Linked by tests/m4/run-m4.sh
 * with TweakKernel's own user/start.S and user/user.ld.
 */
#include "../../backend/kb.h"

int kb_conformance_run(void);
void main(void);

/* The compiler may lower loops to these even when freestanding. */
__attribute__((used)) void *memset(void *dst, int c, unsigned long n)
{
    volatile unsigned char *d = dst;
    for (unsigned long i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

__attribute__((used)) void *memcpy(void *dst, const void *src, unsigned long n)
{
    volatile unsigned char *d = dst;
    const volatile unsigned char *s = src;
    for (unsigned long i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static void say(const char *s)
{
    unsigned long n = 0;
    while (s[n]) n++;
    tw_kb_debug_write(s, n);
}

void main(void)
{
    say("tweakwin-m4: backend conformance start\n");
    if (tw_kb_init() != TW_KB_OK) {
        say("tweakwin-m4: FAIL init\n");
        tw_kb_process_exit(1);
    }
    say("tweakwin-m4: backend ");
    say(tw_kb_info()->name);
    say("\n");
    int failed = kb_conformance_run();
    say(failed ? "tweakwin-m4: FAIL\n" : "TWEAKWIN_M4_KB_OK\n");
    tw_kb_process_exit(failed ? 1 : 0);
}

/* TweakKernel's user/start.S calls this if main returns. */
void tweak_exit(long status);
void tweak_exit(long status)
{
    tw_kb_process_exit((int32_t)status);
}
