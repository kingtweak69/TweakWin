/* Host driver for tests/backend/kb_conformance.c. */
#include <stdio.h>

int kb_conformance_run(void);

int main(void)
{
    int failed = kb_conformance_run();
    printf("backend (host): %s\n", failed ? "FAILED" : "ok");
    return failed ? 1 : 0;
}
