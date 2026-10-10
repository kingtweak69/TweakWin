#ifndef TWEAKWIN_ADVAPI32_H
#define TWEAKWIN_ADVAPI32_H

/* advapi32.dll subset: the isolated virtual registry (see runtime/registry.h). */

#include "../kernel32/kernel32.h"

const tw_k32_desc *tw_advapi32_exports(size_t *n);

#endif
