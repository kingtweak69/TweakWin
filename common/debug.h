#ifndef TWEAKWIN_DEBUG_H
#define TWEAKWIN_DEBUG_H

/*
 * Debug categories, enabled with TWEAKWIN_DEBUG=cat1,cat2 (or "all").
 * Output goes to stderr as "[tweakwin:cat] message".
 */

enum tw_debug_cat {
    TW_DBG_LOADER     = 1u << 0,
    TW_DBG_IMPORTS    = 1u << 1,
    TW_DBG_MEMORY     = 1u << 2,
    TW_DBG_HANDLES    = 1u << 3,
    TW_DBG_FILESYSTEM = 1u << 4,
    TW_DBG_REGISTRY   = 1u << 5,
    TW_DBG_THREAD     = 1u << 6,
    TW_DBG_USER32     = 1u << 7,
    TW_DBG_GDI        = 1u << 8,
    TW_DBG_NETWORK    = 1u << 9,
};

void tw_debug_init(void);
unsigned tw_debug_mask(void);
const char *tw_debug_name(unsigned cat);

#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
void tw_debug_log(unsigned cat, const char *fmt, ...);

#define TW_DEBUG(cat, ...)                                   \
    do {                                                     \
        if (tw_debug_mask() & (cat)) tw_debug_log((cat), __VA_ARGS__); \
    } while (0)

#endif
