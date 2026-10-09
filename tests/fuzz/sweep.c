/*
 * Deterministic mutation sweep over PE fixtures, run under ASan + UBSan.
 * Any out-of-bounds read, overflow, leak or UB aborts the run.
 *
 *   sweep FILE...
 *
 * For each file:
 *   - every truncation length
 *   - every byte set to 0x00, 0xff, 0x7f, 0x80 and bit-flipped
 *   - 200,000 random multi-byte mutations (fixed seed)
 * Every parse must return OK, MALFORMED or UNSUPPORTED.
 */

#include "../../loader/pe/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long g_runs, g_ok, g_bad, g_unsup;

static uint64_t rng_state = 0x7765616b77696eull; /* "weakwin" */
static uint64_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void run(const uint8_t *buf, size_t len)
{
    /* parse from an exact-size heap copy so ASan catches any overread */
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy) abort();
    memcpy(copy, buf, len);
    tw_pe_image im;
    tw_pe_error err;
    tw_pe_status st = tw_pe_parse(copy, len, &im, &err);
    switch (st) {
    case TW_PE_OK: g_ok++; break;
    case TW_PE_ERR_MALFORMED: g_bad++; break;
    case TW_PE_ERR_UNSUPPORTED: g_unsup++; break;
    default:
        fprintf(stderr, "sweep: unexpected status %d (%s)\n", st, err.msg);
        abort();
    }
    tw_pe_free(&im);
    free(copy);
    g_runs++;
}

static void sweep(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (1 << 24)) { fprintf(stderr, "%s: bad size\n", path); exit(1); }
    size_t n = (size_t)sz;
    uint8_t *orig = malloc(n), *work = malloc(n);
    if (fread(orig, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);

    unsigned long long before = g_runs;
    for (size_t len = 0; len <= n; len++) run(orig, len);

    static const uint8_t vals[] = { 0x00, 0xff, 0x7f, 0x80 };
    for (size_t i = 0; i < n; i++) {
        memcpy(work, orig, n);
        for (size_t k = 0; k < sizeof(vals); k++) {
            if (orig[i] == vals[k]) continue;
            work[i] = vals[k];
            run(work, n);
        }
        work[i] = (uint8_t)(orig[i] ^ (1u << (rng() & 7)));
        run(work, n);
    }

    for (int iter = 0; iter < 200000; iter++) {
        memcpy(work, orig, n);
        int muts = 1 + (int)(rng() % 8);
        for (int m = 0; m < muts; m++) {
            size_t pos = (size_t)(rng() % n);
            /* bias toward headers, where most structure lives */
            if (rng() & 1) pos %= (n < 0x400 ? n : 0x400);
            switch (rng() % 4) {
            case 0: work[pos] = (uint8_t)rng(); break;
            case 1: if (pos + 4 <= n) { uint32_t v = (uint32_t)rng(); memcpy(work + pos, &v, 4); } break;
            case 2: if (pos + 4 <= n) { uint32_t v = (uint32_t)(rng() % 0x10000); memcpy(work + pos, &v, 4); } break;
            default: work[pos] ^= (uint8_t)(1u << (rng() & 7)); break;
            }
        }
        size_t len = (rng() % 16 == 0) ? (size_t)(rng() % (n + 1)) : n;
        run(work, len);
    }
    printf("sweep: %s: %llu parses\n", path, g_runs - before);
    free(orig);
    free(work);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: sweep FILE...\n");
        return 64;
    }
    for (int i = 1; i < argc; i++) sweep(argv[i]);
    printf("sweep: %llu total (ok %llu, malformed %llu, unsupported %llu), no memory errors\n",
           g_runs, g_ok, g_bad, g_unsup);
    return 0;
}
