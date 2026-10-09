#include "cli.h"

#include "../loader/load.h"
#include "../loader/pe/pe.h"
#include "../rt/rt.h"
#include "../runtime/process.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void put_path_err(const char *path)
{
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        fputc((*p >= 0x20 && *p < 0x7f) ? *p : '?', stderr);
}

static int exit_for_load(tw_load_status st)
{
    switch (st) {
    case TW_LOAD_OK:                    return TW_EXIT_OK;
    case TW_LOAD_ERR_MALFORMED:         return TW_EXIT_MALFORMED;
    case TW_LOAD_ERR_UNSUPPORTED:       return TW_EXIT_UNSUPPORTED;
    case TW_LOAD_ERR_UNRESOLVED_DLL:    return TW_EXIT_UNRESOLVED_DLL;
    case TW_LOAD_ERR_UNRESOLVED_SYMBOL: return TW_EXIT_UNRESOLVED_SYMBOL;
    case TW_LOAD_ERR_RUNTIME:           return TW_EXIT_RUNTIME;
    default:                            return TW_EXIT_FAILURE;
    }
}

int tw_cmd_run(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "usage: tweakwin run FILE.exe [arg ...]\n");
        return TW_EXIT_USAGE;
    }
    const char *path = argv[0];
    tw_loaded im;
    tw_pe_error perr;
    tw_load_status st = tw_load(path, TW_BASE_PREFER, &im, &perr);
    if (st != TW_LOAD_OK) {
        fflush(stdout);
        fprintf(stderr, "tweakwin: ");
        put_path_err(path);
        fprintf(stderr, ": %s: %s", tw_load_status_name(st), im.err[0] ? im.err : perr.msg);
        if (perr.has_offset && (st == TW_LOAD_ERR_MALFORMED || st == TW_LOAD_ERR_UNSUPPORTED))
            fprintf(stderr, " (%s 0x%" PRIx64 ")", perr.offset_is_rva ? "RVA" : "file offset", perr.offset);
        fputc('\n', stderr);
        int rc = exit_for_load(st);
        tw_unload(&im);
        return rc;
    }

    if (tw_runtime_bind(&im, path, argc, argv) != 0) {
        fflush(stdout);
        fprintf(stderr, "tweakwin: ");
        put_path_err(path);
        fprintf(stderr, ": runtime: failed to initialize the guest process\n");
        tw_runtime_unbind();
        tw_unload(&im);
        return TW_EXIT_FAILURE;
    }

    tw_rt_begin(&im);

    uint32_t guest_exit = 0;
    st = tw_execute(&im, &guest_exit);
    tw_rt_end();
    tw_runtime_unbind();
    if (st != TW_LOAD_OK) {
        fflush(stdout);
        fprintf(stderr, "tweakwin: ");
        put_path_err(path);
        fprintf(stderr, ": %s: %s\n", tw_load_status_name(st), im.err);
        int rc = exit_for_load(st);
        tw_unload(&im);
        return rc;
    }

    uint32_t code = guest_exit;
    tw_unload(&im);
    return (int)(code & 0xff);
}
