#include "cli.h"

#include "../common/debug.h"
#include "../include/tweakwin/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static void usage(FILE *f)
{
    fprintf(f,
            "usage: tweakwin <command> [args]\n"
            "\n"
            "commands:\n"
            "  inspect FILE.exe   parse and describe a Windows PE32+ image\n"
            "  doctor             report runtime environment and implementation status\n"
            "  run FILE.exe [arg ...]  load and execute a Windows x86-64 console PE\n"
            "  --version          print version\n"
            "  --help             show this help\n"
            "\n"
            "environment:\n"
            "  TWEAKWIN_DEBUG=cat[,cat]  debug categories: loader, imports, memory, handles,\n"
            "                            filesystem, registry, thread, user32, gdi, network, all\n"
            "\n"
            "exit status:\n"
            "  If the guest starts, the status is the guest ExitProcess code (low 8 bits).\n"
            "  If the guest does not start (or does not ExitProcess):\n"
            "    1 loader/I/O failure, 2 malformed PE, 3 unsupported PE,\n"
            "    5 unresolved DLL, 6 unresolved symbol, 7 runtime failure, 64 usage\n");
}

static void data_dir(char *out, size_t n)
{
    const char *xdg = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    if (xdg && xdg[0] == '/')
        snprintf(out, n, "%s/tweakwin", xdg);
    else if (home && *home)
        snprintf(out, n, "%s/.local/share/tweakwin", home);
    else
        snprintf(out, n, "(unknown: HOME not set)");
}

int tw_cmd_doctor(int argc, char **argv)
{
    (void)argv;
    if (argc != 0) {
        fprintf(stderr, "usage: tweakwin doctor\n");
        return TW_EXIT_USAGE;
    }
    struct utsname u;
    char dir[4096];
    data_dir(dir, sizeof(dir));
    const char *wl = getenv("WAYLAND_DISPLAY");
    const char *dbg = getenv("TWEAKWIN_DEBUG");

    printf("TweakWin doctor\n");
    printf("Version: %s\n", TWEAKWIN_VERSION_STRING);
    printf("Milestone: %s\n", TWEAKWIN_MILESTONE);
    if (uname(&u) == 0)
        printf("Host: %s %s %s\n", u.sysname, u.release, u.machine);
    printf("Host architecture supported: %s\n",
           (uname(&u) == 0 && strcmp(u.machine, "x86_64") == 0) ? "yes" : "no (x86-64 required)");
    printf("Guest target: Windows x86-64 PE32+ (no WOW64)\n");
    printf("Runtime directory: %s\n", dir);
    printf("Prefix directory: %s/prefixes\n", dir);
    printf("PE parser: ready\n");
    printf("PE loader: ready\n");
    printf("relocations: DIR64\n");
    printf("import resolver: ready\n");
    printf("API modules: kernel32 console runtime, ntdll namespace\n");
    printf("filesystem: relative paths only\n");
    printf("command line: Windows quoting\n");
    printf("environment: TWEAKWIN_GUEST_ prefix only\n");
    printf("Wayland: %s\n", wl && *wl ? wl : "not detected (WAYLAND_DISPLAY unset)");
    printf("Vulkan: not checked (Milestone 9)\n");
    printf("Audio backend: not checked (not scheduled)\n");
    printf("Debug categories: %s\n", dbg && *dbg ? dbg : "(none)");
    return TW_EXIT_OK;
}

int main(int argc, char **argv)
{
    tw_debug_init();
    if (argc < 2) {
        usage(stderr);
        return TW_EXIT_USAGE;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
        printf("tweakwin %s\n", TWEAKWIN_VERSION_STRING);
        return TW_EXIT_OK;
    }
    if (!strcmp(cmd, "--help") || !strcmp(cmd, "-h") || !strcmp(cmd, "help")) {
        usage(stdout);
        return TW_EXIT_OK;
    }
    if (!strcmp(cmd, "inspect")) return tw_cmd_inspect(argc - 2, argv + 2);
    if (!strcmp(cmd, "doctor")) return tw_cmd_doctor(argc - 2, argv + 2);
    if (!strcmp(cmd, "run")) return tw_cmd_run(argc - 2, argv + 2);
    fprintf(stderr, "tweakwin: unknown command '%s'\n", cmd);
    usage(stderr);
    return TW_EXIT_USAGE;
}
