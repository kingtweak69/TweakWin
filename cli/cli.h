#ifndef TWEAKWIN_CLI_H
#define TWEAKWIN_CLI_H

enum {
    TW_EXIT_OK = 0,
    TW_EXIT_FAILURE = 1,           /* I/O error or generic / loader failure */
    TW_EXIT_MALFORMED = 2,         /* input rejected as malformed */
    TW_EXIT_UNSUPPORTED = 3,       /* valid input, not supported by this version */
    TW_EXIT_UNIMPLEMENTED = 4,     /* command exists in the contract but is not built yet */
    TW_EXIT_UNRESOLVED_DLL = 5,    /* import DLL is not in the module registry */
    TW_EXIT_UNRESOLVED_SYMBOL = 6, /* DLL known, symbol is not */
    TW_EXIT_RUNTIME = 7,           /* guest started but did not ExitProcess */
    TW_EXIT_USAGE = 64,
};

int tw_cmd_inspect(int argc, char **argv);
int tw_cmd_doctor(int argc, char **argv);
int tw_cmd_run(int argc, char **argv);

#endif
