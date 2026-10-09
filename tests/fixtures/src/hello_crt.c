/* Ordinary CRT-linked console program: exercises a realistic MinGW import
   table, CRT TLS callbacks, relocations and unwind data. Parse-only fixture. */
#include <stdio.h>
#include <stdlib.h>

static const char *const greetings[] = { "Hello", "from", "TweakWin" };

int main(int argc, char **argv)
{
    for (int i = 0; i < 3; i++) printf("%s ", greetings[i]);
    printf("(%d args, first=%s)\n", argc, argc > 0 ? argv[0] : "?");
    return getenv("TWEAKWIN_FAIL") ? 1 : 0;
}
