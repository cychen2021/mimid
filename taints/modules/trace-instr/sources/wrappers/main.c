#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "callbacks.h"

int _real_program_main(int argc, char* argv[]);

void handler(int sig) {
    exit(sig);
}

int main(int argc, char* argv[])
{
    signal(SIGSEGV, handler); // handle segfault to terminate properly
    atexit(tracerllvm_endTrace);

    tracerllvm_beginTrace();
    tracerllvm_argcargv(argc, argv);

    return _real_program_main(argc, argv);
}
