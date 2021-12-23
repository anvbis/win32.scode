#!/usr/bin/env python3

from pwn import *


shellcode = asm('''
    int3

start:
    mov ebp, esp
    sub sp, 0x60

find_kernel32:
    xor ecx, ecx
    mov esi, fs:[ecx+0x30]
    mov esi, [esi+0x0c]
    mov esi, [esi+0x1c]

next_module:
    mov ebx, [esi+0x08]
    mov edi, [esi+0x20]
    mov esi, [esi]
    cmp [edi+0x18], cx
    jne next_module

    int3
''')

print(disasm(shellcode))
print(shellcode)
