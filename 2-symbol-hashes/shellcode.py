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

    xor eax, eax
    push eax
    push 0x73736563  # "cess"
    push 0x6f725065  # "ePro"
    push 0x74616e69  # "inat"
    push 0x6d726554  # "Term"
    mov esi, esp     # "TerminateProcess"

compute_hash:
    xor eax, eax
    cdq
    cld
compute_hash_again:
    lodsb
    test al, al
    jz compute_hash_finished
    ror edx, 0x0d
    add edx, eax
    jmp compute_hash_again
compute_hash_finished:
''')

print(f'compute_hash(b\'TerminateProcess\') = {compute_hash(b"TerminateProcess")}')
print(f'shellcode = {shellcode}')

