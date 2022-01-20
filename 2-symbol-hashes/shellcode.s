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
    nop
