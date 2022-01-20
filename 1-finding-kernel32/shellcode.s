start:
    mov ebp, esp
    sub sp, 0x60

get_init_order_module_list:
    xor ecx, ecx
    mov esi, fs:[ecx+0x30]  # _TEB->ProcessEnvironmentBlock
    mov esi, [esi+0x0c]     # _PEB->Ldr
    mov esi, [esi+0x1c]     # _PEB_LDR_DATA->InInitializationOrderModuleList

check_module:
    mov ebx, [esi+0x08]  # _LDR_DATA_TABLE_ENTRY->DllBase
    mov edi, [esi+0x20]  # _LDR_DATA_TABLE_ENTRY->DllName
    mov esi, [esi]
    cmp [edi+0x18], cx
    jne check_module
