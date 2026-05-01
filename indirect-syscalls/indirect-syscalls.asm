EXTERN wNtAllocateVirtualMemorySSN:DWORD
EXTERN sysAddrNtAllocateVirtualMemory:QWORD

EXTERN wNtWriteVirtualMemorySSN:DWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD

EXTERN wNtCreateThreadExSSN:DWORD
EXTERN sysAddrNtCreateThreadEx:QWORD

EXTERN wNtWaitForSingleObjectSSN:DWORD
EXTERN sysAddrNtWaitForSingleObject:QWORD

.CODE ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
IndirectSysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtAllocateVirtualMemorySSN
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]
IndirectSysNtAllocateVirtualMemory ENDP

; Similar procedures for NtWriteVirtualMemory syscalls
IndirectSysNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemorySSN
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
IndirectSysNtWriteVirtualMemory ENDP

; Similar procedures for NtCreateThreadEx syscalls
IndirectSysNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadExSSN
    jmp QWORD PTR [sysAddrNtCreateThreadEx]
IndirectSysNtCreateThreadEx ENDP

; Similar procedures for NtWaitForSingleObject syscalls
IndirectSysNtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, wNtWaitForSingleObjectSSN
    jmp QWORD PTR [sysAddrNtWaitForSingleObject]
IndirectSysNtWaitForSingleObject ENDP

END ; End of the module
