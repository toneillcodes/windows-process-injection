;
; Function: NtAllocateVirtualMemory
; SSN:      0x0018
;
; Function: NtWriteVirtualMemory
; SSN:      0x003A
;
; Function: NtCreateThreadEx
; SSN:      0x00BC
;
; Function: NtWaitForSingleObject
; SSN:      0x0004
;

.CODE

; --- NtAllocateVirtualMemory Wrapper ---
; This follows the x64 Calling Convention (Windows)
; Args: RCX, RDX, R8, R9, [Stack...]

SysNtAllocateVirtualMemory PROC
    mov r10, rcx        ; The 'syscall' instruction destroys RCX. 
                        ; We move the first argument (ProcessHandle) to R10
                        ; because the kernel expects it there instead of RCX.

    mov eax, 18h        ; Load the System Service Number (SSN) into EAX.
                        ; 0x18 is the ID for NtAllocateVirtualMemory on 
                        ; many Windows 10/11 x64 builds.

    syscall             ; Transfer control to the Windows Kernel.
                        ; The CPU switches to Ring 0 and executes the function
                        ; associated with the ID currently in EAX (0x18).

    ret                 ; Return to the caller. The NTSTATUS result 
                        ; will be stored in the EAX register.
SysNtAllocateVirtualMemory ENDP

extern wNtAllocateVirtualMemorySSN : DWORD  ; Variable defined in C++

;extern wNtAllocateVirtualMemorySSN : DWORD  ; Variable defined in C++
;SysNtAllocateVirtualMemory PROC
;    mov r10, rcx
;    mov eax, wNtAllocateVirtualMemorySSN    ; Load the dynamic SSN
;    syscall
;    ret
;SysNtAllocateVirtualMemory ENDP

SysNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 3Ah 
    syscall
    ret
SysNtWriteVirtualMemory ENDP

SysNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, 0BCh
    syscall
    ret
SysNtCreateThreadEx ENDP

SysNtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, 4
    syscall
    ret
SysNtWaitForSingleObject ENDP

END