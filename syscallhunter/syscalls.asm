.code

; extern "C" DWORD GetSSNFromAddress(PVOID funcAddr);
; Argument 'funcAddr' is in RCX
GetSSNFromAddress PROC
    mov r8, rcx         ; Copy function address to R8
    xor rax, rax        ; Clear RAX (our return value)
    mov r9, 0           ; Counter for our search loop

search_loop:
    ; Limit search to 28 bytes so that reading a 4-byte immediate value
    ; afterwards never crosses our 32-byte boundary limit.
    cmp r9, 28          
    jge not_found       ; If we hit index 28, stop to prevent out-of-bounds

    ; Look for 0xB8 (mov eax, ...)
    cmp byte ptr [r8 + r9], 0B8h
    je found_ssn

    inc r9
    jmp search_loop

found_ssn:
    ; Securely grab the 4-byte SSN immediately following the 0xB8 opcode
    mov eax, dword ptr [r8 + r9 + 1]
    ret

not_found:
    xor eax, eax        ; Return 0 if not found or unsafe to read
    ret
GetSSNFromAddress ENDP

END