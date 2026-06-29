.code

; extern "C" DWORD GetSSNFromAddress(PVOID funcAddr);
; Argument 'funcAddr' is in RCX
GetSSNFromAddress PROC
    mov r8, rcx         ; Copy function address to R8
    xor rax, rax        ; Clear RAX (our return value)
    mov r9, 0           ; Counter for our search loop

search_loop:
    ; Check if we've searched too far (e.g., 32 bytes)
    cmp r9, 32
    je not_found

    ; Look for 0xB8 (mov eax, ...)
    cmp byte ptr [r8 + r9], 0B8h
    je found_ssn

    inc r9
    jmp search_loop

found_ssn:
    ; The SSN starts at the byte after 0xB8
    inc r9
    mov eax, dword ptr [r8 + r9]
    ret

not_found:
    xor eax, eax        ; Return 0 if not found
    ret
GetSSNFromAddress ENDP

END