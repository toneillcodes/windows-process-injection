#include "syscall-utils.h"

extern "C" DWORD GetSSN(PVOID functionAddress) {
    BYTE* ptr = (BYTE*)functionAddress;

    /* We are looking for the 'mov eax, SSN' instruction.
       The opcode is B8 (MOV EAX, imm32)
       In most Windows stubs, it starts at the 4th byte:
       4C 8B D1 B8 [SSN] 00 00 00

       index 0: 4C 8B D1 (mov r10, rcx)
       index 3: B8 <SSN> (mov eax, ...)       
    */
    if (ptr[3] == 0xB8) {
        return *(DWORD*)(ptr + 4);
    }
         
    // If it's not at index 3, an EDR might have hooked it.
    // We can search for the 0xB8 byte within the first few instructions.
    for (int i = 0; i < 16; i++) {
        if (ptr[i] == 0xB8) {
            return *(DWORD*)(ptr + i + 1);
        }
    }
    
    return 0;
}

// Simplified logic to find the 'syscall' opcode (0x0F 0x05)
extern "C" PVOID GetSyscallAddress(PVOID functionAddress) {
	BYTE* ptr = (BYTE*)functionAddress;
	
	// Search the first 32 bytes of the function for the syscall instruction 0f 05
	for (int i = 0; i < 32; i++) {
		if (ptr[i] == 0x0F && ptr[i+1] == 0x05) {
			return (PVOID)(ptr + i);
		}
	}
	return NULL;
}