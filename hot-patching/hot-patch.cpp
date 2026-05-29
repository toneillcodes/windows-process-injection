/*
*   compile: cl.exe hot-patch.cpp
*/
#include <windows.h>
#include <stdio.h>

int targetFunction() {
    printf("[!] This is the original function, you should NOT see this output when the hot patch is enabled.\n");
    return 0;
}

// The replacement function that patches the bad behavior
int FixedFunction() {
    printf("[+] The function was successfully patched and corrected!\n");
    return 0; 
}

void PatchLocalFunction(void* targetFunction, void* newFunction) {
    DWORD oldProtect;
    
    // Calculate the relative offset for a JMP instruction (0xE9)
    // Formula: TargetAddress - CurrentAddress - SizeOfJmpInstruction
    SIZE_T relativeOffset = (SIZE_T)newFunction - (SIZE_T)targetFunction - 5;

    // Build the 5-byte JMP instruction payload
    unsigned char jmpPatch[5];
    jmpPatch[0] = 0xE9; // JMP opcode
    memcpy(&jmpPatch[1], &relativeOffset, 4);

    // Unprotect the target function memory temporarily
    VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Overwrite the first 5 bytes to redirect control flow
    memcpy(targetFunction, jmpPatch, 5);

    // Restore original protection
    VirtualProtect(targetFunction, 5, oldProtect, &oldProtect);
}

int main() {
    printf("[*] Starting hot patch PoC execution\n");
    
    // Call the function before the patch to see original behavior
    printf("[*] Before Patch\n");
    int result = targetFunction();
    printf("[*] Completed with return code: %d.\n", result);

    // Apply the local module patch
    printf("[*] Applying hot patch...\n");
    PatchLocalFunction((void*)&targetFunction, (void*)&FixedFunction);

    // Call the function after the patch to see if it redirects
    printf("[*] After Patch\n");
    result = targetFunction();
    
    printf("[*] Completed with return code: %d. Done, exiting.\n", result);
    return 0;
}