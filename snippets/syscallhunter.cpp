#include <stdio.h>

#include "syscall-utils.h"

int main() {
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    PVOID funcAddress = GetProcAddress(hModule, "NtCreateThreadEx");

    if (funcAddress) {
        DWORD ssn = GetSSN(funcAddress);
        PVOID sysAddr = GetSyscallAddress(funcAddress);

        printf("Function: NtCreateThreadEx\n");
        printf("SSN:      0x%04X\n", ssn);
        printf("Syscall:  0x%p\n", sysAddr);
    }
    return 0;
}