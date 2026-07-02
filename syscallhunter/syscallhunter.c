#include <stdio.h>
#include <windows.h>
#include "..\includes\syscall-utils.h"
#include "..\includes\peb-eat-utils.h"

int main(int argc, char* argv[]) {
    // Check if the user provided both the module and function name
    if (argc < 3) {
        printf("Usage: %s <module_name> <function_name>\n", argv[0]);
        printf("Example: %s ntdll.dll NtCreateThreadEx\n", argv[0]);
        return 1;
    }

    char* moduleName = argv[1];
    char* functionName = argv[2];

    // Attempt to get a handle to the loaded module
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        printf("[!] Failed to get handle for module: %s (Error: %lu)\n", moduleName, GetLastError());
        return 1;
    }

    // Attempt to locate the function address within that module
    PVOID funcAddress = (PVOID)GetProcAddress(hModule, functionName);
    if (funcAddress == NULL) {
        printf("[!] Failed to find function: %s in %s\n", functionName, moduleName);
        return 1;
    }

    // Extract the System Service Number and Syscall instruction address
    DWORD ssn = GetSSN(funcAddress);
    PVOID sysAddr = GetSyscallAddress(funcAddress);

    printf("Module:   %s\n", moduleName);
    printf("Function: %s\n", functionName);
    printf("SSN:      0x%04X\n", ssn);
    printf("Syscall:  0x%p\n", sysAddr);

    return 0;
}