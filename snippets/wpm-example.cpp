//
// Compile: cl.exe wpm-example.cpp /nologo example.cpp
//
#include <windows.h>
#include <stdio.h>

int main() {
    // Example payload buffer
    unsigned char buf[] = "\x90\x90\x90\x90"; 
    HANDLE pHandle = GetCurrentProcess();
    // 1. Allocate straight to RX space. No RWX, no explicit RW transition.
    LPVOID bufferAddress = VirtualAlloc(NULL, sizeof buf, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READ);
    if (!bufferAddress) {
        printf("[ERROR] Allocation failed. Error: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Memory allocated as RX at: 0x%p\n", bufferAddress);
    // 2. The documentation implies this should fail. The kernel says otherwise.
    // NOTE: This internal permission flip is still a visible event to kernel telemetry!
    BOOL writeShellcode = WriteProcessMemory(pHandle, bufferAddress, buf, sizeof buf, NULL);
    if (!writeShellcode) {
        printf("[ERROR] Write failed. Error: %lu\n", GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }
    printf("[+] Successfully wrote to RX memory without calling VirtualProtect.\n");
    return 0;
}