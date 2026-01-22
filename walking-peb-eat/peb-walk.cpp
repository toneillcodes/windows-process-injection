#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>     // Required for __readgsqword / __readfsdword
#include <winternl.h>   // for peb data structure https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb

#include "../header-files/utils.h"

// Define missing NTSTATUS codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#define MAX_EXPORTED_FUNCS 25

#pragma comment(lib, "user32.lib")

// obtain the local process TEB
void* GetLocalTebAddress(void) {
#ifdef _WIN64
    return (void*)__readgsqword(0x30);
#else
    return (void*)__readfsdword(0x18);
#endif
}

// todo: test and validation for remote PEB
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// todo: test and validation for remote PEB
PVOID GetRemotePebAddress(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    // get the address of NtQueryInformationProcess
    // this could be replaced with a manual lookup through the local PEB to avoid GetProcAddress
    pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), 
        "NtQueryInformationProcess"
    );

    // Query the process for the PEB address
    NTSTATUS status = NtQueryInfo(
        hProcess, 
        ProcessBasicInformation, // Value 0
        &pbi, 
        sizeof(pbi), 
        &returnLength
    );

    if (status == STATUS_SUCCESS) {
        return pbi.PebBaseAddress;
    }
    
    return NULL;
}

// find the address of an exported function within a given module
// obviously depends on a name value being present in the array found at AddressOfNames
PVOID GetProcAddressManualByName(HMODULE hMod, char* targetFunc) {
    PBYTE base = (PBYTE)hMod;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDataDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportDataDir.VirtualAddress);

    PDWORD names = (PDWORD)(base + exports->AddressOfNames);
    PWORD ordinals = (PWORD)(base + exports->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)(base + exports->AddressOfFunctions);

    // --- Binary Search Logic Start ---
    int low = 0;
    int high = exports->NumberOfNames - 1;

    while (low <= high) {
        int mid = low + (high - low) / 2;
        char* currentName = (char*)(base + names[mid]);

        int cmp = my_strcmp(targetFunc, currentName);

        if (cmp == 0) {
            // Match found!
            WORD ordinalValue = ordinals[mid];
            DWORD funcRVA = functions[ordinalValue];

            // Forwarder Check
            if (funcRVA >= exportDataDir.VirtualAddress &&
                funcRVA < (exportDataDir.VirtualAddress + exportDataDir.Size)) {
                // Add more forwarder logic here
                return NULL;
            }

            return (PVOID)(base + funcRVA);
        }

        if (cmp < 0) {
            high = mid - 1; // Target is in the lower half
        }
        else {
            low = mid + 1;  // Target is in the upper half
        }
    }
    // --- Binary Search Logic End ---

    return NULL;
}

// find the address of an exported function within a given module
PVOID GetProcAddressManualByOrdinal(HMODULE hMod, WORD ordinal) {
    PBYTE base = (PBYTE)hMod;

    // 1. Navigate to the Export Directory (standard PE parsing)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // 2. Adjust the ordinal
    // Most DLLs start their ordinals at a "Base" (usually 1). 
    // If the DLL says export #12 and the Base is 1, the actual index is 11.
    DWORD functionIndex = ordinal - exports->Base;

    // 3. Bounds check
    if (functionIndex >= exports->NumberOfFunctions) return NULL;

    // 4. Get the RVA from the functions array
    PDWORD functionsArray = (PDWORD)(base + exports->AddressOfFunctions);
    DWORD funcRVA = functionsArray[functionIndex];

    return (PVOID)(base + funcRVA);
}

PVOID GetModuleBaseManual(PPEB pebObject, const char* targetModuleName) {
    // we want the ldr data
    PPEB_LDR_DATA ldr = pebObject->Ldr;
    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntry = listHead->Flink;

    // traverse the doubly-linked list, if we ouroboros we're done
    while (currentEntry != listHead) {
        // InMemoryOrderLinks is the second field in LDR_DATA_TABLE_ENTRY
        // use CONTAINING_RECORD to snap back to the start of the structure
        LDR_DATA_TABLE_ENTRY* moduleEntry = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(
            currentEntry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
      
        UNICODE_STRING fileName = moduleEntry->FullDllName;
        //printf("fileName = %wZ\n", fileName);
        PVOID moduleBase = moduleEntry->DllBase;
        // get DOS Header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            printf("Invalid DOS Signature\n");
            return NULL;
        }

        // get NT Headers using the offset from DOS Header
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            printf("Invalid NT Signature\n");
            return NULL;
        }
        
        // Locate the Export Directory in the Data Directory
        IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDataDir.VirtualAddress == 0) {
            // does this case matter? maybe with debug enabled
            //printf("No Export Table found for entry  %wZ\n", &fileName);
        }
        else {
            PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + exportDataDir.VirtualAddress);
            char* moduleName = NULL;
            moduleName = (char*)((BYTE*)moduleBase + exportDir->Name);        
            
            if (moduleName != NULL) {
                // todo: case insensitive would be better, the names are not consistent
                // examples: ntdll.dll, USER32.dll, KERNEL32.DLL
                //if (my_strcmp(moduleName, targetModuleName) == 0) {
                if (my_stricmp(moduleName, targetModuleName) == 0) {
                    return moduleBase;                  
                }
            }
        }
        currentEntry = currentEntry->Flink;
    }

    return NULL;
}

// custom type defs for function invocation
typedef int (WINAPI* myMessageBoxA)(HWND hWnd, LPCSTR lptext, LPCSTR lpCaption, UINT uType);

int main(int argc, char* argv[]) {
    // import MessageBoxA for testing without triggering a message to the UI
    if (argc > 999) MessageBoxA(NULL, NULL, NULL, 0);
    
    int debugOutput = 1;

    void* teb = GetLocalTebAddress();
    if (debugOutput) {
        printf("Current process TEB address: %p\n", teb);
    }
	
    void* peb = NULL;
#ifdef _WIN64
    // On x64, PEB is at TEB + 0x60
    peb = *(void**)((unsigned char*)teb + 0x60);
#else
    // On x86, PEB is at TEB + 0x30
    // not currently used, but good to have around
    peb = *(void**)((unsigned char*)teb + 0x30);
#endif
    if (debugOutput) {
        printf("Current process PEB address (TEB + offset): %p\n", peb);
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb#remarks
    // Assuming peb_address holds the valid memory location of the PEB
    PPEB peb_ptr = (PPEB)peb;

    // Accessing the 'BeingDebugged' flag
    if (peb_ptr->BeingDebugged) {
        printf("Debugger is attached\n");
    }
    else {
        printf("No debugger detected\n");
    }
    
    PVOID dllBase = GetModuleBaseManual(peb_ptr, "USER32.dll");         // or maybe ntdll.dll
    if(dllBase) {
        printf("DLL found @ %llx\n",dllBase);
        PVOID rvaFound = GetProcAddressManualByName((HMODULE) dllBase, "MessageBoxA");    // and then NtAllocateVirtualMemory
        if(rvaFound) {
            printf("found function within DLL @ %llx\n", rvaFound);			
            // MessageBoxA example
            myMessageBoxA dynamicMsgBox = NULL;
            dynamicMsgBox = (myMessageBoxA)rvaFound;
            dynamicMsgBox(NULL, "Executed via manual address resolution!", "Success", MB_OK);            
        } else {
            printf("Unable to locate function\n");
        }
    } else {
        printf("Unable to locate DLL\n");
    }
   
    printf("Done.");
    return 0;
}