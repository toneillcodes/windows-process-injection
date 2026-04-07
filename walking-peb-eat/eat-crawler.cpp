#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h> // Required for __readgsqword / __readfsdword
#include <winternl.h> // for peb data structure https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb

// for testing with MessageBoxA
#pragma comment(lib, "user32.lib")

#include "..\includes\utils.h"
#include "..\includes\peb-eat-utils.h"

#define MAX_EXPORTED_FUNCS 25

typedef int (WINAPI* myMessageBoxA)(HWND hWnd, LPCSTR lptext, LPCSTR lpCaption, UINT uType);

int main(int argc, char* argv[]) {
    int debugOutput = 1;
    uintptr_t functionAddresses[MAX_EXPORTED_FUNCS];

    void* teb = GetLocalTebAddress();
    if (debugOutput) {
        printf("Current process TEB address: %p\n", teb);
    }

    // maybe move this to a GetLocalPebAddress function?
    // this is good for demonstration but we can really skip straight to the PEB
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

    // Accessing the 'BeingDebugged' flag (a documented field)
    if (peb_ptr->BeingDebugged) {
        printf("Debugger is attached\n");
    }
    else {
        printf("No debugger detected\n");
    }

	//	init counter to zero
	int foundCount = 0;

    char targetFunc[] = "MessageBoxA";
    uintptr_t finalFunctionAddr = NULL;

    // Accessing the 'Ldr' member, which points to PEB_LDR_DATA
    PPEB_LDR_DATA ldr_data = peb_ptr->Ldr;

    // The list head for modules in memory order
    PLIST_ENTRY list_head = &ldr_data->InMemoryOrderModuleList;
    // current entry
    PLIST_ENTRY current_entry = list_head->Flink;

    while (current_entry != list_head) { // Loop until we return to the list head
        // Use CONTAINING_RECORD to get the base address of the LDR_DATA_TABLE_ENTRY
        LDR_DATA_TABLE_ENTRY* module_entry = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(
            current_entry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        // Access module information, e.g., the DLL base address
        PVOID moduleBaseAddress = module_entry->DllBase;
        UNICODE_STRING dllName = module_entry->FullDllName;
        ULONG sessionId = module_entry->TimeDateStamp;
        ULONG checksum = module_entry->CheckSum;
        if (debugOutput) {
            printf("--------\n");
            printf("DLL Base Address = 0x%p\n", &moduleBaseAddress);
            printf("DLL Name = %wZ\n", &dllName);
            printf("session id = %lu\n", sessionId);
            printf("checksum = %lu\n", checksum);
        }
        //ParseDll(moduleBaseAddress);
        PVOID moduleBase = moduleBaseAddress;
        // Get DOS Header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            printf("Invalid DOS Signature\n");
            return -1;
        }

        // Get NT Headers using the offset from DOS Header
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            printf("Invalid NT Signature\n");
            return -1;
        }

        // Locate the Export Directory in the Data Directory
        IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDataDir.VirtualAddress == 0) {
            if (debugOutput) {
                printf("No Export Table found for entry  %wZ\n", &dllName);
            }
        }
        else {
            if (debugOutput) {
                printf("Export Table Detected.\n");
            }
            // Get the Export Directory Structure
            PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + exportDataDir.VirtualAddress);

            char* dllName = (char*)((BYTE*)moduleBase + exportDir->Name);
            if (debugOutput) {
                printf("DLL Name: %s\n", dllName);
            }
            uintptr_t Base = exportDir->Base;
            uintptr_t AddressOfFunctions = exportDir->AddressOfFunctions;
            uintptr_t AddressOfNameOrdinals = exportDir->AddressOfNameOrdinals;
            uintptr_t AddressOfNames = exportDir->AddressOfNames;
            DWORD Characteristics = exportDir->Characteristics;
            WORD MajorVersion = exportDir->MajorVersion;
            WORD MinorVersion = exportDir->MinorVersion;
            DWORD NumberOfNames = exportDir->NumberOfNames;
            DWORD NumberOfFunctions = exportDir->NumberOfFunctions;
            DWORD TimeDateStamp = exportDir->TimeDateStamp;

            // initialize EAT arrays
            PDWORD nameArray = (PDWORD)((BYTE*)moduleBase + exportDir->AddressOfNames);
            PWORD ordinalsArray = (PWORD)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);
            PDWORD functionsArray = (PDWORD)((BYTE*)moduleBase + exportDir->AddressOfFunctions);

            DWORD forwardedCount = 0;

            if (debugOutput) {
                printf("AddressOfFunctions (RVA): 0x%llx\n", AddressOfFunctions);
                printf("AddressOfNameOrdinals (RVA): 0x%llx\n", AddressOfNameOrdinals);
                printf("AddressOfNames (RVA): 0x%llx\n", AddressOfNames);
                printf("Absolute AddressOfFunctions: 0x%llx\n", (uintptr_t)moduleBase + AddressOfFunctions);
                printf("Absolute AddressOfNameOrdinals: 0x%llx\n", (uintptr_t)moduleBase + AddressOfNameOrdinals);
                printf("Absolute AddressOfNames: 0x%llx\n", (uintptr_t)moduleBase + AddressOfNames);
                //printf("Base: 0x%llx\n", Base);
                printf("Major Version: %d\n", MajorVersion);
                printf("Minor Version: %d\n", MinorVersion);
                printf("Number of Names: %d\n", NumberOfNames);
                printf("Number of Functions: %d\n", NumberOfFunctions);
            }

            if (_stricmp(dllName, "umppc.dll") == 0) {
                printf("CrowdStrike DLL detected! Skipping parsing.\n");            
            } else if(_stricmp(dllName, "SophosED.dll") == 0) {
                printf("Sophos DLL detected! Skipping parsing.\n");
            }            
            else {
                // Iterate through every function exported by the DLL
                for (DWORD i = 0; i < NumberOfFunctions; i++) {

                    // Get the Function RVA directly using the index 'i'                    
                    DWORD functionRVA = functionsArray[i];
                    if (functionRVA == 0) continue; // Skip entries with no address

                    char* funcName = NULL;

                    // Search the NameOrdinals array for a value that matches 'i'
                    for (DWORD j = 0; j < NumberOfNames; j++) {
                        if (ordinalsArray[j] == i) {
                            // the name at nameArray[j] belongs to function index i
                            funcName = (char*)((BYTE*)moduleBase + nameArray[j]);
                            break;
                        }
                    }

                    // check if it matches our target function
                    if (funcName != NULL) {
                        if (debugOutput) {  
                            // this takes debug output to another level...
                            //printf("Function Index %d has Name: %s\n", i, funcName);
                        }

                        if (strcmp(funcName, targetFunc) == 0) {
                            // Check if it's a Forwarded Export before saving the address
                            DWORD exportStart = exportDataDir.VirtualAddress;
                            DWORD exportEnd = exportDataDir.VirtualAddress + exportDataDir.Size;

                            if (functionRVA >= exportStart && functionRVA < exportEnd) {
                                char* forwarderString = (char*)((BYTE*)moduleBase + functionRVA);
                                printf("[!] Found %s, but it's a forwarder to: %s\n", targetFunc, forwarderString);
                                // For now, we don't resolve the other DLL, just skip it
                                continue;
                            }

                            finalFunctionAddr = (uintptr_t)((BYTE*)moduleBase + functionRVA);
                            if (foundCount < MAX_EXPORTED_FUNCS) {
                                functionAddresses[foundCount] = finalFunctionAddr;
                                foundCount++;
                            }                            
                            printf("[%s] found at: 0x%llx in: %wZ\n", targetFunc, finalFunctionAddr, &module_entry->FullDllName);
                        }
                    }
                }
            }
        }
        // Move to the next entry in the list
        current_entry = current_entry->Flink;
    }
   
    /*printf("Last entry located @ 0x%llx\n", finalFunctionAddr);
    myMessageBoxA dynamicMsgBox = (myMessageBoxA)finalFunctionAddr;
    dynamicMsgBox(NULL, "Executed via manual address resolution!", "Success", MB_OK);*/
    
    // make sure we find an entry by adding a call
    if (argc > 999) MessageBoxA(NULL, NULL, NULL, 0);    
    myMessageBoxA dynamicMsgBox = NULL;
    if (foundCount > 1) {
        printf("Multiple results found. Which would you like to invoke?\n");
        for (int i = 0; i < foundCount; i++) {
            printf("[%d] to invoke @ 0x%llx\n", i, functionAddresses[i]);
        }
        int addressSelection = -1;
        scanf_s("%d", &addressSelection);
        if (addressSelection == -1) {
            printf("No address selected, exiting.");
            return -1;
        }
        else if (addressSelection >= 0 && addressSelection < foundCount) {
            dynamicMsgBox = (myMessageBoxA)functionAddresses[addressSelection];
        }
    }
    else if (foundCount == 1) {
        printf("Only one entry found - invoking from 0x%llx\n", finalFunctionAddr);
        dynamicMsgBox = (myMessageBoxA)finalFunctionAddr;
    }
    else {
        printf("No entries found.\n");
    }

    // did we find an entry? if so, let's invoke it
    if(dynamicMsgBox != NULL) {
        dynamicMsgBox(NULL, "Executed via manual address resolution!", "Success", MB_OK);
    }
    
    printf("Done.");
    return 0;
}