#include "peb-eat-utils.h"
#include "utils.h"

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