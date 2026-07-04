#pragma once
#include "peb-eat-utils.h"
#include "utils.h"
#include <stddef.h>
#include <stdio.h>

#define LOCAL_PROCESS_HANDLE ((HANDLE)(LONG_PTR)-1)

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ============================================================================
// --- Core Internal Abstraction Layer ---
// ============================================================================

// Seamlessly handles memory read operations for both local and remote execution
BOOL ReadMemoryInternal(HANDLE hProcess, PVOID baseAddress, PVOID localBuffer, SIZE_T size) {
    if (hProcess == NULL || hProcess == LOCAL_PROCESS_HANDLE) {
        __try {
            memcpy(localBuffer, baseAddress, size);
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    } else {
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(hProcess, baseAddress, localBuffer, size, &bytesRead) && (bytesRead == size);
    }
}

// PE validation function to parse and verify DOS and NT headers safely
BOOL GetPEHeaders(HANDLE hProcess, PVOID moduleBase, IMAGE_DOS_HEADER* outDos, IMAGE_NT_HEADERS* outNt) {
    if (!ReadMemoryInternal(hProcess, moduleBase, outDos, sizeof(IMAGE_DOS_HEADER))) return FALSE;
    if (outDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PVOID ntHeadersAddr = (BYTE*)moduleBase + outDos->e_lfanew;
    if (!ReadMemoryInternal(hProcess, ntHeadersAddr, outNt, sizeof(IMAGE_NT_HEADERS))) return FALSE;
    if (outNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    return TRUE;
}

// ============================================================================
// --- Generic Manual Parsing Engines ---
// ============================================================================

PVOID GetModuleBaseManualGeneric(HANDLE hProcess, PVOID pebAddr, const char* targetModuleName) {
    PEB localPeb = { 0 };
    if (!ReadMemoryInternal(hProcess, pebAddr, &localPeb, sizeof(PEB))) return NULL;
    if (!localPeb.Ldr) return NULL;

    PEB_LDR_DATA localLdr = { 0 };
    if (!ReadMemoryInternal(hProcess, localPeb.Ldr, &localLdr, sizeof(PEB_LDR_DATA))) return NULL;

    PVOID remoteListHead = (BYTE*)localPeb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
    LIST_ENTRY currentEntry = localLdr.InMemoryOrderModuleList;

    WCHAR targetNameWide[MAX_PATH] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, targetModuleName, -1, targetNameWide, MAX_PATH);

    while (currentEntry.Flink != remoteListHead) {
        PVOID tableEntryAddr = CONTAINING_RECORD(currentEntry.Flink, LDR_DATA_TABLE_ENTRY_COMPAT, InMemoryOrderLinks);
        LDR_DATA_TABLE_ENTRY_COMPAT moduleEntry = { 0 };

        if (!ReadMemoryInternal(hProcess, tableEntryAddr, &moduleEntry, sizeof(LDR_DATA_TABLE_ENTRY_COMPAT))) break;

        if (moduleEntry.BaseDllName.Buffer && moduleEntry.BaseDllName.Length < (MAX_PATH * sizeof(WCHAR))) {
            WCHAR localNameBuffer[MAX_PATH] = { 0 };
            
            if (ReadMemoryInternal(hProcess, moduleEntry.BaseDllName.Buffer, localNameBuffer, moduleEntry.BaseDllName.Length)) {
                localNameBuffer[moduleEntry.BaseDllName.Length / sizeof(WCHAR)] = L'\0';

                if (_wcsicmp(localNameBuffer, targetNameWide) == 0) {
                    return moduleEntry.DllBase;
                }
            }
        }
        currentEntry = moduleEntry.InMemoryOrderLinks;
    }
    return NULL;
}

PVOID GetProcAddressManualGeneric(HANDLE hProcess, PVOID moduleBase, const char* functionName, WORD ordinal) {
    IMAGE_DOS_HEADER dosHeader = { 0 };
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    if (!GetPEHeaders(hProcess, moduleBase, &dosHeader, &ntHeaders)) return NULL;

    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY exportDir = { 0 };
    PVOID exportDirAddr = (BYTE*)moduleBase + exportDataDir.VirtualAddress;
    if (!ReadMemoryInternal(hProcess, exportDirAddr, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY))) return NULL;

    if (functionName == NULL) {
        // Resolve via Ordinal
        DWORD functionIndex = ordinal - exportDir.Base;
        if (functionIndex >= exportDir.NumberOfFunctions) return NULL;

        DWORD funcRVA = 0;
        PVOID funcRVAAddr = (BYTE*)moduleBase + exportDir.AddressOfFunctions + (functionIndex * sizeof(DWORD));
        if (!ReadMemoryInternal(hProcess, funcRVAAddr, &funcRVA, sizeof(DWORD))) return NULL;

        return (BYTE*)moduleBase + funcRVA;
    }

    // Resolve via Name (Binary Search)
    DWORD* nameTable = (DWORD*)malloc(exportDir.NumberOfNames * sizeof(DWORD));
    WORD* ordinalTable = (WORD*)malloc(exportDir.NumberOfNames * sizeof(WORD));
    if (!nameTable || !ordinalTable) {
        free(nameTable); free(ordinalTable);
        return NULL;
    }

    ReadMemoryInternal(hProcess, (BYTE*)moduleBase + exportDir.AddressOfNames, nameTable, exportDir.NumberOfNames * sizeof(DWORD));
    ReadMemoryInternal(hProcess, (BYTE*)moduleBase + exportDir.AddressOfNameOrdinals, ordinalTable, exportDir.NumberOfNames * sizeof(WORD));

    int low = 0;
    int high = exportDir.NumberOfNames - 1;
    PVOID functionAddress = NULL;

    while (low <= high) {
        int mid = low + (high - low) / 2;
        char currentName[256] = { 0 };
        
        PVOID nameAddress = (BYTE*)moduleBase + nameTable[mid];
        ReadMemoryInternal(hProcess, nameAddress, currentName, sizeof(currentName) - 1);

        int cmp = strcmp(functionName, currentName);
        if (cmp == 0) {
            WORD ordinalValue = ordinalTable[mid];
            DWORD funcRVA = 0;
            PVOID funcRVAAddr = (BYTE*)moduleBase + exportDir.AddressOfFunctions + (ordinalValue * sizeof(DWORD));
            
            if (ReadMemoryInternal(hProcess, funcRVAAddr, &funcRVA, sizeof(DWORD))) {
                if (funcRVA >= exportDataDir.VirtualAddress && funcRVA < (exportDataDir.VirtualAddress + exportDataDir.Size)) {
                    printf("[!] Warning: Forwarded export detected.\n");
                    break;
                }
                functionAddress = (BYTE*)moduleBase + funcRVA;
            }
            break;
        }
        if (cmp < 0) high = mid - 1;
        else low = mid + 1;
    }

    free(nameTable);
    free(ordinalTable);
    return functionAddress;
}

PVOID GetPebAddressGeneric(HANDLE hProcess) {
    // --- Bootstrap our own API resolution via the local PEB ---
    // Get the local PEB base address silently
    if (hProcess == NULL || hProcess == LOCAL_PROCESS_HANDLE || hProcess == GetCurrentProcess()) {
#ifdef _WIN64
        return (PVOID)__readgsqword(0x60);
#else
        return (PVOID)__readfsdword(0x30);
#endif
    }

    // Remote Architecture Traversal Path
#ifdef _WIN64
    PVOID localPeb = (PVOID)__readgsqword(0x60);
#else
    localPeb = (PVOID)__readfsdword(0x30);
#endif

    // Locate ntdll.dll locally using a custom module parser (replaces GetModuleHandle)
    PVOID localNtdllBase = GetModuleBaseManualGeneric(LOCAL_PROCESS_HANDLE, localPeb, "ntdll.dll");
    if (!localNtdllBase) return NULL;

    // Locate NtQueryInformationProcess using a custom EAT parser (replaces GetProcAddress)
    pNtQueryInformationProcess CustomNtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddressManualGeneric(
        LOCAL_PROCESS_HANDLE, 
        localNtdllBase, 
        "NtQueryInformationProcess", 
        0
    );
    if (!CustomNtQueryInfoProcess) return NULL;

    // --- Perform the Query ---
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    // Call the manually resolved function pointer
    NTSTATUS status = CustomNtQueryInfoProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    return (status == STATUS_SUCCESS) ? pbi.PebBaseAddress : NULL;
}

BOOL GetModuleSectionGeneric(HANDLE hProcess, PVOID moduleBase, const char* sectionName, IMAGE_SECTION_INFO* outSectionInfo) {
    IMAGE_DOS_HEADER dosHeader = { 0 };
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    if (!GetPEHeaders(hProcess, moduleBase, &dosHeader, &ntHeaders)) return FALSE;

    PVOID sectionTableAddr = (BYTE*)moduleBase + dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader;
    WORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;

    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * numberOfSections);
    if (!sectionHeaders) return FALSE;

    if (!ReadMemoryInternal(hProcess, sectionTableAddr, sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * numberOfSections)) {
        free(sectionHeaders);
        return FALSE;
    }

    BOOL found = FALSE;
    for (WORD i = 0; i < numberOfSections; i++) {
        if (strncmp((char*)sectionHeaders[i].Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            outSectionInfo->VirtualAddress = sectionHeaders[i].VirtualAddress;
            outSectionInfo->SizeOfRawData = sectionHeaders[i].SizeOfRawData;
            outSectionInfo->VirtualSize = sectionHeaders[i].Misc.VirtualSize;
            found = TRUE;
            break;
        }
    }

    free(sectionHeaders);
    return found;
}

/**
 * Finds the absolute virtual address of the first exported function entry point
 * that physically resides inside the .text section.
 */
PVOID FindFirstExportInTextSectionGeneric(HANDLE hProcess, PVOID moduleBase) {
    // 1. Reuse your existing section finder to get .text boundaries cleanly
    IMAGE_SECTION_INFO textSec = { 0 };
    if (!GetModuleSectionGeneric(hProcess, moduleBase, ".text", &textSec)) {
        printf("[-] Failed to find .text section boundaries.\n");
        return NULL;
    }

    DWORD textStartRVA = textSec.VirtualAddress;
    DWORD textEndRVA = textStartRVA + ((textSec.VirtualSize > 0) ? textSec.VirtualSize : textSec.SizeOfRawData);

    // 2. Read and validate PE headers for the Export Data Directory
    IMAGE_DOS_HEADER dosHeader = { 0 };
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    if (!GetPEHeaders(hProcess, moduleBase, &dosHeader, &ntHeaders)) return NULL;

    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0 || exportDataDir.Size == 0) return NULL;

    // 3. Read the core Export Directory
    IMAGE_EXPORT_DIRECTORY exportDir = { 0 };
    PVOID exportDirAddr = (BYTE*)moduleBase + exportDataDir.VirtualAddress;
    if (!ReadMemoryInternal(hProcess, exportDirAddr, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY))) return NULL;
    if (exportDir.NumberOfFunctions == 0) return NULL;

    // 4. Pull down the Export Address Table (EAT)
    DWORD* eatBuffer = (DWORD*)malloc(exportDir.NumberOfFunctions * sizeof(DWORD));
    if (!eatBuffer) return NULL;

    PVOID eatAddress = (BYTE*)moduleBase + exportDir.AddressOfFunctions;
    if (!ReadMemoryInternal(hProcess, eatAddress, eatBuffer, exportDir.NumberOfFunctions * sizeof(DWORD))) {
        free(eatBuffer);
        return NULL;
    }

    PVOID targetFunctionAddress = NULL;

    // 5. Locate the first valid RVA residing inside the .text section
    for (DWORD i = 0; i < exportDir.NumberOfFunctions; i++) {
        DWORD currentFuncRVA = eatBuffer[i];
        if (currentFuncRVA == 0) continue;

        // Skip forwarded exports
        if (currentFuncRVA >= exportDataDir.VirtualAddress && 
            currentFuncRVA < (exportDataDir.VirtualAddress + exportDataDir.Size)) {
            continue;
        }

        // Check if RVA fits inside .text bounds
        if (currentFuncRVA >= textStartRVA && currentFuncRVA < textEndRVA) {
            targetFunctionAddress = (BYTE*)moduleBase + currentFuncRVA;
            break; 
        }
    }

    free(eatBuffer);
    return targetFunctionAddress;
}

// ============================================================================
// --- Image Path Utilities ---
// ============================================================================

WCHAR* GetRemoteProcessImagePathEx(HANDLE hProcess, PPEB pLocalPebContent) {
    if (!pLocalPebContent || !pLocalPebContent->ProcessParameters) return NULL;

    // 1. Read the Process Parameters structure using the pointer inside your pre-read PEB
    RTL_USER_PROCESS_PARAMETERS_LITE procParams;
    if (!ReadMemoryInternal(hProcess, pLocalPebContent->ProcessParameters, &procParams, sizeof(procParams))) {
        return NULL;
    }

    // 2. Allocate space and fetch the wide string path
    USHORT pathLenBytes = procParams.ImagePathName.Length;
    WCHAR* localPathBuffer = (WCHAR*)malloc(pathLenBytes + sizeof(WCHAR));
    if (!localPathBuffer) return NULL;

    ZeroMemory(localPathBuffer, pathLenBytes + sizeof(WCHAR));

    if (ReadMemoryInternal(hProcess, procParams.ImagePathName.Buffer, localPathBuffer, pathLenBytes)) {
        return localPathBuffer; // Caller frees 
    }

    free(localPathBuffer);
    return NULL;
}

/**
 * Convenience Wrapper: Handles fetching the PEB for you if you don't have it yet.
 */
WCHAR* GetRemoteProcessImagePath(HANDLE hProcess) {
    PVOID remotePebAddr = GetPebAddressGeneric(hProcess);
    if (!remotePebAddr) return NULL;

    PEB localPeb;
    if (!ReadMemoryInternal(hProcess, remotePebAddr, &localPeb, sizeof(PEB))) {
        return NULL;
    }

    // invoke the optimized function
    return GetRemoteProcessImagePathEx(hProcess, &localPeb);
}

// ============================================================================
// --- Exported Public API Wrappers ---
// ============================================================================

void* GetLocalTebAddress(void) {
#ifdef _WIN64
    return (void*)__readgsqword(0x30);
#else
    return (void*)__readfsdword(0x18);
#endif
}

PVOID GetRemotePebAddress(HANDLE hProcess) { 
    return GetPebAddressGeneric(hProcess); 
}

PVOID GetLocalPebAddress(void) {
    return GetPebAddressGeneric(LOCAL_PROCESS_HANDLE);
}

PVOID GetModuleBaseManual(PPEB pebObject, const char* targetModuleName) {
    return GetModuleBaseManualGeneric(LOCAL_PROCESS_HANDLE, (PVOID)pebObject, targetModuleName);
}

PVOID GetModuleBaseManualRemote(HANDLE hProcess, PVOID remotePebAddr, const char* targetModuleName) {
    return GetModuleBaseManualGeneric(hProcess, remotePebAddr, targetModuleName);
}

PVOID GPAManualByName(HMODULE hMod, char* targetFunc) {
    return GetProcAddressManualGeneric(LOCAL_PROCESS_HANDLE, (PVOID)hMod, targetFunc, 0);
}

PVOID GPAManualByOrdinal(HMODULE hMod, WORD ordinal) {
    return GetProcAddressManualGeneric(LOCAL_PROCESS_HANDLE, (PVOID)hMod, NULL, ordinal);
}

PVOID GetRemoteProcAddressManual(HANDLE hProcess, PVOID moduleBase, const char* functionName) {
    return GetProcAddressManualGeneric(hProcess, moduleBase, functionName, 0);
}

BOOL GetRemoteModuleSection(HANDLE hProcess, PVOID moduleBase, const char* sectionName, IMAGE_SECTION_INFO* outSectionInfo) {
    return GetModuleSectionGeneric(hProcess, moduleBase, sectionName, outSectionInfo);
}