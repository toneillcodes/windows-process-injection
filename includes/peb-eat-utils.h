#pragma once
#include <windows.h>
#include <winternl.h>

// --- Structures & Defines ---
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef struct _IMAGE_SECTION_INFO {
    PVOID VirtualAddress;
    DWORD SizeOfRawData;
    DWORD VirtualSize;
} IMAGE_SECTION_INFO, *PIMAGE_SECTION_INFO;

// Custom layout ensuring BaseDllName is present regardless of SDK versions
typedef struct _LDR_DATA_TABLE_ENTRY_COMPAT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_COMPAT, *PLDR_DATA_TABLE_ENTRY_COMPAT;

// --- Forward Declarations of Public API Functions ---
void* GetLocalTebAddress(void);
PVOID GetRemotePebAddress(HANDLE hProcess);

PVOID GetModuleBaseManual(PPEB pebObject, const char* targetModuleName);
PVOID GetModuleBaseManualRemote(HANDLE hProcess, PVOID remotePebAddr, const char* targetModuleName);

PVOID GPAManualByName(HMODULE hMod, char* targetFunc);
PVOID GPAManualByOrdinal(HMODULE hMod, WORD ordinal);
PVOID GetRemoteProcAddressManual(HANDLE hProcess, PVOID moduleBase, const char* functionName);

BOOL GetRemoteModuleSection(HANDLE hProcess, PVOID moduleBase, const char* sectionName, IMAGE_SECTION_INFO* outSectionInfo);