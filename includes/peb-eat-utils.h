#pragma once
#include <windows.h>
#include <winternl.h>

// --- Structures & Defines ---
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef struct _IMAGE_SECTION_INFO {
    DWORD VirtualAddress;
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

// Define the COMPLETE structure since winternl.h cuts out the fields we need
typedef struct _FULL_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks; 
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;    
    ULONG Flags;
    WORD ObsoleteLoadCount;
    WORD TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} FULL_LDR_DATA_TABLE_ENTRY, *PFULL_LDR_DATA_TABLE_ENTRY;

// Thread Information Class for TEB queries
#define ThreadTebInformation 26

typedef struct _THREAD_TEB_INFORMATION {
    PVOID TebInformation;
} THREAD_TEB_INFORMATION, *PTHREAD_TEB_INFORMATION;

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

// Minimum required definitions for the Process Parameters
typedef struct _RTL_USER_PROCESS_PARAMETERS_LITE {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_LITE, *PRTL_USER_PROCESS_PARAMETERS_LITE;

// --- Forward Declarations of Public API Functions ---
void* GetLocalTebAddress(void);
PVOID GetRemotePebAddress(HANDLE hProcess);

PVOID GetModuleBaseManual(PPEB pebObject, const char* targetModuleName);
PVOID GetModuleBaseManualRemote(HANDLE hProcess, PVOID remotePebAddr, const char* targetModuleName);

WCHAR* GetRemoteProcessImagePathEx(HANDLE hProcess, PPEB pLocalPebContent);
WCHAR* GetRemoteProcessImagePath(HANDLE hProcess);

PVOID GPAManualByName(HMODULE hMod, char* targetFunc);
PVOID GPAManualByOrdinal(HMODULE hMod, WORD ordinal);
PVOID GetRemoteProcAddressManual(HANDLE hProcess, PVOID moduleBase, const char* functionName);

BOOL GetRemoteModuleSection(HANDLE hProcess, PVOID moduleBase, const char* sectionName, IMAGE_SECTION_INFO* outSectionInfo);