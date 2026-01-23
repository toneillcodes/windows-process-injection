#ifndef PEB_EAT_UTILS_H
#define PEB_EAT_UTILS_H

#include <windows.h>
#include <winternl.h> 
#include <intrin.h>    

// Define missing NTSTATUS codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Returns the TEB address for the current thread
void* GetLocalTebAddress(void);

// Returns the address of the PEB for a remote process
PVOID GetRemotePebAddress(HANDLE hProcess);

// Basic utility to calculate string length
int my_strlen(const char* inputString);

// Manual implementation of GetProcAddress (by name)
PVOID GetProcAddressManualByName(HMODULE hMod, char* targetFunc);

// Manual implementation of GetProcAddress (by ordinal)
PVOID GetProcAddressManualByOrdinal(HMODULE hMod, WORD ordinal);

// Manually finds the base address of a module using the PEB's Ldr list
PVOID GetModuleBaseManual(PPEB pebObject, const char* targetModuleName);

#endif // PEB_EAT_UTILS_H