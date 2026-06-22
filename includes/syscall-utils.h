#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD GetSSN(PVOID functionAddress);
DWORD GetSSNByName(PPEB peb, const char* funcName);
PVOID GetSyscallAddress(PVOID functionAddress);

#ifdef __cplusplus
}
#endif