#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD GetSSN(PVOID functionAddress);
DWORD GetSSNByName(PPEB peb, const char* funcName);
DWORD GetSSNByHash(PPEB peb, HASHED_VALUE hvModule, HASHED_VALUE hvFunction);
PVOID GetSyscallAddress(PVOID functionAddress);

#ifdef __cplusplus
}
#endif