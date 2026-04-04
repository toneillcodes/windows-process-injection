#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD GetSSN(PVOID functionAddress);
PVOID GetSyscallAddress(PVOID functionAddress);

#ifdef __cplusplus
}
#endif