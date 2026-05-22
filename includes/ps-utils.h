#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD FindPidByName(const wchar_t* processName);
HANDLE GetProcessHandle(DWORD pid);

#ifdef __cplusplus
}
#endif