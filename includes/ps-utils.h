#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD FindPidByName(const wchar_t* processName);

#ifdef __cplusplus
}
#endif