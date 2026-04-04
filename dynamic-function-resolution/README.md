# Dyanmic Function Resolution
Intended to hide functions from static analysis that evaluates strings and the IAT.

## Overview
Define the prototype definition. 
Use something that doesn't include the string you want to obfuscate.
P_VirtualAllocEx is used below along with 'myVirtualAllocEx' which are good for examples but horrible for OPSEC and defeats the purpose of DFR.
```
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
typedef LPVOID(WINAPI* P_VirtualAllocEx)(
	HANDLE pHandle,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);
```

Call GetProcAddress to resolve the address.
```
myVirtualAllocEx = (P_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
```

Invoke the function.
```
LPVOID bufferAddress = myVirtualAllocEx(pHandle, NULL, sizeof buf, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
```