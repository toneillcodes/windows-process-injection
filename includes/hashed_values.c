#pragma once
#include "hashed_values.h"
#include "hash_functions.h"

// DLLs
HASHED_VALUE hv_kernel32            = { ror13, 0x8FECD63F };
//HASHED_VALUE hv_kernel32            = { djb2, 0x7040EE75 };
//HASHED_VALUE hv_kernel32            = { fnv1a, 0xA3E6F6C3 };
//HASHED_VALUE hv_kernel32            = { crc32, 0x6AE69F02 };
//HASHED_VALUE hv_kernel32            = { sdbm, 0x8F7EE672 };

HASHED_VALUE hv_ntdll               = { ror13, 0xCEF6E822 };
//HASHED_VALUE hv_ntdll               = { djb2, 0x22D3B5ED };
//HASHED_VALUE hv_ntdll               = { fnv1a, 0xA62A3B3B };
//HASHED_VALUE hv_ntdll               = { crc32, 0x84C05E40 };
//HASHED_VALUE hv_ntdll               = { sdbm, 0xD22E2014 };

// APIs
//HASHED_VALUE hv_VirtualAlloc      = { ror13, 0x91F1CA54 };
HASHED_VALUE hv_VirtualAlloc        = { djb2, 0x58DACBD7 };
//HASHED_VALUE hv_VirtualAlloc        = { fnv1a, 0x58DACBD7 };
//HASHED_VALUE hv_VirtualAlloc        = { crc32, 0x58DACBD7 };
//HASHED_VALUE hv_VirtualAlloc        = { sdbm, 0x58DACBD7 };

//HASHED_VALUE hv_VirtualProtect      = { ror13, 0x89C6C61B };
HASHED_VALUE hv_VirtualProtect      = { djb2, 0x8B9EBDCD };
//HASHED_VALUE hv_VirtualProtect      = { fnv1a, 0x7851C633 };
//HASHED_VALUE hv_VirtualProtect      = { crc32, 0x12DF2E6B };
//HASHED_VALUE hv_VirtualProtect      = { sdbm, 0x208602E4 };

//HASHED_VALUE hv_LoadLibraryA        = { ror13, 0xEC4E52AE };
//HASHED_VALUE hv_LoadLibraryA        = { djb2,  0x0666395B };
//HASHED_VALUE hv_LoadLibraryA        = { fnv1a, 0x4DBC712F };
HASHED_VALUE hv_LoadLibraryA        = { crc32, 0xE5E824EB };
//HASHED_VALUE hv_LoadLibraryA        = { sdbm, 0xE4D44BCC };

//HASHED_VALUE hv_GetProcAddr         = { ror13, 0x8C8DFCB2 };
HASHED_VALUE hv_GetProcAddr         = { djb2, 0xA2A45B14 };
//HASHED_VALUE hv_GetProcAddr         = { fnv1a, 0xBCABB6F0 };
//HASHED_VALUE hv_GetProcAddr         = { crc32, 0x0BA0C213 };
//HASHED_VALUE hv_GetProcAddr         = { sdbm, 0x51998ABD };

HASHED_VALUE hv_RtlAddFunctionTable = { ror13, 0x2AFE1865 };
//HASHED_VALUE hv_RtlAddFunctionTable = { djb2, 0x4DCFB62E };
//HASHED_VALUE hv_RtlAddFunctionTable = { fnv1a, 0x294780A8 };
//HASHED_VALUE hv_RtlAddFunctionTable = { crc32, 0x0F38DC03 };
//HASHED_VALUE hv_RtlAddFunctionTable = { sdbm, 0xA761CC3F };

HASHED_VALUE hv_TlsAlloc            = { ror13, 0x5D2E3A1D };
//HASHED_VALUE hv_TlsAlloc            = { djb2, 0x1672FDA3 };
//HASHED_VALUE hv_TlsAlloc            = { fnv1a, 0xDDF1729B };
//HASHED_VALUE hv_TlsAlloc            = { crc32, 0x2E297A75 };
//HASHED_VALUE hv_TlsAlloc            = { sdbm, 0xC71E8E5A };

//HASHED_VALUE hv_TlsGetValue         = { ror13, 0x3A46E89D };
//HASHED_VALUE hv_TlsGetValue         = { djb2, 0xE6234575 };
HASHED_VALUE hv_TlsGetValue         = { fnv1a, 0x07C1AA27 };
//HASHED_VALUE hv_TlsGetValue         = { crc32, 0x6FCFA16D };
//HASHED_VALUE hv_TlsGetValue         = { sdbm, 0x6F3EA336 };

HASHED_VALUE hv_TlsSetValue         = { ror13, 0x3A46EA1D };
//HASHED_VALUE hv_TlsSetValue         = { djb2, 0xF9394001 };
//HASHED_VALUE hv_TlsSetValue         = { fnv1a, 0x892105D3 };
//HASHED_VALUE hv_TlsSetValue         = { crc32, 0x973E9EBC };
//HASHED_VALUE hv_TlsSetValue         = { sdbm, 0x1412F82A };

HASHED_VALUE hv_VirtualAllocEx = { ror13, 0x7F9A959C };
HASHED_VALUE hv_WriteProcessMemory = { ror13, 0xD83D6DB1 };
HASHED_VALUE hv_VirtualProtectEx = { ror13, 0x74D9875A };
HASHED_VALUE hv_CreateRemoteThread = { ror13, 0x72FD9DED };
HASHED_VALUE hv_WaitForSingleObject = { ror13, 0xD64659BD };
HASHED_VALUE hv_NtAllocateVirtualMemory = { ror13, 0xD33BCD4F };
HASHED_VALUE hv_NtWriteVirtualMemory = { ror13, 0xC510CFD2 };
HASHED_VALUE hv_NtProtectVirtualMemory = { ror13, 0x8C498F99 };
HASHED_VALUE hv_NtCreateThreadEx = { ror13, 0x5E1DEF78 };
HASHED_VALUE hv_NtWaitForSingleObject = { ror13, 0xB64741C4 };
HASHED_VALUE hv_NtQueryVirtualMemory = { ror13, 0x4F13C7A2 };
HASHED_VALUE hv_NtQueryInformationProcess = { ror13, 0xB18FF9B9 };

// EXE
HASHED_VALUE hv_explorer = { ror13, 0x4E5CC7D6 };