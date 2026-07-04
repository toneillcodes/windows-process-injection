#pragma once
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

typedef LONG NTSTATUS;

typedef enum _SYSCALL_FLAVOR {
    FLAVOR_WIN32,
    FLAVOR_DFR,
    FLAVOR_DIRECT,
    FLAVOR_INDIRECT
} SYSCALL_FLAVOR;

typedef enum _PITECHNIQUE {
    DEFAULT,
    EARLY_BIRD_APC,
    PROCESS_HOLLOWING
} PITECHNIQUE;

// Shared pipeline state
typedef struct _INJECTION_CONTEXT {
    BOOL   spawnTarget;
    char*  spawnPath;
    DWORD  targetPid;
    HANDLE hProcess;
    HANDLE hThread;
    PVOID  pRemoteAddress;
    SIZE_T payloadSize;
    BOOL   enableStomping;
    char*  targetModule;
    char*  targetExport;
    DWORD  targetOffset;
    PITECHNIQUE technique;
} INJECTION_CONTEXT, *PINJECTION_CONTEXT;

// Function pointer signatures, currently unused
typedef BOOL(*FnAllocate)(PINJECTION_CONTEXT ctx, DWORD protect, SYSCALL_FLAVOR flavor);
typedef BOOL(*FnWrite)(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor);
typedef BOOL(*FnProtect)(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect, SYSCALL_FLAVOR flavor);
typedef BOOL(*FnInvoke)(PINJECTION_CONTEXT ctx, SYSCALL_FLAVOR flavor);

typedef struct _INJECTION_ENGINE {
    FnAllocate Allocate;
    FnWrite    Write;
    FnProtect  Protect;
    FnInvoke   Invoke;    
} INJECTION_ENGINE, *PINJECTION_ENGINE;

// DFR Definitions
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
typedef LPVOID(WINAPI* P_VirtualAllocEx)(
	HANDLE pHandle,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
typedef BOOL(WINAPI* P_VirtualProtectEx) (
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
typedef BOOL(WINAPI* P_WriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
typedef HANDLE(WINAPI* P_CreateRemoteThread) (
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId	
);

// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
typedef DWORD(WINAPI* P_WaitForSingleObject) (
    HANDLE hHandle,
    DWORD  dwMilliseconds
);

// --- FORCE C-LINKAGE FOR ASSEMBLY & C++ UTILITIES ---
#ifdef __cplusplus
extern "C" {
#endif

// Indirect assembly stubs from indirect-syscalls.obj
NTSTATUS IndirectSysNtAllocateVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
);
NTSTATUS IndirectSysNtProtectVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    PSIZE_T RegionSize, 
    ULONG NewProtect, 
    PULONG OldProtect
);
NTSTATUS IndirectSysNtWriteVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID BaseAddress, 
    PVOID Buffer, 
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS IndirectSysNtCreateThreadEx(
    PHANDLE ThreadHandle, 
    ACCESS_MASK DesiredAccess, 
    PVOID ObjectAttributes, 
    HANDLE ProcessHandle, 
    PVOID lpStartAddress, 
    PVOID lpParameter, 
    ULONG Flags, 
    SIZE_T StackZeroBits, 
    SIZE_T SizeOfStackCommit, 
    SIZE_T SizeOfStackReserve, 
    PVOID lpBytesBuffer
);

NTSTATUS IndirectSysNtWaitForSingleObject(
    HANDLE Handle, 
    BOOLEAN Alertable, 
    PLARGE_INTEGER Timeout
);

// Direct assembly stubs

// https://ntdoc.m417z.com/NtAllocateVirtualMemory
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,    
    PVOID* BaseAddress,      
    ULONG_PTR ZeroBits,      
    PSIZE_T RegionSize,      
    ULONG AllocationType,    
    ULONG Protect            
);

// https://ntdoc.m417z.com/ntprotectvirtualmemory
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

// https://ntdoc.m417z.com/NtWriteVirtualMemory
NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,     
    PVOID BaseAddress,        
    PVOID Buffer,             
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten 
);

// Added missing direct prototype for the protection phase
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// https://ntdoc.m417z.com/ntcreatethreadex
NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,        
    ACCESS_MASK DesiredAccess,   
    PVOID ObjectAttributes,      
    HANDLE ProcessHandle,        
    PVOID lpStartAddress,        
    PVOID lpParameter,           
    ULONG Flags,                 
    SIZE_T StackZeroBits,        
    SIZE_T SizeOfStackCommit,    
    SIZE_T SizeOfStackReserve,   
    PVOID lpBytesBuffer          
);

// https://ntdoc.m417z.com/NtWaitForSingleObject
NTSTATUS SysNtWaitForSingleObject(
    HANDLE Handle,          
    BOOLEAN Alertable,      
    PLARGE_INTEGER Timeout  
);

#ifdef __cplusplus
}
#endif

// engine declarations
BOOL InitializeResolvers(SYSCALL_FLAVOR flavor);
BOOL DefaultAllocate(PINJECTION_CONTEXT ctx, DWORD protect, SYSCALL_FLAVOR flavor);
BOOL DefaultWrite(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor);
BOOL DefaultProtect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect, SYSCALL_FLAVOR flavor);
BOOL DefaultInvoke(PINJECTION_CONTEXT ctx,  SYSCALL_FLAVOR flavor);
BOOL EngineExecute(PINJECTION_ENGINE engine, PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor, DWORD finalProtect);