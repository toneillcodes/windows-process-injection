#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>     // Required for __readgsqword / __readfsdword
#include <winternl.h>   // for peb data structure https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb

#include "../includes/utils.h"              //  crt replacements
#include "../includes/peb-eat-utils.h"      //  custom peb/eat walking functions

#define MAX_EXPORTED_FUNCS 25

#pragma comment(lib, "user32.lib")

// custom type defs for function invocation
typedef int (WINAPI* myMessageBoxA)(HWND hWnd, LPCSTR lptext, LPCSTR lpCaption, UINT uType);

int main(int argc, char* argv[]) {
    // import MessageBoxA for testing without triggering a message to the UI
    if (argc > 999) MessageBoxA(NULL, NULL, NULL, 0);
    
    int debugOutput = 1;

    void* teb = GetLocalTebAddress();
    if (debugOutput) {
        printf("Current process TEB address: %p\n", teb);
    }
	
    // maybe move this to a GetLocalPebAddress function?
    // this is good for demonstration but we can really skip straight to the PEB
    void* peb = NULL;
#ifdef _WIN64
    // On x64, PEB is at TEB + 0x60
    peb = *(void**)((unsigned char*)teb + 0x60);
#else
    // On x86, PEB is at TEB + 0x30
    // not currently used, but good to have around
    peb = *(void**)((unsigned char*)teb + 0x30);
#endif
    if (debugOutput) {
        printf("Current process PEB address (TEB + offset): %p\n", peb);
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb#remarks
    // Assuming peb_address holds the valid memory location of the PEB
    PPEB peb_ptr = (PPEB)peb;

    // Accessing the 'BeingDebugged' flag
    if (peb_ptr->BeingDebugged) {
        printf("Debugger is attached\n");
    }
    else {
        printf("No debugger detected\n");
    }
    
    PVOID dllBase = GetModuleBaseManual(peb_ptr, "USER32.dll");         // or maybe ntdll.dll
    if(dllBase) {
        printf("DLL found @ %llx\n",dllBase);
        PVOID rvaFound = GetProcAddressManualByName((HMODULE) dllBase, "MessageBoxA");    // and then NtAllocateVirtualMemory
        if(rvaFound) {
            printf("found function within DLL @ %llx\n", rvaFound);			
            // MessageBoxA example
            myMessageBoxA dynamicMsgBox = NULL;
            dynamicMsgBox = (myMessageBoxA)rvaFound;
            dynamicMsgBox(NULL, "Executed via manual address resolution!", "Success", MB_OK);            
        } else {
            printf("Unable to locate function\n");
        }
    } else {
        printf("Unable to locate DLL\n");
    }
   
    printf("Done.");
    return 0;
}