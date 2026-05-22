#include <stdio.h>

#include "..\includes\peb-eat-utils.h"
#include "..\includes\ps-utils.h"

void InventoryRemoteDlls(HANDLE hProcess, bool namesOnly, const char* outputFilePath) {
    PVOID remotePebAddr = GetRemotePebAddress(hProcess);
    if (!remotePebAddr) {
        printf("[-] Failed to locate remote PEB.\n");
        return;
    }

    PEB localPeb;
    if (!ReadProcessMemory(hProcess, remotePebAddr, &localPeb, sizeof(PEB), NULL)) {
        printf("[-] Failed to read remote PEB structure. Error: %lu\n", GetLastError());
        return;
    }

    PEB_LDR_DATA localLdr;
    if (!ReadProcessMemory(hProcess, localPeb.Ldr, &localLdr, sizeof(PEB_LDR_DATA), NULL)) {
        printf("[-] Failed to read remote LDR data.\n");
        return;
    }

    // Try opening the file if a path was provided
    FILE* outputFile = NULL;
    if (outputFilePath) {
        outputFile = fopen(outputFilePath, "w");
        if (!outputFile) {
            printf("[-] Failed to open output file: %s. Defaulting to console only.\n", outputFilePath);
        } else {
            printf("[+] Output will also be dumped to: %s\n", outputFilePath);
        }
    }

    LIST_ENTRY* headRemoteLink = &((PPEB_LDR_DATA)localPeb.Ldr)->InMemoryOrderModuleList;
    LIST_ENTRY currentLink = localLdr.InMemoryOrderModuleList;

    printf("[+] Enumerating loaded modules:\n");
    printf("--------------------------------------------------\n");

    while (currentLink.Flink != headRemoteLink) {
        ULONG_PTR remoteEntryAddr = (ULONG_PTR)currentLink.Flink - sizeof(LIST_ENTRY);
        
        FULL_LDR_DATA_TABLE_ENTRY localEntry;
        if (!ReadProcessMemory(hProcess, (LPCVOID)remoteEntryAddr, &localEntry, sizeof(FULL_LDR_DATA_TABLE_ENTRY), NULL)) {
            printf("[-] Failed to read a module entry from the list.\n");
            break;
        }

        USHORT nameLen = localEntry.BaseDllName.Length;
        WCHAR* localBuffer = (WCHAR*)malloc(nameLen + sizeof(WCHAR));
        
        if (localBuffer) {
            ZeroMemory(localBuffer, nameLen + sizeof(WCHAR));
            
            if (ReadProcessMemory(hProcess, localEntry.BaseDllName.Buffer, localBuffer, nameLen, NULL)) {
                
                // Formulate the line based on the user's formatting preference
                if (namesOnly) {
                    // Raw string only
                    printf("%ws\n", localBuffer);
                    if (outputFile) {
                        fprintf(outputFile, "%ws\n", localBuffer);
                    }
                } else {
                    // Standard Base Address + String
                    printf("[0x%p] %ws\n", localEntry.DllBase, localBuffer);
                    if (outputFile) {
                        fprintf(outputFile, "[0x%p] %ws\n", localEntry.DllBase, localBuffer);
                    }
                }
            }
            free(localBuffer);
        }

        currentLink = localEntry.InMemoryOrderLinks;
    }

    // Wrap up file handles if open
    if (outputFile) {
        fclose(outputFile);
    }
}

void PrintUsage(const char* programName) {
    printf("Usage: %s [options]\n", programName);
    printf("Options:\n");
    printf("  -p, --pid                 Target process ID.\n");
    printf("  -n, --names-only          Only print out the raw DLL names (omit base addresses)\n");
    printf("  -o, --output <filename>   Dump the inventory out to a text file\n");
    printf("  -h, --help                Show this help screen\n");
}

// command line args: output names only, output to a file?
int main(int argc, char *argv[]) {
    bool namesOnly = false;
    const char* outputFilePath = NULL;
    DWORD targetPid;

    // Loop through command line parameters
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) {
            // Check if there's an actual argument following -p
            if (i + 1 < argc) {
                targetPid = atoi(argv[i + 1]);
                i++; // Skip next argument since we consumed it here
            } else {
                printf("[-] Error: -p/--pid requires a target process ID.\n");
                PrintUsage(argv[0]);
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--names-only") == 0) {
            namesOnly = true;
        } 
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            // Check if there's an actual argument following -o
            if (i + 1 < argc) {
                outputFilePath = argv[i + 1];
                i++; // Skip next argument since we consumed it here
            } else {
                printf("[-] Error: -o/--output requires a file path argument.\n");
                PrintUsage(argv[0]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else {
            printf("[-] Unknown parameter: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    // Locate target and execute

    if (targetPid == 0) {
        printf("[-] Could not find target process execution context.\n");
        return 1;
    }

    HANDLE pHandle = GetProcessHandle(targetPid);
    if (!pHandle) {
         printf("[-] Failed to open handle to target process.\n");
         return 1;
    }

    InventoryRemoteDlls(pHandle, namesOnly, outputFilePath);

    CloseHandle(pHandle);
    return 0;
}