/*
* Outputs the DLLs loaded by a process with optional flags to display names only and write to a file
* compile: cl.exe list-process-dlls.c ..\includes\peb-eat-utils.c ..\includes\utils.c ..\includes\ps-utils.c
*/
#include <stdio.h>
#include <stdbool.h> // Ensure bool, true, and false are explicitly supported

#include "..\includes\peb-eat-utils.h"
#include "..\includes\ps-utils.h"

void InventoryRemoteDlls(HANDLE hProcess, bool namesOnly, bool showSize, bool includeImagePath, const char* outputFilePath) {
    PVOID remotePebAddr = GetRemotePebAddress(hProcess);
    if (!remotePebAddr) {
        printf("[-] Failed to locate remote PEB.\n");
        return;
    }

    PEB remotePebContent;
    if (!ReadProcessMemory(hProcess, remotePebAddr, &remotePebContent, sizeof(PEB), NULL)) {
        printf("[-] Failed to read remote PEB structure. Error: %lu\n", GetLastError());
        return;
    }
    
    PEB_LDR_DATA remoteLdrContent;
    if (!ReadProcessMemory(hProcess, remotePebContent.Ldr, &remoteLdrContent, sizeof(PEB_LDR_DATA), NULL)) {
        printf("[-] Failed to read remote LDR data.\n");
        return;
    }

    // Retrieve the executable image path using the optimized function
    WCHAR* exePath = GetRemoteProcessImagePathEx(hProcess, &remotePebContent);
    if (exePath && !showSize) {
        printf("[+] Executed From: %ws\n", exePath);
    }

    // Try opening the file if a path was provided
    FILE* outputFile = NULL;
    if (outputFilePath) {
        outputFile = fopen(outputFilePath, "w");
        if (!outputFile) {
            printf("[-] Failed to open output file: %s. Defaulting to console only.\n", outputFilePath);
        } else if (!showSize) {
            // Only print this diagnostic line if we aren't generating a pure CSV stream
            printf("[+] Output will also be dumped to: %s\n", outputFilePath);
        }
    }

    LIST_ENTRY* headRemoteLink = &((PPEB_LDR_DATA)remotePebContent.Ldr)->InMemoryOrderModuleList;
    LIST_ENTRY currentLink = remoteLdrContent.InMemoryOrderModuleList;

    // Adjust CSV headers based on whether the image path column is requested
    if (showSize) {
        if (includeImagePath) {
            printf("TargetProcess,Name,TextSectionSize\n");
            if (outputFile) fprintf(outputFile, "TargetProcess,Name,TextSectionSize\n");
        } else {
            printf("Name,TextSectionSize\n");
            if (outputFile) fprintf(outputFile, "Name,TextSectionSize\n");
        }
    } else {
        printf("[+] Enumerating loaded modules:\n");
        printf("--------------------------------------------------\n");
    }

    while (currentLink.Flink != headRemoteLink) {
        ULONG_PTR remoteEntryAddr = (ULONG_PTR)currentLink.Flink - sizeof(LIST_ENTRY);
                
        FULL_LDR_DATA_TABLE_ENTRY remoteEntryContent;
        if (!ReadProcessMemory(hProcess, (LPCVOID)remoteEntryAddr, &remoteEntryContent, sizeof(FULL_LDR_DATA_TABLE_ENTRY), NULL)) {
            if (!showSize) printf("[-] Failed to read a module entry from the list.\n");
            break;
        }

        USHORT nameLen = remoteEntryContent.BaseDllName.Length;
        WCHAR* localBuffer = (WCHAR*)malloc(nameLen + sizeof(WCHAR));
        
        if (localBuffer) {
            ZeroMemory(localBuffer, nameLen + sizeof(WCHAR));
            
            if (ReadProcessMemory(hProcess, remoteEntryContent.BaseDllName.Buffer, localBuffer, nameLen, NULL)) {
                
                DWORD textSectionSize = 0;

                if (showSize) {
                    IMAGE_SECTION_INFO sectionInfo = { 0 };
                    if (GetRemoteModuleSection(hProcess, remoteEntryContent.DllBase, ".text", &sectionInfo)) {
                        textSectionSize = sectionInfo.VirtualSize; 
                    }
                }

                if (showSize) {
                    // Conditional CSV formatting row structure
                    if (includeImagePath && exePath) {
                        printf("%ws,%ws,%lu\n", exePath, localBuffer, textSectionSize);
                        if (outputFile) fprintf(outputFile, "%ws,%ws,%lu\n", exePath, localBuffer, textSectionSize);
                    } else {
                        printf("%ws,%lu\n", localBuffer, textSectionSize);
                        if (outputFile) fprintf(outputFile, "%ws,%lu\n", localBuffer, textSectionSize);
                    }
                } 
                else if (namesOnly) {
                    printf("%ws\n", localBuffer);
                    if (outputFile) fprintf(outputFile, "%ws\n", localBuffer);
                } 
                else {
                    printf("[0x%p - Size: %lu] %ws\n", remoteEntryContent.DllBase, remoteEntryContent.SizeOfImage, localBuffer);
                    if (outputFile) {                        
                        fprintf(outputFile, "[0x%p - Size: %lu] %ws\n", remoteEntryContent.DllBase, remoteEntryContent.SizeOfImage, localBuffer);
                    }
                }
            }
            free(localBuffer);
        }

        currentLink = remoteEntryContent.InMemoryOrderLinks;
    }

    // Clean up our string asset allocation before exiting out
    if (exePath) {
        free(exePath);
    }

    if (outputFile) {
        fclose(outputFile);
    }
}

void PrintUsage(const char* programName) {
    printf("Usage: %s [options]\n", programName);
    printf("Options:\n");
    printf("  -p, --pid                Target process ID.\n");
    printf("  -n, --names-only         Only print out the raw DLL names (omit base addresses)\n");
    printf("  -s, --size               Output name and .text size in CSV format\n");
    printf("  -i, --include-path       Include the target process image path within the CSV output\n");
    printf("  -o, --output <filename>  Dump the inventory out to a text file\n");
    printf("  -h, --help               Show this help screen\n");
}

int handleArgs(int argc, char *argv[], bool* namesOnly, bool* showSize, bool* includeImagePath, const char** outputFilePath, DWORD* targetPid) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return -1; 
        }        
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) {
            if (i + 1 < argc) {                
                *targetPid = atoi(argv[i + 1]);
                i++; 
            } else {
                printf("[-] Error: -p/--pid requires a target process ID.\n");
                PrintUsage(argv[0]);
                return 1;
            }
        } 
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--names-only") == 0) {            
            *namesOnly = true;
        } 
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) {            
            *showSize = true;
        } 
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--include-path") == 0) {            
            *includeImagePath = true;
        } 
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {                
                *outputFilePath = argv[i + 1];
                i++; 
            } else {
                printf("[-] Error: -o/--output requires a file path argument.\n");
                PrintUsage(argv[0]);
                return 1;
            }
        }
        else {
            printf("[-] Unknown parameter: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    bool namesOnly = false;
    bool showSize = false;
    bool includeImagePath = false;
    const char* outputFilePath = NULL; 
    DWORD targetPid = 0;

    int validArgs = 0;    
    validArgs = handleArgs(argc, argv, &namesOnly, &showSize, &includeImagePath, &outputFilePath, &targetPid);

    if (validArgs == -1) {
        return 0;
    }

    if (validArgs != 0) {
        return validArgs;
    }

    if (targetPid == 0) {
        printf("[-] Error: Target process ID is missing or invalid.\n");
        PrintUsage(argv[0]);
        return 1;
    }

    HANDLE pHandle = GetProcessHandle(targetPid);
    if (!pHandle) {
         printf("[-] Failed to open handle to target process.\n");
         return 1;
    }

    InventoryRemoteDlls(pHandle, namesOnly, showSize, includeImagePath, outputFilePath);

    CloseHandle(pHandle);
    return 0;
}