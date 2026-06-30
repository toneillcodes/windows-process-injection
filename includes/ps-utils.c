#include "ps-utils.h"
#include <tlhelp32.h>
#include <wchar.h>

DWORD FindPidByName(const wchar_t* processName) {
    DWORD pid = 0;
    // Force the Wide-character version of the struct
    PROCESSENTRY32W entry; 
    entry.dwSize = sizeof(PROCESSENTRY32W);

    // Create a snapshot of the system processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        // Force the Wide-character version of the API
        if (Process32FirstW(snapshot, &entry)) {
            do {
                // Now both sides are Wide strings, so _wcsicmp works!
                if (_wcsicmp(processName, entry.szExeFile) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

HANDLE GetProcessHandle(DWORD targetPID) {
    // Request ONLY the minimum permissions needed for the job:
    // 1. PROCESS_QUERY_INFORMATION - needed for NtQueryInformationProcess (PEB location)
    // 2. PROCESS_VM_READ           - needed for ReadProcessMemory (reading the DLL list)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPID);

    if (hProcess == NULL) {
        DWORD error = GetLastError();
        //printf("[-] OpenProcess failed! Error code: %lu\n", error);
        
        // Quick troubleshooting tips based on common error codes:
        if (error == ERROR_ACCESS_DENIED) {
            //printf("[!] Hint: Access Denied. Try running your tool as Administrator,\n");
            //printf("    or check if you are targeting a protected system process (like lsass.exe).\n");
        } else if (error == ERROR_INVALID_PARAMETER) {
            //printf("[!] Hint: Invalid Parameter. Double-check that the PID actually exists.\n");
        }
        return NULL;
    }

    //printf("[+] Successfully obtained handle for PID %lu\n", targetPID);
    return hProcess;
}