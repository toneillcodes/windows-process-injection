#include "ps-utils.h"
#include <tlhelp32.h>
#include <wchar.h>

extern "C" DWORD FindPidByName(const wchar_t* processName) {
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