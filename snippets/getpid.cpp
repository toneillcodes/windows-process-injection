#include <windows.h>
#include <tlhelp32.h>
#include <string>

DWORD FindPidByName(const char* processName) {
    DWORD foundpid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return foundpid;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(processName, pe.szExeFile) == 0) {
                foundpid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return foundpid;
}

void main() {
    DWORD pid = 0;
    const char* processName = "notepad.exe";

    pid = FindPidByName(processName);
    if (pid == 0) {
        printf("[ERROR] Failed to obtain process ID!\n");
    }
	
	printf("PID found: %d\n", pid);
	
}
