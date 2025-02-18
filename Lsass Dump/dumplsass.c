#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#pragma comment (lib, "dbghelp.lib")

// Function Prototypes
DWORD getProcessID(const char *procName);
BOOL enablePrivilege(LPCTSTR privilegeName);
BOOL createMiniDump(DWORD processID, const char *dumpFilePath);

// Locate target process by name
DWORD getProcessID(const char *procName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD processID = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Process32First failed. Error: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(procName, pe32.szExeFile) == 0) {
            processID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return processID;
}

// Enable required privilege
BOOL enablePrivilege(LPCTSTR privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        printf("LookupPrivilegeValue failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Create minidump of target process
BOOL createMiniDump(DWORD processID, const char *dumpFilePath) {
    HANDLE hProcess, hDumpFile;
    BOOL dumpResult = FALSE;

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        printf("OpenProcess failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    hDumpFile = CreateFile(dumpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    dumpResult = MiniDumpWriteDump(hProcess, processID, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (dumpResult) {
        printf("Minidump successfully created: %s\n", dumpFilePath);
    } else {
        printf("MiniDumpWriteDump failed. Error: %lu\n", GetLastError());
    }

    CloseHandle(hDumpFile);
    CloseHandle(hProcess);
    return dumpResult;
}

int main() {
    const char *targetProc = "lsass.exe";
    const char *dumpFile = "C:\\temp\\lsass_advanced.dmp";
    DWORD processID;

    if (!enablePrivilege(SE_DEBUG_NAME)) {
        printf("Failed to enable SE_DEBUG_NAME privilege.\n");
        return EXIT_FAILURE;
    }

    processID = getProcessID(targetProc);
    if (processID == 0) {
        printf("Target process not found: %s\n", targetProc);
        return EXIT_FAILURE;
    }

    if (!createMiniDump(processID, dumpFile)) {
        printf("Failed to create minidump.\n");
        return EXIT_FAILURE;
    }

    printf("Operation completed successfully.\n");
    return EXIT_SUCCESS;
}
