#include <windows.h>
#include "detours.h"
#include <iostream>

// Declare pointer to original function
int (WINAPI *Real_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT) = MessageBoxW;

// Our custom hooked function
int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    std::wcout << L"[HOOKED] MessageBoxW called!" << std::endl;
    std::wcout << L"Original Text: " << lpText << std::endl;

    // Modify message text
    LPCWSTR newText = L"This message was intercepted by Detours!";
   
    // Call the original MessageBoxW
    return Real_MessageBoxW(hWnd, newText, lpCaption, uType);
}

int main()
{
    // Attach the detour
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_MessageBoxW, MyMessageBoxW);
    DetourTransactionCommit();

    // Test: This call will go through our hook
    MessageBoxW(NULL, L"Hello, World!", L"Detours Example", MB_OK);

    // Detach the hook before exit
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_MessageBoxW, MyMessageBoxW);
    DetourTransactionCommit();

    return 0;
}