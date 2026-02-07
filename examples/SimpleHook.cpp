#include "../src/SwiftHook.h"
#include <iostream>
#include <Windows.h>

// Original MessageBoxA function pointer
using MessageBoxA_t = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t pOriginalMessageBoxA = nullptr;

// Our detour function
int WINAPI DetourMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "MessageBoxA hooked!" << std::endl;
    std::cout << "Original caption: " << (lpCaption ? lpCaption : "NULL") << std::endl;
    std::cout << "Original text: " << (lpText ? lpText : "NULL") << std::endl;

    // Modify the message
    return pOriginalMessageBoxA(hWnd,
        "This message was intercepted by SwiftHook!",
        "SwiftHook Example",
        uType);
}

int main() {
    std::cout << "SwiftHook - Simple Example" << std::endl;
    std::cout << "===========================" << std::endl;

    // Initialize SwiftHook
    SwiftHook::Status status = SwiftHook::Initialize();
    if (status != SwiftHook::Status::OK) {
        std::cerr << "Failed to initialize: " << SwiftHook::GetStatusString(status) << std::endl;
        return 1;
    }

    std::cout << "SwiftHook initialized successfully" << std::endl;

    // Get address of MessageBoxA
    void* pTarget = reinterpret_cast<void*>(&MessageBoxA);

    // Create hook
    status = SwiftHook::CreateHookT(
        &MessageBoxA,
        &DetourMessageBoxA,
        &pOriginalMessageBoxA
    );

    if (status != SwiftHook::Status::OK) {
        std::cerr << "Failed to create hook: " << SwiftHook::GetStatusString(status) << std::endl;
        SwiftHook::Uninitialize();
        return 1;
    }

    std::cout << "Hook created successfully" << std::endl;

    // Enable the hook
    status = SwiftHook::EnableHook(pTarget);
    if (status != SwiftHook::Status::OK) {
        std::cerr << "Failed to enable hook: " << SwiftHook::GetStatusString(status) << std::endl;
        SwiftHook::Uninitialize();
        return 1;
    }

    std::cout << "Hook enabled" << std::endl;
    std::cout << std::endl;

    // Test the hook
    std::cout << "Calling MessageBoxA (should be hooked)..." << std::endl;
    MessageBoxA(NULL, "Original Message", "Original Caption", MB_OK);

    // Disable the hook
    std::cout << std::endl << "Disabling hook..." << std::endl;
    SwiftHook::DisableHook(pTarget);

    // Test without hook
    std::cout << "Calling MessageBoxA (should NOT be hooked)..." << std::endl;
    MessageBoxA(NULL, "This should appear as-is", "Unhooked", MB_OK);

    // Cleanup
    SwiftHook::Uninitialize();
    std::cout << std::endl << "Cleanup complete" << std::endl;

    return 0;
}