#include "../src/SwiftHook.h"
#include <iostream>
#include <string>

// Target functions to hook
int Add(int a, int b) {
    return a + b;
}

int Multiply(int a, int b) {
    return a * b;
}

std::string GetMessage() {
    return "Original message";
}

// Function pointers for originals
using Add_t = int(*)(int, int);
using Multiply_t = int(*)(int, int);
using GetMessage_t = std::string(*)();

Add_t pOriginalAdd = nullptr;
Multiply_t pOriginalMultiply = nullptr;
GetMessage_t pOriginalGetMessage = nullptr;

// Detour functions
int DetourAdd(int a, int b) {
    std::cout << "  [Hook] Add(" << a << ", " << b << ") called" << std::endl;
    int result = pOriginalAdd(a, b);
    std::cout << "  [Hook] Add result: " << result << std::endl;
    return result;
}

int DetourMultiply(int a, int b) {
    std::cout << "  [Hook] Multiply(" << a << ", " << b << ") called" << std::endl;
    // Let's modify the behavior - multiply by 10
    int result = pOriginalMultiply(a, b) * 10;
    std::cout << "  [Hook] Modified result (x10): " << result << std::endl;
    return result;
}

std::string DetourGetMessage() {
    std::cout << "  [Hook] GetMessage() called" << std::endl;
    return "Message intercepted by SwiftHook!";
}

int main() {
    std::cout << "SwiftHook - Function Interception Example" << std::endl;
    std::cout << "==========================================" << std::endl << std::endl;

    // Initialize
    if (SwiftHook::Initialize() != SwiftHook::Status::OK) {
        std::cerr << "Failed to initialize SwiftHook" << std::endl;
        return 1;
    }

    // Test functions without hooks
    std::cout << "=== Testing WITHOUT hooks ===" << std::endl;
    std::cout << "Add(5, 3) = " << Add(5, 3) << std::endl;
    std::cout << "Multiply(4, 7) = " << Multiply(4, 7) << std::endl;
    std::cout << "GetMessage() = \"" << GetMessage() << "\"" << std::endl;
    std::cout << std::endl;

    // Create hooks
    std::cout << "=== Creating hooks ===" << std::endl;

    SwiftHook::Status status;

    status = SwiftHook::CreateHookT(Add, DetourAdd, &pOriginalAdd);
    if (status != SwiftHook::Status::OK) {
        std::cerr << "Failed to hook Add: " << SwiftHook::GetStatusString(status) << std::endl;
    }
    else {
        std::cout << "Add() hooked successfully" << std::endl;
    }

    status = SwiftHook::CreateHookT(Multiply, DetourMultiply, &pOriginalMultiply);
    if (status != SwiftHook::Status::OK) {
        std::cerr << "Failed to hook Multiply: " << SwiftHook::GetStatusString(status) << std::endl;
    }
    else {
        std::cout << "Multiply() hooked successfully" << std::endl;
    }

    status = SwiftHook::CreateHookT(GetMessage, DetourGetMessage, &pOriginalGetMessage);
    if (status != SwiftHook::Status::OK) {
        std::cerr << "Failed to hook GetMessage: " << SwiftHook::GetStatusString(status) << std::endl;
    }
    else {
        std::cout << "GetMessage() hooked successfully" << std::endl;
    }

    std::cout << std::endl;

    // Enable all hooks
    std::cout << "=== Enabling all hooks ===" << std::endl;
    SwiftHook::EnableAllHooks();
    std::cout << std::endl;

    // Test with hooks enabled
    std::cout << "=== Testing WITH hooks ===" << std::endl;
    std::cout << "Add(5, 3):" << std::endl;
    int addResult = Add(5, 3);
    std::cout << "  Returned: " << addResult << std::endl << std::endl;

    std::cout << "Multiply(4, 7):" << std::endl;
    int mulResult = Multiply(4, 7);
    std::cout << "  Returned: " << mulResult << std::endl << std::endl;

    std::cout << "GetMessage():" << std::endl;
    std::string msg = GetMessage();
    std::cout << "  Returned: \"" << msg << "\"" << std::endl;
    std::cout << std::endl;

    // Disable specific hook
    std::cout << "=== Disabling Add hook ===" << std::endl;
    SwiftHook::DisableHook(reinterpret_cast<void*>(Add));
    std::cout << std::endl;

    std::cout << "=== Testing with Add unhooked ===" << std::endl;
    std::cout << "Add(5, 3) = " << Add(5, 3) << " (should not show hook message)" << std::endl;
    std::cout << "Multiply(4, 7):" << std::endl;
    Multiply(4, 7);
    std::cout << std::endl;

    // Cleanup
    std::cout << "=== Cleaning up ===" << std::endl;
    SwiftHook::Uninitialize();
    std::cout << "SwiftHook uninitialized" << std::endl;

    return 0;
}