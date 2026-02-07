#include "../src/SwiftHook.h"
#include <iostream>
#include <string>

// Multiple test functions
int Add(int a, int b) { return a + b; }
int Sub(int a, int b) { return a - b; }
int Mul(int a, int b) { return a * b; }
int Div(int a, int b) { return a / b; }

// Function pointers
using BinaryOp_t = int(*)(int, int);
BinaryOp_t pOrigAdd = nullptr;
BinaryOp_t pOrigSub = nullptr;
BinaryOp_t pOrigMul = nullptr;
BinaryOp_t pOrigDiv = nullptr;

// Tracking
int g_addCalls = 0;
int g_subCalls = 0;
int g_mulCalls = 0;
int g_divCalls = 0;

// Detours
int DetourAdd(int a, int b) {
    g_addCalls++;
    std::cout << "  Add(" << a << ", " << b << ")" << std::endl;
    return pOrigAdd(a, b);
}

int DetourSub(int a, int b) {
    g_subCalls++;
    std::cout << "  Sub(" << a << ", " << b << ")" << std::endl;
    return pOrigSub(a, b);
}

int DetourMul(int a, int b) {
    g_mulCalls++;
    std::cout << "  Mul(" << a << ", " << b << ")" << std::endl;
    return pOrigMul(a, b);
}

int DetourDiv(int a, int b) {
    g_divCalls++;
    std::cout << "  Div(" << a << ", " << b << ")" << std::endl;
    return pOrigDiv(a, b);
}

void ResetCounters() {
    g_addCalls = g_subCalls = g_mulCalls = g_divCalls = 0;
}

int main() {
    std::cout << "SwiftHook - Multiple Hooks Test" << std::endl;
    std::cout << "================================" << std::endl << std::endl;

    // Initialize
    if (SwiftHook::Initialize() != SwiftHook::Status::OK) {
        std::cerr << "Failed to initialize!" << std::endl;
        return 1;
    }

    // Create multiple hooks
    std::cout << "Creating hooks..." << std::endl;
    SwiftHook::CreateHookT(Add, DetourAdd, &pOrigAdd);
    SwiftHook::CreateHookT(Sub, DetourSub, &pOrigSub);
    SwiftHook::CreateHookT(Mul, DetourMul, &pOrigMul);
    SwiftHook::CreateHookT(Div, DetourDiv, &pOrigDiv);
    std::cout << "4 hooks created" << std::endl << std::endl;

    // Enable all
    std::cout << "Enabling all hooks..." << std::endl;
    SwiftHook::EnableAllHooks();
    std::cout << "All hooks enabled" << std::endl << std::endl;

    // Test all functions
    std::cout << "Testing all hooked functions:" << std::endl;
    ResetCounters();

    int r1 = Add(10, 5);
    int r2 = Sub(10, 5);
    int r3 = Mul(10, 5);
    int r4 = Div(10, 5);

    std::cout << "\nResults:" << std::endl;
    std::cout << "  Add(10,5) = " << r1 << " (called " << g_addCalls << " times)" << std::endl;
    std::cout << "  Sub(10,5) = " << r2 << " (called " << g_subCalls << " times)" << std::endl;
    std::cout << "  Mul(10,5) = " << r3 << " (called " << g_mulCalls << " times)" << std::endl;
    std::cout << "  Div(10,5) = " << r4 << " (called " << g_divCalls << " times)" << std::endl;
    std::cout << std::endl;

    // Disable all
    std::cout << "Disabling all hooks..." << std::endl;
    SwiftHook::DisableAllHooks();
    std::cout << std::endl;

    // Test without hooks
    std::cout << "Testing without hooks (should not see detour messages):" << std::endl;
    ResetCounters();

    Add(7, 3);
    Sub(7, 3);
    Mul(7, 3);
    Div(6, 2);

    std::cout << "Call counts: Add=" << g_addCalls
        << ", Sub=" << g_subCalls
        << ", Mul=" << g_mulCalls
        << ", Div=" << g_divCalls << std::endl;
    std::cout << "(All should be 0)" << std::endl << std::endl;

    // Selective enable
    std::cout << "Enabling only Add and Mul..." << std::endl;
    SwiftHook::EnableHook(reinterpret_cast<void*>(Add));
    SwiftHook::EnableHook(reinterpret_cast<void*>(Mul));
    std::cout << std::endl;

    std::cout << "Testing selective hooks:" << std::endl;
    ResetCounters();

    Add(1, 2);
    Sub(1, 2);
    Mul(1, 2);
    Div(4, 2);

    std::cout << "\nCall counts:" << std::endl;
    std::cout << "  Add: " << g_addCalls << " (should be 1)" << std::endl;
    std::cout << "  Sub: " << g_subCalls << " (should be 0)" << std::endl;
    std::cout << "  Mul: " << g_mulCalls << " (should be 1)" << std::endl;
    std::cout << "  Div: " << g_divCalls << " (should be 0)" << std::endl;
    std::cout << std::endl;

    // Remove all
    std::cout << "Removing all hooks..." << std::endl;
    SwiftHook::RemoveAllHooks();
    std::cout << std::endl;

    // Final test
    std::cout << "Final test (no hooks):" << std::endl;
    ResetCounters();
    std::cout << "Add(99, 1) = " << Add(99, 1) << std::endl;
    std::cout << "Detour call count: " << g_addCalls << " (should be 0)" << std::endl;
    std::cout << std::endl;

    // Cleanup
    SwiftHook::Uninitialize();
    std::cout << "Test completed successfully!" << std::endl;

    return 0;
}