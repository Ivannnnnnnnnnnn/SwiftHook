#include "../src/SwiftHook.h"
#include <iostream>
#include <cassert>

void RunTest(const char* testName, bool condition) {
    if (condition) {
        std::cout << "[PASS] " << testName << std::endl;
    }
    else {
        std::cerr << "[FAIL] " << testName << std::endl;
    }
}

int TestFunction(int x) {
    return x * 2;
}

using TestFunc_t = int(*)(int);
TestFunc_t pOriginalTest = nullptr;
int g_detourCalled = 0;

int DetourTest(int x) {
    g_detourCalled++;
    return pOriginalTest(x) + 1;
}

int main() {
    std::cout << "SwiftHook - Basic Tests" << std::endl;
    std::cout << "=======================" << std::endl << std::endl;

    // Test 1: Initialize
    std::cout << "Test 1: Initialize" << std::endl;
    SwiftHook::Status status = SwiftHook::Initialize();
    RunTest("Initialize returns OK", status == SwiftHook::Status::OK);

    // Test 2: Double initialize should fail
    std::cout << "\nTest 2: Double initialize" << std::endl;
    status = SwiftHook::Initialize();
    RunTest("Double initialize returns error",
        status == SwiftHook::Status::ERROR_ALREADY_INITIALIZED);

    // Test 3: Create hook
    std::cout << "\nTest 3: Create hook" << std::endl;
    status = SwiftHook::CreateHookT(TestFunction, DetourTest, &pOriginalTest);
    RunTest("CreateHook returns OK", status == SwiftHook::Status::OK);
    RunTest("Original function pointer set", pOriginalTest != nullptr);

    // Test 4: Create duplicate hook
    std::cout << "\nTest 4: Create duplicate hook" << std::endl;
    TestFunc_t pDummy = nullptr;
    status = SwiftHook::CreateHookT(TestFunction, DetourTest, &pDummy);
    RunTest("Duplicate hook returns error",
        status == SwiftHook::Status::ERROR_ALREADY_CREATED);

    // Test 5: Enable hook
    std::cout << "\nTest 5: Enable hook" << std::endl;
    status = SwiftHook::EnableHook(reinterpret_cast<void*>(TestFunction));
    RunTest("EnableHook returns OK", status == SwiftHook::Status::OK);
    RunTest("Hook is enabled",
        SwiftHook::IsHookEnabled(reinterpret_cast<void*>(TestFunction)));

    // Test 6: Test hooked function
    std::cout << "\nTest 6: Test hooked function" << std::endl;
    g_detourCalled = 0;
    int result = TestFunction(5);
    RunTest("Detour was called", g_detourCalled == 1);
    RunTest("Result is correct (5*2+1=11)", result == 11);

    // Test 7: Disable hook
    std::cout << "\nTest 7: Disable hook" << std::endl;
    status = SwiftHook::DisableHook(reinterpret_cast<void*>(TestFunction));
    RunTest("DisableHook returns OK", status == SwiftHook::Status::OK);
    RunTest("Hook is disabled",
        !SwiftHook::IsHookEnabled(reinterpret_cast<void*>(TestFunction)));

    // Test 8: Test unhooked function
    std::cout << "\nTest 8: Test unhooked function" << std::endl;
    g_detourCalled = 0;
    result = TestFunction(5);
    RunTest("Detour was NOT called", g_detourCalled == 0);
    RunTest("Result is original (5*2=10)", result == 10);

    // Test 9: Re-enable hook
    std::cout << "\nTest 9: Re-enable hook" << std::endl;
    status = SwiftHook::EnableHook(reinterpret_cast<void*>(TestFunction));
    RunTest("Re-enable returns OK", status == SwiftHook::Status::OK);
    g_detourCalled = 0;
    result = TestFunction(5);
    RunTest("Detour called after re-enable", g_detourCalled == 1);

    // Test 10: Remove hook
    std::cout << "\nTest 10: Remove hook" << std::endl;
    status = SwiftHook::RemoveHook(reinterpret_cast<void*>(TestFunction));
    RunTest("RemoveHook returns OK", status == SwiftHook::Status::OK);

    // Test 11: Enable removed hook should fail
    std::cout << "\nTest 11: Enable removed hook" << std::endl;
    status = SwiftHook::EnableHook(reinterpret_cast<void*>(TestFunction));
    RunTest("Enable removed hook returns error",
        status == SwiftHook::Status::ERROR_NOT_CREATED);

    // Test 12: Uninitialize
    std::cout << "\nTest 12: Uninitialize" << std::endl;
    status = SwiftHook::Uninitialize();
    RunTest("Uninitialize returns OK", status == SwiftHook::Status::OK);

    // Test 13: Double uninitialize
    std::cout << "\nTest 13: Double uninitialize" << std::endl;
    status = SwiftHook::Uninitialize();
    RunTest("Double uninitialize returns error",
        status == SwiftHook::Status::ERROR_NOT_INITIALIZED);

    std::cout << "\n=======================" << std::endl;
    std::cout << "Tests completed!" << std::endl;

    return 0;
}