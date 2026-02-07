#include "HookManager.h"
#include "Disassembler.h"
#include "Config.h"
#include <vector>
#include <mutex>
#include <algorithm>
#include <cstring>

#if SWIFTHOOK_WINDOWS
// Temporarily disable problematic Windows macros
#pragma push_macro("ERROR_ALREADY_EXISTS")
#pragma push_macro("ERROR_NOT_FOUND")
#pragma push_macro("ERROR_INVALID_PARAMETER")
#pragma push_macro("ERROR_NO_MORE_FILES")
#pragma push_macro("ERROR_ALREADY_INITIALIZED")
#undef ERROR_ALREADY_EXISTS
#undef ERROR_NOT_FOUND
#undef ERROR_INVALID_PARAMETER
#undef ERROR_NO_MORE_FILES
#undef ERROR_ALREADY_INITIALIZED

#include <Windows.h>

// Restore macros
#pragma pop_macro("ERROR_ALREADY_EXISTS")
#pragma pop_macro("ERROR_NOT_FOUND")
#pragma pop_macro("ERROR_INVALID_PARAMETER")
#pragma pop_macro("ERROR_NO_MORE_FILES")
#pragma pop_macro("ERROR_ALREADY_INITIALIZED")
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace SwiftHook {

    struct HookManager::Impl {
        std::vector<HookEntry> hooks;
        TrampolineAllocator allocator;
        ThreadFreezer freezer;
        std::mutex mutex;
        bool initialized;

        Impl() : initialized(false) {}
    };

    HookManager::HookManager()
        : pImpl(std::make_unique<Impl>()) {
    }

    HookManager::~HookManager() {
        if (pImpl->initialized) {
            Uninitialize();
        }
    }

    Status HookManager::Initialize() {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (pImpl->initialized) {
            return Status::ERROR_ALREADY_INITIALIZED;
        }

        pImpl->initialized = true;
        return Status::OK;
    }

    Status HookManager::Uninitialize() {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        // Remove all hooks
        for (auto& hook : pImpl->hooks) {
            if (hook.state == HookState::ENABLED) {
                UninstallHook(&hook);
            }
        }

        pImpl->hooks.clear();
        pImpl->allocator.FreeAll();
        pImpl->initialized = false;

        return Status::OK;
    }

    HookEntry* HookManager::FindHook(void* pTarget) {
        for (auto& hook : pImpl->hooks) {
            if (hook.pTarget == pTarget) {
                return &hook;
            }
        }
        return nullptr;
    }

    const HookEntry* HookManager::FindHook(void* pTarget) const {
        for (const auto& hook : pImpl->hooks) {
            if (hook.pTarget == pTarget) {
                return &hook;
            }
        }
        return nullptr;
    }

    size_t HookManager::GetHookSize() {
#if SWIFTHOOK_X64
        // JMP [RIP+0]; 64-bit address
        return 14; // FF 25 00 00 00 00 + 8 bytes address
#elif SWIFTHOOK_X86
        // JMP immediate
        return 5; // E9 + 4 bytes offset
#else
        // ARM/ARM64
        return 16;
#endif
    }

    void HookManager::WriteJump(void* pFrom, void* pTo) {
        uint8_t* pCode = static_cast<uint8_t*>(pFrom);

#if SWIFTHOOK_X64
        // JMP [RIP+0] instruction (FF 25 00 00 00 00)
        // followed by 64-bit absolute address
        pCode[0] = 0xFF;
        pCode[1] = 0x25;
        *reinterpret_cast<uint32_t*>(&pCode[2]) = 0; // RIP + 0
        *reinterpret_cast<uint64_t*>(&pCode[6]) = reinterpret_cast<uint64_t>(pTo);
#elif SWIFTHOOK_X86
        // JMP relative instruction (E9)
        pCode[0] = 0xE9;
        intptr_t offset = static_cast<uint8_t*>(pTo) - (pCode + 5);
        *reinterpret_cast<int32_t*>(&pCode[1]) = static_cast<int32_t>(offset);
#else
        // ARM/ARM64 - simplified
        // This would need proper instruction encoding
        SWIFTHOOK_UNUSED(pCode);
        SWIFTHOOK_UNUSED(pTo);
#endif
    }

    void* HookManager::CreateTrampoline(void* pTarget, size_t* pOriginalLength) {
        size_t hookSize = GetHookSize();

        // Copy enough instructions to cover the hook
        uint8_t originalCode[64];
        size_t copiedLength = Disassembler::CopyInstructions(
            originalCode, pTarget, hookSize, sizeof(originalCode));

        if (copiedLength == 0) {
            return nullptr;
        }

        // Allocate trampoline
        size_t trampolineSize = copiedLength + GetHookSize();
        void* pTrampoline = pImpl->allocator.Allocate(pTarget, trampolineSize);

        if (!pTrampoline) {
            return nullptr;
        }

        // Copy original instructions to trampoline
        std::memcpy(pTrampoline, originalCode, copiedLength);

        // Add jump back to original function (after our hook)
        void* pReturn = static_cast<uint8_t*>(pTarget) + copiedLength;
        void* pJumpLocation = static_cast<uint8_t*>(pTrampoline) + copiedLength;
        WriteJump(pJumpLocation, pReturn);

        *pOriginalLength = copiedLength;
        return pTrampoline;
    }

    Status HookManager::InstallHook(HookEntry* pHook) {
        if (!pHook) return Status::ERROR_INVALID_PARAMETER;

#if SWIFTHOOK_WINDOWS
        DWORD oldProtect;
        if (!VirtualProtect(pHook->pTarget, GetHookSize(),
            PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return Status::ERROR_MEMORY_PROTECT;
        }
#else
        size_t pageSize = sysconf(_SC_PAGESIZE);
        uintptr_t addr = reinterpret_cast<uintptr_t>(pHook->pTarget);
        void* pageStart = reinterpret_cast<void*>(addr & ~(pageSize - 1));

        if (mprotect(pageStart, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            return Status::ERROR_MEMORY_PROTECT;
        }
#endif

        // Write the jump
        WriteJump(pHook->pTarget, pHook->pDetour);

#if SWIFTHOOK_WINDOWS
        VirtualProtect(pHook->pTarget, GetHookSize(), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pHook->pTarget, GetHookSize());
#else
        __builtin___clear_cache(
            static_cast<char*>(pHook->pTarget),
            static_cast<char*>(pHook->pTarget) + GetHookSize()
        );
#endif

        pHook->state = HookState::ENABLED;
        return Status::OK;
    }

    Status HookManager::UninstallHook(HookEntry* pHook) {
        if (!pHook) return Status::ERROR_INVALID_PARAMETER;

#if SWIFTHOOK_WINDOWS
        DWORD oldProtect;
        if (!VirtualProtect(pHook->pTarget, pHook->originalLength,
            PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return Status::ERROR_MEMORY_PROTECT;
        }
#else
        size_t pageSize = sysconf(_SC_PAGESIZE);
        uintptr_t addr = reinterpret_cast<uintptr_t>(pHook->pTarget);
        void* pageStart = reinterpret_cast<void*>(addr & ~(pageSize - 1));

        if (mprotect(pageStart, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            return Status::ERROR_MEMORY_PROTECT;
        }
#endif

        // Restore original bytes
        std::memcpy(pHook->pTarget, pHook->originalBytes, pHook->originalLength);

#if SWIFTHOOK_WINDOWS
        VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pHook->pTarget, pHook->originalLength);
#else
        __builtin___clear_cache(
            static_cast<char*>(pHook->pTarget),
            static_cast<char*>(pHook->pTarget) + pHook->originalLength
        );
#endif

        pHook->state = HookState::DISABLED;
        return Status::OK;
    }

    Status HookManager::CreateHook(void* pTarget, void* pDetour, void** ppOriginal) {
        if (!pTarget || !pDetour || !ppOriginal) {
            return Status::ERROR_INVALID_PARAMETER;
        }

        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        // Check if hook already exists
        if (FindHook(pTarget)) {
            return Status::ERROR_ALREADY_CREATED;
        }

        // Check if target is hookable
        if (!Disassembler::IsHookable(pTarget, GetHookSize())) {
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        // Create trampoline
        size_t originalLength;
        void* pTrampoline = CreateTrampoline(pTarget, &originalLength);

        if (!pTrampoline) {
            return Status::ERROR_MEMORY_ALLOC;
        }

        // Create hook entry
        HookEntry hook;
        hook.pTarget = pTarget;
        hook.pDetour = pDetour;
        hook.pTrampoline = pTrampoline;
        hook.originalLength = originalLength;
        hook.state = HookState::DISABLED;

        // Backup original bytes
        std::memcpy(hook.originalBytes, pTarget, originalLength);

        // Add to list
        pImpl->hooks.push_back(hook);

        // Return trampoline as "original" function
        *ppOriginal = pTrampoline;

        return Status::OK;
    }

    Status HookManager::EnableHook(void* pTarget) {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry* pHook = FindHook(pTarget);
        if (!pHook) {
            return Status::ERROR_NOT_CREATED;
        }

        if (pHook->state == HookState::ENABLED) {
            return Status::ERROR_ENABLED;
        }

        // Freeze threads for safe installation
        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid()) {
            return Status::ERROR_THREAD_FREEZE;
        }

        return InstallHook(pHook);
    }

    Status HookManager::DisableHook(void* pTarget) {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry* pHook = FindHook(pTarget);
        if (!pHook) {
            return Status::ERROR_NOT_CREATED;
        }

        if (pHook->state == HookState::DISABLED) {
            return Status::ERROR_DISABLED;
        }

        // Freeze threads for safe removal
        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid()) {
            return Status::ERROR_THREAD_FREEZE;
        }

        return UninstallHook(pHook);
    }

    Status HookManager::RemoveHook(void* pTarget) {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry* pHook = FindHook(pTarget);
        if (!pHook) {
            return Status::ERROR_NOT_CREATED;
        }

        // Disable if enabled
        if (pHook->state == HookState::ENABLED) {
            ScopedThreadFreezer freezer(pImpl->freezer);
            if (!freezer.IsValid()) {
                return Status::ERROR_THREAD_FREEZE;
            }
            UninstallHook(pHook);
        }

        // Free trampoline
        pImpl->allocator.Free(pHook->pTrampoline);

        // Remove from list
        pImpl->hooks.erase(
            std::remove_if(pImpl->hooks.begin(), pImpl->hooks.end(),
                [pTarget](const HookEntry& h) { return h.pTarget == pTarget; }),
            pImpl->hooks.end()
        );

        return Status::OK;
    }

    Status HookManager::EnableAllHooks() {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid()) {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto& hook : pImpl->hooks) {
            if (hook.state == HookState::DISABLED) {
                InstallHook(&hook);
            }
        }

        return Status::OK;
    }

    Status HookManager::DisableAllHooks() {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid()) {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto& hook : pImpl->hooks) {
            if (hook.state == HookState::ENABLED) {
                UninstallHook(&hook);
            }
        }

        return Status::OK;
    }

    Status HookManager::RemoveAllHooks() {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid()) {
            return Status::ERROR_THREAD_FREEZE;
        }

        // Disable all hooks
        for (auto& hook : pImpl->hooks) {
            if (hook.state == HookState::ENABLED) {
                UninstallHook(&hook);
            }
            pImpl->allocator.Free(hook.pTrampoline);
        }

        pImpl->hooks.clear();
        return Status::OK;
    }

    bool HookManager::IsHookEnabled(void* pTarget) const {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        const HookEntry* pHook = FindHook(pTarget);
        return pHook && pHook->state == HookState::ENABLED;
    }

    bool HookManager::IsInitialized() const {
        return pImpl->initialized;
    }

    size_t HookManager::GetHookCount() const {
        std::lock_guard<std::mutex> lock(pImpl->mutex);
        return pImpl->hooks.size();
    }

} // namespace SwiftHook