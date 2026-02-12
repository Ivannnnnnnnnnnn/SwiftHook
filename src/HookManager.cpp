#include "HookManager.h"
#include "Disassembler.h"
#include "Config.h"
#include <vector>
#include <shared_mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <limits>

// Platform-specific handling
#if SWIFTHOOK_WINDOWS
// Windows macros conflict with our enum values, temporarily disable them
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

// Restore macros after Windows headers are included
#pragma pop_macro("ERROR_ALREADY_EXISTS")
#pragma pop_macro("ERROR_NOT_FOUND")
#pragma pop_macro("ERROR_INVALID_PARAMETER")
#pragma pop_macro("ERROR_NO_MORE_FILES")
#pragma pop_macro("ERROR_ALREADY_INITIALIZED")
#else
#include <sys/mman.h>
#include <unistd.h>
#if SWIFTHOOK_MACOS
#include <libkern/OSCacheControl.h>
#endif
#endif

namespace SwiftHook
{
    // Result of target validation with detailed error/warning messages
    struct ValidationResult {
        bool canHook;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;

        ValidationResult() : canHook(true) {}
    };

    struct HookManager::Impl
    {
        std::vector<HookEntry> hooks;      // All managed hooks
        TrampolineAllocator allocator;     // Trampoline memory allocator
        ThreadFreezer freezer;             // Thread suspension for safe hooking
        mutable std::shared_mutex hooksMutex; // Reader/writer lock for hook list
        std::atomic<bool> initialized;     // Thread-safe initialization flag

        Impl() : initialized(false) {}
    };

    HookManager::HookManager()
        : pImpl(std::make_unique<Impl>())
    {
    }

    HookManager::~HookManager()
    {
        if (pImpl->initialized.load(std::memory_order_acquire))
        {
            Uninitialize();
        }
    }

    namespace {
        // Cross-platform instruction cache invalidation
        void FlushInstructionCachePortable(void* addr, size_t size) {
#if SWIFTHOOK_WINDOWS
            ::FlushInstructionCache(GetCurrentProcess(), addr, size);
#elif SWIFTHOOK_MACOS
            sys_icache_invalidate(addr, size);
#elif SWIFTHOOK_LINUX
            __builtin___clear_cache(
                static_cast<char*>(addr),
                static_cast<char*>(addr) + size
            );
#else
            SWIFTHOOK_UNUSED(addr);
            SWIFTHOOK_UNUSED(size);
#endif
        }
    }

    // Verify target function can be safely hooked, return warnings/errors
    ValidationResult HookManager::ValidateHookTarget(void* pTarget) {
        ValidationResult result;

        // Must be in executable memory
        if (!IsExecutableAddress(pTarget)) {
            result.errors.push_back("Target address is not in executable memory");
            result.canHook = false;
            return result;
        }

        // Null check
        uintptr_t addr = reinterpret_cast<uintptr_t>(pTarget);
        if (addr == 0) {
            result.errors.push_back("Target address is null");
            result.canHook = false;
            return result;
        }

        // Windows x86 hotpatch prologue detection
#if SWIFTHOOK_WINDOWS && SWIFTHOOK_X86
        uint8_t* bytes = static_cast<uint8_t*>(pTarget);
        if (bytes[0] == 0x8B && bytes[1] == 0xFF) {
            result.warnings.push_back("Function has hotpatch prologue (mov edi, edi)");
        }
#endif

        // Ensure function is long enough to patch
        size_t minRequired = GetMaxHookSize();
        if (!Disassembler::IsHookable(pTarget, minRequired)) {
            result.errors.push_back("Function is too short to hook safely");
            result.canHook = false;
            return result;
        }

        // Detect common problematic patterns
        uint8_t* code = static_cast<uint8_t*>(pTarget);
        if (code[0] == 0xC3 || code[0] == 0xC2) {
            result.warnings.push_back("Function appears to be a stub (immediate return)");
        }

        // May already be hooked
        if (code[0] == 0xE9 || code[0] == 0xEB ||
            (code[0] == 0xFF && (code[1] & 0x38) == 0x20)) {
            result.warnings.push_back("Function starts with a jump (possibly already hooked)");
        }

        return result;
    }

    Status HookManager::Initialize()
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_ALREADY_INITIALIZED;
        }

        pImpl->initialized.store(true, std::memory_order_release);
        return Status::OK;
    }

    Status HookManager::Uninitialize()
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        // Remove all active hooks
        for (auto& hook : pImpl->hooks)
        {
            if (hook.state == HookState::ENABLED)
            {
                UninstallHook(&hook);
            }
        }

        pImpl->hooks.clear();
        pImpl->allocator.FreeAll();
        pImpl->initialized.store(false, std::memory_order_release);

        return Status::OK;
    }

    HookEntry* HookManager::FindHook(void* pTarget)
    {
        for (auto& hook : pImpl->hooks)
        {
            if (hook.pTarget == pTarget)
            {
                return &hook;
            }
        }
        return nullptr;
    }

    const HookEntry* HookManager::FindHook(void* pTarget) const
    {
        for (const auto& hook : pImpl->hooks)
        {
            if (hook.pTarget == pTarget)
            {
                return &hook;
            }
        }
        return nullptr;
    }

    namespace
    {
        // Check if a 32-bit relative jump can reach the target
        bool IsInRelativeJumpRange(void* pFrom, void* pTo)
        {
#if SWIFTHOOK_X64
            intptr_t from = reinterpret_cast<intptr_t>(pFrom);
            intptr_t to = reinterpret_cast<intptr_t>(pTo);
            intptr_t diff = to - (from + 5);
            return (diff >= (std::numeric_limits<int32_t>::min)() &&
                diff <= (std::numeric_limits<int32_t>::max)());
#else
            SWIFTHOOK_UNUSED(pFrom);
            SWIFTHOOK_UNUSED(pTo);
            return true;
#endif
        }
    }

    // Determine optimal jump instruction size based on distance
    size_t HookManager::GetJumpSize(void* pFrom, void* pTo)
    {
#if SWIFTHOOK_X64
        if (IsInRelativeJumpRange(pFrom, pTo))
        {
            return 5;  // Relative jump (E9 xx xx xx xx)
        }
        return 14;     // Absolute indirect jump (FF 25 00 00 00 00 + 8 byte address)
#elif SWIFTHOOK_X86
        SWIFTHOOK_UNUSED(pFrom);
        SWIFTHOOK_UNUSED(pTo);
        return 5;      // Relative jump (E9 xx xx xx xx)
#elif SWIFTHOOK_ARM64
        SWIFTHOOK_UNUSED(pFrom);
        SWIFTHOOK_UNUSED(pTo);
        return 16;     // 4 instructions for far jump (LDR + BR + 8 byte address)
#else
        SWIFTHOOK_UNUSED(pFrom);
        SWIFTHOOK_UNUSED(pTo);
        return 0;
#endif
    }

    // Maximum bytes needed for a hook on current platform
    size_t HookManager::GetMaxHookSize()
    {
#if SWIFTHOOK_X64
        return 14; // Absolute indirect jump
#elif SWIFTHOOK_X86
        return 5;  // Relative jump
#elif SWIFTHOOK_ARM64
        return 16; // Far jump sequence
#else
        return 16;
#endif
    }

    // Write a jump instruction from pFrom to pTo, using specified patch size
    bool HookManager::WriteJump(void* pFrom, void* pTo, size_t patchLength)
    {
        uint8_t* pCode = static_cast<uint8_t*>(pFrom);

#if SWIFTHOOK_X64
        if (patchLength == 5)
        {
            // Relative jump within 2GB
            pCode[0] = 0xE9;
            intptr_t offset = reinterpret_cast<uint8_t*>(pTo) - (pCode + 5);
            *reinterpret_cast<int32_t*>(&pCode[1]) = static_cast<int32_t>(offset);
            return true;
        }

        if (patchLength == 14)
        {
            // Absolute indirect jump via RIP-relative addressing
            pCode[0] = 0xFF;
            pCode[1] = 0x25;
            *reinterpret_cast<uint32_t*>(&pCode[2]) = 0; // RIP + 0
            *reinterpret_cast<uint64_t*>(&pCode[6]) = reinterpret_cast<uint64_t>(pTo);
            return true;
        }

        return false;
#elif SWIFTHOOK_X86
        // x86 always uses relative jump
        if (patchLength != 5)
        {
            return false;
        }
        pCode[0] = 0xE9;
        intptr_t offset = static_cast<uint8_t*>(pTo) - (pCode + 5);
        *reinterpret_cast<int32_t*>(&pCode[1]) = static_cast<int32_t>(offset);
        return true;
#elif SWIFTHOOK_ARM64
        if (patchLength < 16)
        {
            return false;
        }

        uint64_t target = reinterpret_cast<uint64_t>(pTo);
        uint32_t* instr = reinterpret_cast<uint32_t*>(pCode);

        instr[0] = 0x58000050;  // LDR X16, #8 (load literal from PC+8)
        instr[1] = 0xD61F0200;  // BR X16 (branch to X16)
        *reinterpret_cast<uint64_t*>(&instr[2]) = target;

        return true;
#else
        SWIFTHOOK_UNUSED(pCode);
        SWIFTHOOK_UNUSED(pTo);
        SWIFTHOOK_UNUSED(patchLength);
        return false;
#endif
    }

    // Fill memory with architecture-specific NOP instructions
    void HookManager::FillNops(void* pFrom, size_t count)
    {
        if (!pFrom || count == 0)
            return;

#if SWIFTHOOK_X64 || SWIFTHOOK_X86
        std::memset(pFrom, 0x90, count);  // x86/x64 NOP
#elif SWIFTHOOK_ARM64
        uint32_t* instr = static_cast<uint32_t*>(pFrom);
        for (size_t i = 0; i < count / 4; i++)
        {
            instr[i] = 0xD503201F;  // ARM64 NOP
        }
#endif
    }

    // Check if address points to executable memory
    bool HookManager::IsExecutableAddress(void* pTarget)
    {
        if (!pTarget)
        {
            return false;
        }

#if SWIFTHOOK_WINDOWS
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(pTarget, &mbi, sizeof(mbi)))
        {
            return false;
        }

        // Must be committed memory
        if (mbi.State != MEM_COMMIT)
        {
            return false;
        }

        DWORD protect = mbi.Protect;
        if (protect & PAGE_GUARD)
        {
            protect &= ~PAGE_GUARD;
        }

        if (protect & PAGE_NOACCESS)
        {
            return false;
        }

        // Check for execute permissions
        return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
#else
        // Simple read test for Unix
        volatile uint8_t test;
        test = *static_cast<volatile uint8_t*>(pTarget);
        SWIFTHOOK_UNUSED(test);
        return true;
#endif
    }

    // Create trampoline function that executes original code
    void* HookManager::CreateTrampoline(void* pTarget, size_t minLength,
        size_t* pOriginalLength, Status* pStatus)
    {
        if (pStatus)
        {
            *pStatus = Status::ERROR_UNKNOWN;
        }

        // Copy whole instructions to cover minLength
        const uint8_t* src = static_cast<const uint8_t*>(pTarget);
        size_t copiedLength = 0;
        while (copiedLength < minLength)
        {
            size_t instrLen = Disassembler::GetInstructionLength(src + copiedLength);
            if (instrLen == 0 ||
                copiedLength + instrLen > SWIFTHOOK_MAX_FUNCTION_SIZE)
            {
                if (pStatus)
                {
                    *pStatus = Status::ERROR_UNSUPPORTED_FUNCTION;
                }
                return nullptr;
            }
            copiedLength += instrLen;
        }

        if (copiedLength == 0)
        {
            if (pStatus)
            {
                *pStatus = Status::ERROR_UNSUPPORTED_FUNCTION;
            }
            return nullptr;
        }

        // Allocate memory near the target for relative jumps
        size_t trampolineSize = copiedLength + GetMaxHookSize();
        void* pTrampoline = pImpl->allocator.Allocate(pTarget, trampolineSize);

        if (!pTrampoline)
        {
            if (pStatus)
            {
                *pStatus = Status::ERROR_MEMORY_ALLOC;
            }
            return nullptr;
        }

        // Copy and relocate instructions to trampoline
        size_t actualCopied = Disassembler::CopyInstructions(
            pTrampoline, pTarget, minLength, trampolineSize);

        if (actualCopied == 0)
        {
            pImpl->allocator.Free(pTrampoline);
            if (pStatus)
            {
                *pStatus = Status::ERROR_UNSUPPORTED_FUNCTION;
            }
            return nullptr;
        }

        // Add jump back to original function after the copied block
        void* jumpBack = static_cast<uint8_t*>(pTrampoline) + actualCopied;
        void* continueAt = static_cast<uint8_t*>(pTarget) + actualCopied;

        if (!WriteJump(jumpBack, continueAt, GetMaxHookSize()))
        {
            pImpl->allocator.Free(pTrampoline);
            if (pStatus)
            {
                *pStatus = Status::ERROR_UNKNOWN;
            }
            return nullptr;
        }

        // Ensure trampoline code is visible to instruction cache
        FlushInstructionCachePortable(pTrampoline, trampolineSize);

        if (pOriginalLength)
        {
            *pOriginalLength = actualCopied;
        }

        if (pStatus)
        {
            *pStatus = Status::OK;
        }

        return pTrampoline;
    }

    // Write hook jump into target function
    Status HookManager::InstallHook(HookEntry* pHook)
    {
        if (!pHook || !pHook->pTarget || !pHook->pDetour)
        {
            return Status::ERROR_INVALID_PARAMETER;
        }

        // Make memory writable
#if SWIFTHOOK_WINDOWS
        DWORD oldProtect;
        if (!VirtualProtect(pHook->pTarget, pHook->originalLength,
            PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#else
        long pageSize = sysconf(_SC_PAGESIZE);
        uintptr_t addr = reinterpret_cast<uintptr_t>(pHook->pTarget);
        uintptr_t pageStart = addr & ~(pageSize - 1);
        uintptr_t pageEnd = (addr + pHook->originalLength + pageSize - 1) & ~(pageSize - 1);
        size_t protectSize = pageEnd - pageStart;

        if (mprotect(reinterpret_cast<void*>(pageStart), protectSize,
            PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#endif

        // Write the detour jump
        if (!WriteJump(pHook->pTarget, pHook->pDetour, pHook->patchLength))
        {
#if SWIFTHOOK_WINDOWS
            VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
#endif
            return Status::ERROR_UNKNOWN;
        }

        // NOP any leftover bytes
        if (pHook->originalLength > pHook->patchLength)
        {
            void* nopStart = static_cast<uint8_t*>(pHook->pTarget) + pHook->patchLength;
            FillNops(nopStart, pHook->originalLength - pHook->patchLength);
        }

        // Ensure all writes are visible and instruction cache is consistent
        std::atomic_thread_fence(std::memory_order_release);
        FlushInstructionCachePortable(pHook->pTarget, pHook->originalLength);

#if SWIFTHOOK_WINDOWS
        VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
#endif

        pHook->state = HookState::ENABLED;
        return Status::OK;
    }

    // Restore original function bytes
    Status HookManager::UninstallHook(HookEntry* pHook)
    {
        if (!pHook || !pHook->pTarget)
        {
            return Status::ERROR_INVALID_PARAMETER;
        }

        // Make memory writable
#if SWIFTHOOK_WINDOWS
        DWORD oldProtect;
        if (!VirtualProtect(pHook->pTarget, pHook->originalLength,
            PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#else
        long pageSize = sysconf(_SC_PAGESIZE);
        uintptr_t addr = reinterpret_cast<uintptr_t>(pHook->pTarget);
        uintptr_t pageStart = addr & ~(pageSize - 1);
        uintptr_t pageEnd = (addr + pHook->originalLength + pageSize - 1) & ~(pageSize - 1);
        size_t protectSize = pageEnd - pageStart;

        if (mprotect(reinterpret_cast<void*>(pageStart), protectSize,
            PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#endif

        // Restore original bytes
        std::memcpy(pHook->pTarget, pHook->originalBytes.data(), pHook->originalLength);

        // Ensure restore is visible and instruction cache is consistent
        std::atomic_thread_fence(std::memory_order_release);
        FlushInstructionCachePortable(pHook->pTarget, pHook->originalLength);

#if SWIFTHOOK_WINDOWS
        VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
#endif

        pHook->state = HookState::DISABLED;
        return Status::OK;
    }

    // Create a new hook without enabling it
    Status HookManager::CreateHook(void* pTarget, void* pDetour, void** ppOriginal)
    {
        if (!pTarget || !pDetour || !ppOriginal)
        {
            return Status::ERROR_INVALID_PARAMETER;
        }

        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        // Validate target before proceeding
        ValidationResult validation = ValidateHookTarget(pTarget);
        if (!validation.canHook)
        {
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        // Prevent duplicate hooks
        if (FindHook(pTarget))
        {
            return Status::ERROR_ALREADY_CREATED;
        }

        // Determine required patch size
        size_t patchLength = GetJumpSize(pTarget, pDetour);
        if (patchLength == 0)
        {
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        // Final hookability check
        if (!Disassembler::IsHookable(pTarget, patchLength))
        {
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        // Create trampoline with original instructions
        size_t originalLength;
        Status trampolineStatus = Status::ERROR_UNKNOWN;
        void* pTrampoline = CreateTrampoline(pTarget, patchLength,
            &originalLength, &trampolineStatus);

        if (!pTrampoline)
        {
            return (trampolineStatus == Status::OK) ? Status::ERROR_UNKNOWN : trampolineStatus;
        }

        // Initialize hook entry
        HookEntry hook;
        hook.pTarget = pTarget;
        hook.pDetour = pDetour;
        hook.pTrampoline = pTrampoline;
        hook.originalLength = originalLength;
        hook.patchLength = patchLength;
        hook.state = HookState::DISABLED;

        // Save original bytes for restoration
        hook.originalBytes.resize(originalLength);
        std::memcpy(hook.originalBytes.data(), pTarget, originalLength);

        pImpl->hooks.push_back(hook);

        // Return trampoline as original function pointer
        *ppOriginal = pTrampoline;

        return Status::OK;
    }

    // Enable an existing hook
    Status HookManager::EnableHook(void* pTarget)
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry* pHook = FindHook(pTarget);
        if (!pHook)
        {
            return Status::ERROR_NOT_CREATED;
        }

        if (pHook->state == HookState::ENABLED)
        {
            return Status::ERROR_ENABLED;
        }

        // Suspend threads to prevent execution during hook installation
        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        return InstallHook(pHook);
    }

    // Disable an enabled hook
    Status HookManager::DisableHook(void* pTarget)
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry* pHook = FindHook(pTarget);
        if (!pHook)
        {
            return Status::ERROR_NOT_CREATED;
        }

        if (pHook->state == HookState::DISABLED)
        {
            return Status::ERROR_DISABLED;
        }

        // Suspend threads during restoration
        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        return UninstallHook(pHook);
    }

    // Completely remove a hook
    Status HookManager::RemoveHook(void* pTarget)
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry* pHook = FindHook(pTarget);
        if (!pHook)
        {
            return Status::ERROR_NOT_CREATED;
        }

        // Disable if currently enabled
        if (pHook->state == HookState::ENABLED)
        {
            ScopedThreadFreezer freezer(pImpl->freezer);
            if (!freezer.IsValid())
            {
                return Status::ERROR_THREAD_FREEZE;
            }
            UninstallHook(pHook);
        }

        // Free trampoline memory
        pImpl->allocator.Free(pHook->pTrampoline);

        // Remove from list
        pImpl->hooks.erase(
            std::remove_if(pImpl->hooks.begin(), pImpl->hooks.end(),
                [pTarget](const HookEntry& h)
                { return h.pTarget == pTarget; }),
            pImpl->hooks.end());

        return Status::OK;
    }

    // Enable all disabled hooks
    Status HookManager::EnableAllHooks()
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto& hook : pImpl->hooks)
        {
            if (hook.state == HookState::DISABLED)
            {
                InstallHook(&hook);
            }
        }

        return Status::OK;
    }

    // Disable all enabled hooks
    Status HookManager::DisableAllHooks()
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto& hook : pImpl->hooks)
        {
            if (hook.state == HookState::ENABLED)
            {
                UninstallHook(&hook);
            }
        }

        return Status::OK;
    }

    // Remove all hooks
    Status HookManager::RemoveAllHooks()
    {
        std::unique_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        if (!pImpl->initialized.load(std::memory_order_acquire))
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto& hook : pImpl->hooks)
        {
            if (hook.state == HookState::ENABLED)
            {
                UninstallHook(&hook);
            }
            pImpl->allocator.Free(hook.pTrampoline);
        }

        pImpl->hooks.clear();
        return Status::OK;
    }

    // Check if a specific hook is currently enabled
    bool HookManager::IsHookEnabled(void* pTarget) const
    {
        std::shared_lock<std::shared_mutex> lock(pImpl->hooksMutex);

        const HookEntry* pHook = FindHook(pTarget);
        return pHook && pHook->state == HookState::ENABLED;
    }

    // Check manager initialization state
    bool HookManager::IsInitialized() const
    {
        return pImpl->initialized.load(std::memory_order_acquire);
    }

    // Get number of managed hooks
    size_t HookManager::GetHookCount() const
    {
        std::shared_lock<std::shared_mutex> lock(pImpl->hooksMutex);
        return pImpl->hooks.size();
    }

} // namespace SwiftHook