#include "HookManager.h"
#include "Disassembler.h"
#include "Config.h"
#include <vector>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <limits>

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

namespace SwiftHook
{

    struct HookManager::Impl
    {
        std::vector<HookEntry> hooks;
        TrampolineAllocator allocator;
        ThreadFreezer freezer;
        std::mutex mutex;
        bool initialized;

        Impl() : initialized(false) {}
    };

    HookManager::HookManager()
        : pImpl(std::make_unique<Impl>())
    {
    }

    HookManager::~HookManager()
    {
        if (pImpl->initialized)
        {
            Uninitialize();
        }
    }

    Status HookManager::Initialize()
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (pImpl->initialized)
        {
            return Status::ERROR_ALREADY_INITIALIZED;
        }

        pImpl->initialized = true;
        return Status::OK;
    }

    Status HookManager::Uninitialize()
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        // Remove all hooks
        for (auto &hook : pImpl->hooks)
        {
            if (hook.state == HookState::ENABLED)
            {
                UninstallHook(&hook);
            }
        }

        pImpl->hooks.clear();
        pImpl->allocator.FreeAll();
        pImpl->initialized = false;

        return Status::OK;
    }

    HookEntry *HookManager::FindHook(void *pTarget)
    {
        for (auto &hook : pImpl->hooks)
        {
            if (hook.pTarget == pTarget)
            {
                return &hook;
            }
        }
        return nullptr;
    }

    const HookEntry *HookManager::FindHook(void *pTarget) const
    {
        for (const auto &hook : pImpl->hooks)
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
        bool IsInRelativeJumpRange(void *pFrom, void *pTo)
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

    size_t HookManager::GetJumpSize(void *pFrom, void *pTo)
    {
#if SWIFTHOOK_X64
        if (IsInRelativeJumpRange(pFrom, pTo))
        {
            return 5;
        }
        return 14;
#elif SWIFTHOOK_X86
        SWIFTHOOK_UNUSED(pFrom);
        SWIFTHOOK_UNUSED(pTo);
        return 5;
#else
        SWIFTHOOK_UNUSED(pFrom);
        SWIFTHOOK_UNUSED(pTo);
        return 0;
#endif
    }

    size_t HookManager::GetMaxHookSize()
    {
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

    bool HookManager::WriteJump(void *pFrom, void *pTo, size_t patchLength)
    {
        uint8_t *pCode = static_cast<uint8_t *>(pFrom);

#if SWIFTHOOK_X64
        if (patchLength == 5)
        {
            // JMP rel32 (E9)
            pCode[0] = 0xE9;
            intptr_t offset = reinterpret_cast<uint8_t *>(pTo) - (pCode + 5);
            *reinterpret_cast<int32_t *>(&pCode[1]) = static_cast<int32_t>(offset);
            return true;
        }

        if (patchLength == 14)
        {
            // JMP [RIP+0] instruction (FF 25 00 00 00 00)
            // followed by 64-bit absolute address
            pCode[0] = 0xFF;
            pCode[1] = 0x25;
            *reinterpret_cast<uint32_t *>(&pCode[2]) = 0; // RIP + 0
            *reinterpret_cast<uint64_t *>(&pCode[6]) = reinterpret_cast<uint64_t>(pTo);
            return true;
        }

        return false;
#elif SWIFTHOOK_X86
        // JMP relative instruction (E9)
        if (patchLength != 5)
        {
            return false;
        }
        pCode[0] = 0xE9;
        intptr_t offset = static_cast<uint8_t *>(pTo) - (pCode + 5);
        *reinterpret_cast<int32_t *>(&pCode[1]) = static_cast<int32_t>(offset);
        return true;
#else
        // ARM/ARM64 - simplified
        // This would need proper instruction encoding
        SWIFTHOOK_UNUSED(pCode);
        SWIFTHOOK_UNUSED(pTo);
        SWIFTHOOK_UNUSED(patchLength);
        return false;
#endif
    }

    void HookManager::FillNops(void *pFrom, size_t count)
    {
        if (!pFrom || count == 0)
            return;

        std::memset(pFrom, 0x90, count);
    }

    bool HookManager::IsExecutableAddress(void *pTarget)
    {
#if SWIFTHOOK_WINDOWS
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(pTarget, &mbi, sizeof(mbi)))
        {
            return false;
        }

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

        return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
#else
        SWIFTHOOK_UNUSED(pTarget);
        return true;
#endif
    }

    void *HookManager::CreateTrampoline(void *pTarget, size_t minLength,
                                        size_t *pOriginalLength, Status *pStatus)
    {
        if (pStatus)
        {
            *pStatus = Status::ERROR_UNKNOWN;
        }

        // Determine how many bytes we need to copy to cover the hook
        const uint8_t *src = static_cast<const uint8_t *>(pTarget);
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

        // Allocate trampoline
        size_t trampolineSize = copiedLength + GetMaxHookSize();
        void *pTrampoline = pImpl->allocator.Allocate(pTarget, trampolineSize);

        if (!pTrampoline)
        {
            if (pStatus)
            {
                *pStatus = Status::ERROR_MEMORY_ALLOC;
            }
            return nullptr;
        }

        // Copy and relocate original instructions to trampoline
        size_t relocatedLength = Disassembler::CopyInstructions(
            pTrampoline, pTarget, copiedLength, copiedLength);
        if (relocatedLength != copiedLength)
        {
            if (pStatus)
            {
                *pStatus = Status::ERROR_UNSUPPORTED_FUNCTION;
            }
            return nullptr;
        }

        // Add jump back to original function (after our hook)
        void *pReturn = static_cast<uint8_t *>(pTarget) + copiedLength;
        void *pJumpLocation = static_cast<uint8_t *>(pTrampoline) + copiedLength;
        size_t jumpSize = GetJumpSize(pJumpLocation, pReturn);
        if (jumpSize == 0 || !WriteJump(pJumpLocation, pReturn, jumpSize))
        {
            if (pStatus)
            {
                *pStatus = Status::ERROR_UNSUPPORTED_FUNCTION;
            }
            return nullptr;
        }

        *pOriginalLength = copiedLength;
        if (pStatus)
        {
            *pStatus = Status::OK;
        }
        return pTrampoline;
    }

    Status HookManager::InstallHook(HookEntry *pHook)
    {
        if (!pHook)
            return Status::ERROR_INVALID_PARAMETER;

#if SWIFTHOOK_WINDOWS
        DWORD oldProtect;
        if (!VirtualProtect(pHook->pTarget, pHook->originalLength,
                            PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#else
        size_t pageSize = sysconf(_SC_PAGESIZE);
        uintptr_t addr = reinterpret_cast<uintptr_t>(pHook->pTarget);
        uintptr_t pageStart = addr & ~(pageSize - 1);
        uintptr_t pageEnd = (addr + pHook->originalLength + pageSize - 1) & ~(pageSize - 1);
        size_t protectSize = pageEnd - pageStart;

        if (mprotect(reinterpret_cast<void *>(pageStart), protectSize,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#endif

        // Write the jump
        if (!WriteJump(pHook->pTarget, pHook->pDetour, pHook->patchLength))
        {
#if SWIFTHOOK_WINDOWS
            VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
#endif
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        if (pHook->originalLength > pHook->patchLength)
        {
            FillNops(static_cast<uint8_t *>(pHook->pTarget) + pHook->patchLength,
                     pHook->originalLength - pHook->patchLength);
        }

#if SWIFTHOOK_WINDOWS
        VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pHook->pTarget, pHook->originalLength);
#else
        __builtin___clear_cache(
            static_cast<char *>(pHook->pTarget),
            static_cast<char *>(pHook->pTarget) + pHook->originalLength);
#endif

        pHook->state = HookState::ENABLED;
        return Status::OK;
    }

    Status HookManager::UninstallHook(HookEntry *pHook)
    {
        if (!pHook)
            return Status::ERROR_INVALID_PARAMETER;

#if SWIFTHOOK_WINDOWS
        DWORD oldProtect;
        if (!VirtualProtect(pHook->pTarget, pHook->originalLength,
                            PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#else
        size_t pageSize = sysconf(_SC_PAGESIZE);
        uintptr_t addr = reinterpret_cast<uintptr_t>(pHook->pTarget);
        uintptr_t pageStart = addr & ~(pageSize - 1);
        uintptr_t pageEnd = (addr + pHook->originalLength + pageSize - 1) & ~(pageSize - 1);
        size_t protectSize = pageEnd - pageStart;

        if (mprotect(reinterpret_cast<void *>(pageStart), protectSize,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            return Status::ERROR_MEMORY_PROTECT;
        }
#endif

        // Restore original bytes
        std::memcpy(pHook->pTarget, pHook->originalBytes.data(), pHook->originalLength);

#if SWIFTHOOK_WINDOWS
        VirtualProtect(pHook->pTarget, pHook->originalLength, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pHook->pTarget, pHook->originalLength);
#else
        __builtin___clear_cache(
            static_cast<char *>(pHook->pTarget),
            static_cast<char *>(pHook->pTarget) + pHook->originalLength);
#endif

        pHook->state = HookState::DISABLED;
        return Status::OK;
    }

    Status HookManager::CreateHook(void *pTarget, void *pDetour, void **ppOriginal)
    {
        if (!pTarget || !pDetour || !ppOriginal)
        {
            return Status::ERROR_INVALID_PARAMETER;
        }

        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        if (!IsExecutableAddress(pTarget))
        {
            return Status::ERROR_NOT_EXECUTABLE;
        }

        // Check if hook already exists
        if (FindHook(pTarget))
        {
            return Status::ERROR_ALREADY_CREATED;
        }

        size_t patchLength = GetJumpSize(pTarget, pDetour);
        if (patchLength == 0)
        {
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        // Check if target is hookable
        if (!Disassembler::IsHookable(pTarget, patchLength))
        {
            return Status::ERROR_UNSUPPORTED_FUNCTION;
        }

        // Create trampoline
        size_t originalLength;
        Status trampolineStatus = Status::ERROR_UNKNOWN;
        void *pTrampoline = CreateTrampoline(pTarget, patchLength,
                                             &originalLength, &trampolineStatus);

        if (!pTrampoline)
        {
            return (trampolineStatus == Status::OK) ? Status::ERROR_UNKNOWN : trampolineStatus;
        }

        // Create hook entry
        HookEntry hook;
        hook.pTarget = pTarget;
        hook.pDetour = pDetour;
        hook.pTrampoline = pTrampoline;
        hook.originalLength = originalLength;
        hook.patchLength = patchLength;
        hook.state = HookState::DISABLED;

        // Backup original bytes
        hook.originalBytes.resize(originalLength);
        std::memcpy(hook.originalBytes.data(), pTarget, originalLength);

        // Add to list
        pImpl->hooks.push_back(hook);

        // Return trampoline as "original" function
        *ppOriginal = pTrampoline;

        return Status::OK;
    }

    Status HookManager::EnableHook(void *pTarget)
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry *pHook = FindHook(pTarget);
        if (!pHook)
        {
            return Status::ERROR_NOT_CREATED;
        }

        if (pHook->state == HookState::ENABLED)
        {
            return Status::ERROR_ENABLED;
        }

        // Freeze threads for safe installation
        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        return InstallHook(pHook);
    }

    Status HookManager::DisableHook(void *pTarget)
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry *pHook = FindHook(pTarget);
        if (!pHook)
        {
            return Status::ERROR_NOT_CREATED;
        }

        if (pHook->state == HookState::DISABLED)
        {
            return Status::ERROR_DISABLED;
        }

        // Freeze threads for safe removal
        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        return UninstallHook(pHook);
    }

    Status HookManager::RemoveHook(void *pTarget)
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        HookEntry *pHook = FindHook(pTarget);
        if (!pHook)
        {
            return Status::ERROR_NOT_CREATED;
        }

        // Disable if enabled
        if (pHook->state == HookState::ENABLED)
        {
            ScopedThreadFreezer freezer(pImpl->freezer);
            if (!freezer.IsValid())
            {
                return Status::ERROR_THREAD_FREEZE;
            }
            UninstallHook(pHook);
        }

        // Free trampoline
        pImpl->allocator.Free(pHook->pTrampoline);

        // Remove from list
        pImpl->hooks.erase(
            std::remove_if(pImpl->hooks.begin(), pImpl->hooks.end(),
                           [pTarget](const HookEntry &h)
                           { return h.pTarget == pTarget; }),
            pImpl->hooks.end());

        return Status::OK;
    }

    Status HookManager::EnableAllHooks()
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto &hook : pImpl->hooks)
        {
            if (hook.state == HookState::DISABLED)
            {
                InstallHook(&hook);
            }
        }

        return Status::OK;
    }

    Status HookManager::DisableAllHooks()
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        for (auto &hook : pImpl->hooks)
        {
            if (hook.state == HookState::ENABLED)
            {
                UninstallHook(&hook);
            }
        }

        return Status::OK;
    }

    Status HookManager::RemoveAllHooks()
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        if (!pImpl->initialized)
        {
            return Status::ERROR_NOT_INITIALIZED;
        }

        ScopedThreadFreezer freezer(pImpl->freezer);
        if (!freezer.IsValid())
        {
            return Status::ERROR_THREAD_FREEZE;
        }

        // Disable all hooks
        for (auto &hook : pImpl->hooks)
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

    bool HookManager::IsHookEnabled(void *pTarget) const
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        const HookEntry *pHook = FindHook(pTarget);
        return pHook && pHook->state == HookState::ENABLED;
    }

    bool HookManager::IsInitialized() const
    {
        return pImpl->initialized;
    }

    size_t HookManager::GetHookCount() const
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex);
        return pImpl->hooks.size();
    }

} // namespace SwiftHook
