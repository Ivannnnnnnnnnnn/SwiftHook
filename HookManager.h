#pragma once

#include "Types.h"
#include "TrampolineAllocator.h"
#include "ThreadFreezer.h"
#include <cstdint>
#include <memory>
#include <vector>
#include <string>

namespace SwiftHook {

    enum class Status;
    enum class HookState;

    struct ValidationResult;

    /**
     * @brief Hook information structure
     */
    struct HookEntry {
        void* pTarget;           // Original function address
        void* pDetour;           // Detour function address
        void* pTrampoline;       // Trampoline (original code + jump)
        std::vector<uint8_t> originalBytes; // Backup of original bytes
        size_t originalLength;   // Length of original bytes
        size_t patchLength;      // Length of patch written at target
        HookState state;         // Current hook state
    };

    /**
     * @brief Manages all hooks in the system
     */
    class HookManager {
    public:
        HookManager();
        ~HookManager();

        HookManager(const HookManager&) = delete;
        HookManager& operator=(const HookManager&) = delete;

        /**
         * @brief Initialize the hook manager
         */
        Status Initialize();

        /**
         * @brief Uninitialize and remove all hooks
         */
        Status Uninitialize();

        /**
         * @brief Create a new hook
         * @param pTarget Pointer to function to hook
         * @param pDetour Pointer to detour function
         * @param ppOriginal Pointer to receive trampoline address
         * @return Status code
         */
        Status CreateHook(void* pTarget, void* pDetour, void** ppOriginal);

        /**
         * @brief Enable a hook
         */
        Status EnableHook(void* pTarget);

        /**
         * @brief Disable a hook
         */
        Status DisableHook(void* pTarget);

        /**
         * @brief Remove a hook
         */
        Status RemoveHook(void* pTarget);

        /**
         * @brief Enable all hooks
         */
        Status EnableAllHooks();

        /**
         * @brief Disable all hooks
         */
        Status DisableAllHooks();

        /**
         * @brief Remove all hooks
         */
        Status RemoveAllHooks();

        /**
         * @brief Check if a hook is enabled
         */
        bool IsHookEnabled(void* pTarget) const;

        /**
         * @brief Check if initialized
         */
        bool IsInitialized() const;

        /**
         * @brief Get hook count
         */
        size_t GetHookCount() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> pImpl;

        /**
         * @brief Find a hook entry
         */
        HookEntry* FindHook(void* pTarget);
        const HookEntry* FindHook(void* pTarget) const;

        /**
         * @param pTarget Target address to validate
         * @return ValidationResult with errors and warnings
         */
        ValidationResult ValidateHookTarget(void* pTarget);

        /**
         * @brief Install the hook (write jump instruction)
         */
        Status InstallHook(HookEntry* pHook);

        /**
         * @brief Uninstall the hook (restore original bytes)
         */
        Status UninstallHook(HookEntry* pHook);

        /**
         * @brief Create trampoline for original function
         */
        void* CreateTrampoline(void* pTarget, size_t minLength,
            size_t* pOriginalLength, Status* pStatus);

        /**
         * @brief Write jump instruction
         */
        static bool WriteJump(void* pFrom, void* pTo, size_t patchLength);

        /**
         * @brief Get required patch size for a jump from pFrom to pTo
         */
        static size_t GetJumpSize(void* pFrom, void* pTo);

        /**
         * @brief Get maximum hook size for current architecture
         */
        static size_t GetMaxHookSize();

        /**
         * @brief Fill remaining bytes with NOPs
         */
        static void FillNops(void* pFrom, size_t count);

        /**
         * @brief Check if target address is executable
         */
        static bool IsExecutableAddress(void* pTarget);
    };

} // namespace SwiftHook