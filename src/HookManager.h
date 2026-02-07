#pragma once

#include "Types.h"
#include "TrampolineAllocator.h"
#include "ThreadFreezer.h"
#include <cstdint>
#include <memory>

namespace SwiftHook {

    enum class Status;
    enum class HookState;

    /**
     * @brief Hook information structure
     */
    struct HookEntry {
        void* pTarget;           // Original function address
        void* pDetour;           // Detour function address
        void* pTrampoline;       // Trampoline (original code + jump)
        uint8_t originalBytes[16]; // Backup of original bytes
        size_t originalLength;   // Length of original bytes
        HookState state;         // Current hook state
    };

    /**
     * @brief Manages all hooks in the system
     */
    class HookManager {
    public:
        HookManager();
        ~HookManager();

        // Non-copyable
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
        void* CreateTrampoline(void* pTarget, size_t* pOriginalLength);

        /**
         * @brief Write jump instruction
         */
        static void WriteJump(void* pFrom, void* pTo);

        /**
         * @brief Get required hook size for current architecture
         */
        static size_t GetHookSize();
    };

} // namespace SwiftHook