#pragma once

#include "Types.h"
#include "Config.h"
#include <cstdint>

namespace SwiftHook {

    /**
     * @brief Initialize the SwiftHook library
     * @return Status code
     */
    Status Initialize();

    /**
     * @brief Uninitialize the SwiftHook library and remove all hooks
     * @return Status code
     */
    Status Uninitialize();

    /**
     * @brief Create a hook for a target function
     * @param pTarget Pointer to the target function
     * @param pDetour Pointer to the detour function
     * @param ppOriginal Pointer to receive the trampoline (original function)
     * @return Status code
     */
    Status CreateHook(void* pTarget, void* pDetour, void** ppOriginal);

    /**
     * @brief Create a hook using a template for type safety
     * @tparam T Function pointer type
     * @param pTarget Pointer to the target function
     * @param pDetour Pointer to the detour function
     * @param ppOriginal Pointer to receive the trampoline
     * @return Status code
     */
    template<typename T>
    Status CreateHookT(T pTarget, T pDetour, T* ppOriginal) {
        return CreateHook(
            reinterpret_cast<void*>(pTarget),
            reinterpret_cast<void*>(pDetour),
            reinterpret_cast<void**>(ppOriginal)
        );
    }

    /**
     * @brief Enable a previously created hook
     * @param pTarget Pointer to the target function
     * @return Status code
     */
    Status EnableHook(void* pTarget);

    /**
     * @brief Disable a hook without removing it
     * @param pTarget Pointer to the target function
     * @return Status code
     */
    Status DisableHook(void* pTarget);

    /**
     * @brief Remove a hook completely
     * @param pTarget Pointer to the target function
     * @return Status code
     */
    Status RemoveHook(void* pTarget);

    /**
     * @brief Enable all created hooks
     * @return Status code
     */
    Status EnableAllHooks();

    /**
     * @brief Disable all hooks
     * @return Status code
     */
    Status DisableAllHooks();

    /**
     * @brief Remove all hooks
     * @return Status code
     */
    Status RemoveAllHooks();

    /**
     * @brief Check if a hook exists for the target
     * @param pTarget Pointer to the target function
     * @return true if hook exists, false otherwise
     */
    bool IsHookEnabled(void* pTarget);

    /**
     * @brief Get the status message for a status code
     * @param status Status code
     * @return Human-readable status message
     */
    const char* GetStatusString(Status status);

} // namespace SwiftHook