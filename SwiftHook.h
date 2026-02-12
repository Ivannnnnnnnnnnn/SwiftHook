#pragma once

#include "Types.h"
#include "Config.h"
#include <cstdint>
#include <memory>
#include <functional>

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

    /**
     * @brief RAII wrapper for automatic hook management
     *
     * Automatically removes hook when object goes out of scope.
     *
     * Example:
     * @code
     * {
     *     ScopedHook hook(&TargetFunc, &DetourFunc, &fpOriginal);
     *     if (hook.IsValid()) {
     *         hook.Enable();
     *         // Hook is active here
     *     }
     *     // Hook automatically removed when scope exits
     * }
     * @endcode
     */
    class ScopedHook {
    public:
        /**
         * @brief Create a scoped hook
         * @param pTarget Target function
         * @param pDetour Detour function
         * @param ppOriginal Pointer to receive trampoline
         * @param autoEnable If true, enable immediately on success
         */
        ScopedHook(void* pTarget, void* pDetour, void** ppOriginal, bool autoEnable = false)
            : target_(pTarget), status_(Status::ERROR_UNKNOWN), enabled_(false) {
            status_ = CreateHook(pTarget, pDetour, ppOriginal);
            if (status_ == Status::OK && autoEnable) {
                Enable();
            }
        }

        /**
         * @brief Template version for type safety
         */
        template<typename T>
        ScopedHook(T pTarget, T pDetour, T* ppOriginal, bool autoEnable = false)
            : ScopedHook(reinterpret_cast<void*>(pTarget),
                reinterpret_cast<void*>(pDetour),
                reinterpret_cast<void**>(ppOriginal),
                autoEnable) {
        }

        ~ScopedHook() {
            if (status_ == Status::OK) {
                RemoveHook(target_);
            }
        }

        ScopedHook(const ScopedHook&) = delete;
        ScopedHook& operator=(const ScopedHook&) = delete;

        ScopedHook(ScopedHook&& other) noexcept
            : target_(other.target_), status_(other.status_), enabled_(other.enabled_) {
            other.status_ = Status::ERROR_UNKNOWN;
        }

        /**
         * @brief Enable the hook
         */
        Status Enable() {
            if (status_ != Status::OK) return status_;
            Status result = EnableHook(target_);
            if (result == Status::OK) {
                enabled_ = true;
            }
            return result;
        }

        /**
         * @brief Disable the hook
         */
        Status Disable() {
            if (status_ != Status::OK) return status_;
            Status result = DisableHook(target_);
            if (result == Status::OK) {
                enabled_ = false;
            }
            return result;
        }

        /**
         * @brief Check if hook was created successfully
         */
        bool IsValid() const { return status_ == Status::OK; }

        /**
         * @brief Check if hook is currently enabled
         */
        bool IsEnabled() const { return enabled_; }

        /**
         * @brief Get creation status
         */
        Status GetStatus() const { return status_; }

    private:
        void* target_;
        Status status_;
        bool enabled_;
    };

    /**
     * @brief Fluent builder interface for hook creation
     *
     * Example:
     * @code
     * HookBuilder()
     *     .Target(&OriginalFunc)
     *     .Detour(&MyDetour)
     *     .Original(&fpOriginal)
     *     .AutoEnable(true)
     *     .Install();
     * @endcode
     */
    class HookBuilder {
    public:
        HookBuilder() : target_(nullptr), detour_(nullptr),
            original_(nullptr), autoEnable_(false) {
        }

        HookBuilder& Target(void* addr) {
            target_ = addr;
            return *this;
        }

        template<typename T>
        HookBuilder& Target(T func) {
            target_ = reinterpret_cast<void*>(func);
            return *this;
        }

        HookBuilder& Detour(void* addr) {
            detour_ = addr;
            return *this;
        }

        template<typename T>
        HookBuilder& Detour(T func) {
            detour_ = reinterpret_cast<void*>(func);
            return *this;
        }

        HookBuilder& Original(void** addr) {
            original_ = addr;
            return *this;
        }

        template<typename T>
        HookBuilder& Original(T* addr) {
            original_ = reinterpret_cast<void**>(addr);
            return *this;
        }

        HookBuilder& AutoEnable(bool enable) {
            autoEnable_ = enable;
            return *this;
        }

        /**
         * @brief Install the hook with configured parameters
         */
        Status Install() {
            if (!target_ || !detour_ || !original_) {
                return Status::ERROR_INVALID_PARAMETER;
            }

            Status status = CreateHook(target_, detour_, original_);
            if (status == Status::OK && autoEnable_) {
                status = EnableHook(target_);
            }
            return status;
        }

        /**
         * @brief Create a ScopedHook with configured parameters
         */
        ScopedHook Build() {
            if (!target_ || !detour_ || !original_) {
                return ScopedHook(nullptr, nullptr, nullptr, false);
            }
            return ScopedHook(target_, detour_, original_, autoEnable_);
        }

    private:
        void* target_;
        void* detour_;
        void** original_;
        bool autoEnable_;
    };

    /**
     * @brief Hook guard that enables on construction, disables on destruction
     *
     * Useful for temporarily enabling hooks in a scope.
     *
     * Example:
     * @code
     * CreateHook(&Func, &Detour, &fpOrig);
     * {
     *     HookGuard guard(&Func);
     *     // Hook is enabled in this scope
     * }
     * // Hook is disabled here
     * @endcode
     */
    class HookGuard {
    public:
        explicit HookGuard(void* pTarget)
            : target_(pTarget), wasEnabled_(false) {
            wasEnabled_ = IsHookEnabled(pTarget);
            if (!wasEnabled_) {
                EnableHook(pTarget);
            }
        }

        ~HookGuard() {
            if (!wasEnabled_) {
                DisableHook(target_);
            }
        }

        HookGuard(const HookGuard&) = delete;
        HookGuard& operator=(const HookGuard&) = delete;

    private:
        void* target_;
        bool wasEnabled_;
    };

} // namespace SwiftHook