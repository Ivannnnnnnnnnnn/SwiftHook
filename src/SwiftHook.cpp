#include "SwiftHook.h"
#include "HookManager.h"
#include <memory>

namespace SwiftHook {

    // Global hook manager instance
    static std::unique_ptr<HookManager> g_hookManager;

    Status Initialize() {
        if (g_hookManager) {
            return Status::ERROR_ALREADY_INITIALIZED;
        }

        g_hookManager = std::make_unique<HookManager>();
        return g_hookManager->Initialize();
    }

    Status Uninitialize() {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        Status status = g_hookManager->Uninitialize();
        g_hookManager.reset();
        return status;
    }

    Status CreateHook(void* pTarget, void* pDetour, void** ppOriginal) {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->CreateHook(pTarget, pDetour, ppOriginal);
    }

    Status EnableHook(void* pTarget) {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->EnableHook(pTarget);
    }

    Status DisableHook(void* pTarget) {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->DisableHook(pTarget);
    }

    Status RemoveHook(void* pTarget) {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->RemoveHook(pTarget);
    }

    Status EnableAllHooks() {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->EnableAllHooks();
    }

    Status DisableAllHooks() {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->DisableAllHooks();
    }

    Status RemoveAllHooks() {
        if (!g_hookManager) {
            return Status::ERROR_NOT_INITIALIZED;
        }

        return g_hookManager->RemoveAllHooks();
    }

    bool IsHookEnabled(void* pTarget) {
        if (!g_hookManager) {
            return false;
        }

        return g_hookManager->IsHookEnabled(pTarget);
    }

    const char* GetStatusString(Status status) {
        switch (status) {
        case Status::OK:
            return "Operation succeeded";
        case Status::ERROR_ALREADY_INITIALIZED:
            return "Library already initialized";
        case Status::ERROR_NOT_INITIALIZED:
            return "Library not initialized";
        case Status::ERROR_ALREADY_CREATED:
            return "Hook already exists for target";
        case Status::ERROR_NOT_CREATED:
            return "Hook doesn't exist for target";
        case Status::ERROR_ENABLED:
            return "Hook is already enabled";
        case Status::ERROR_DISABLED:
            return "Hook is already disabled";
        case Status::ERROR_NOT_EXECUTABLE:
            return "Target is not executable memory";
        case Status::ERROR_UNSUPPORTED_FUNCTION:
            return "Function cannot be hooked";
        case Status::ERROR_MEMORY_ALLOC:
            return "Failed to allocate memory";
        case Status::ERROR_MEMORY_PROTECT:
            return "Failed to change memory protection";
        case Status::ERROR_INVALID_PARAMETER:
            return "Invalid parameter provided";
        case Status::ERROR_THREAD_FREEZE:
            return "Failed to freeze threads";
        case Status::ERROR_INSUFFICIENT_BUFFER:
            return "Buffer too small for operation";
        case Status::ERROR_UNKNOWN:
        default:
            return "Unknown error occurred";
        }
    }

} // namespace SwiftHook