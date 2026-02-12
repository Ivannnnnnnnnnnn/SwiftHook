#pragma once

#include <cstdint>

// Undefine Windows macros that conflict with our enum values
#ifdef _WIN32
#ifdef ERROR_UNKNOWN
#undef ERROR_UNKNOWN
#endif
#ifdef ERROR_ALREADY_INITIALIZED
#undef ERROR_ALREADY_INITIALIZED
#endif
#ifdef ERROR_NOT_INITIALIZED
#undef ERROR_NOT_INITIALIZED
#endif
#ifdef ERROR_ALREADY_CREATED
#undef ERROR_ALREADY_CREATED
#endif
#ifdef ERROR_NOT_CREATED
#undef ERROR_NOT_CREATED
#endif
#ifdef ERROR_ENABLED
#undef ERROR_ENABLED
#endif
#ifdef ERROR_DISABLED
#undef ERROR_DISABLED
#endif
#ifdef ERROR_NOT_EXECUTABLE
#undef ERROR_NOT_EXECUTABLE
#endif
#ifdef ERROR_UNSUPPORTED_FUNCTION
#undef ERROR_UNSUPPORTED_FUNCTION
#endif
#ifdef ERROR_MEMORY_ALLOC
#undef ERROR_MEMORY_ALLOC
#endif
#ifdef ERROR_MEMORY_PROTECT
#undef ERROR_MEMORY_PROTECT
#endif
#ifdef ERROR_INVALID_PARAMETER
#undef ERROR_INVALID_PARAMETER
#endif
#ifdef ERROR_THREAD_FREEZE
#undef ERROR_THREAD_FREEZE
#endif
#ifdef ERROR_INSUFFICIENT_BUFFER
#undef ERROR_INSUFFICIENT_BUFFER
#endif
#endif // _WIN32

namespace SwiftHook {

    /**
     * @brief Status codes returned by SwiftHook functions
     */
    enum class Status : int32_t {
        OK = 0,                          // Operation succeeded
        ERROR_ALREADY_INITIALIZED,       // Library already initialized
        ERROR_NOT_INITIALIZED,           // Library not initialized
        ERROR_ALREADY_CREATED,           // Hook already exists for target
        ERROR_NOT_CREATED,               // Hook doesn't exist for target
        ERROR_ENABLED,                   // Hook is already enabled
        ERROR_DISABLED,                  // Hook is already disabled
        ERROR_NOT_EXECUTABLE,            // Target is not executable memory
        ERROR_UNSUPPORTED_FUNCTION,      // Function cannot be hooked (too short, etc.)
        ERROR_MEMORY_ALLOC,              // Failed to allocate memory
        ERROR_MEMORY_PROTECT,            // Failed to change memory protection
        ERROR_INVALID_PARAMETER,         // Invalid parameter provided
        ERROR_THREAD_FREEZE,             // Failed to freeze threads
        ERROR_INSUFFICIENT_BUFFER,       // Buffer too small for operation
        ERROR_UNKNOWN                    // Unknown error occurred
    };

    /**
     * @brief Architecture type
     */
    enum class Architecture {
        X86,
        X64,
        ARM,
        ARM64
    };

    /**
     * @brief Hook state
     */
    enum class HookState {
        DISABLED,
        ENABLED,
        REMOVED
    };

    /**
     * @brief Get current architecture
     */
    inline Architecture GetArchitecture() {
#if defined(_M_X64) || defined(__x86_64__)
        return Architecture::X64;
#elif defined(_M_IX86) || defined(__i386__)
        return Architecture::X86;
#elif defined(_M_ARM64) || defined(__aarch64__)
        return Architecture::ARM64;
#elif defined(_M_ARM) || defined(__arm__)
        return Architecture::ARM;
#else
#error "Unsupported architecture"
#endif
    }

} // namespace SwiftHook