#pragma once

// Version information
#define SWIFTHOOK_VERSION_MAJOR 1
#define SWIFTHOOK_VERSION_MINOR 0
#define SWIFTHOOK_VERSION_PATCH 0

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
#define SWIFTHOOK_WINDOWS 1
#define SWIFTHOOK_LINUX 0
#define SWIFTHOOK_MACOS 0
#elif defined(__linux__)
#define SWIFTHOOK_WINDOWS 0
#define SWIFTHOOK_LINUX 1
#define SWIFTHOOK_MACOS 0
#elif defined(__APPLE__)
#define SWIFTHOOK_WINDOWS 0
#define SWIFTHOOK_LINUX 0
#define SWIFTHOOK_MACOS 1
#else
#error "Unsupported platform"
#endif

// Architecture detection
#if defined(_M_X64) || defined(__x86_64__)
#define SWIFTHOOK_X64 1
#define SWIFTHOOK_X86 0
#elif defined(_M_IX86) || defined(__i386__)
#define SWIFTHOOK_X64 0
#define SWIFTHOOK_X86 1
#else
#define SWIFTHOOK_X64 0
#define SWIFTHOOK_X86 0
#endif

// Compiler detection
#if defined(_MSC_VER)
#define SWIFTHOOK_MSVC 1
#define SWIFTHOOK_GCC 0
#define SWIFTHOOK_CLANG 0
#elif defined(__clang__)
#define SWIFTHOOK_MSVC 0
#define SWIFTHOOK_GCC 0
#define SWIFTHOOK_CLANG 1
#elif defined(__GNUC__)
#define SWIFTHOOK_MSVC 0
#define SWIFTHOOK_GCC 1
#define SWIFTHOOK_CLANG 0
#endif

// Configuration options
#ifndef SWIFTHOOK_THREAD_SAFE
#define SWIFTHOOK_THREAD_SAFE 1
#endif

#ifndef SWIFTHOOK_MAX_HOOKS
#define SWIFTHOOK_MAX_HOOKS 1024
#endif

// Memory allocation alignment
#ifndef SWIFTHOOK_MEMORY_ALIGNMENT
#define SWIFTHOOK_MEMORY_ALIGNMENT 16
#endif

// Maximum function size to analyze (in bytes)
#ifndef SWIFTHOOK_MAX_FUNCTION_SIZE
#define SWIFTHOOK_MAX_FUNCTION_SIZE 256
#endif

// Debug options
#ifdef _DEBUG
#define SWIFTHOOK_DEBUG 1
#else
#define SWIFTHOOK_DEBUG 0
#endif

// Utility macros
#define SWIFTHOOK_UNUSED(x) (void)(x)

#if SWIFTHOOK_MSVC
#define SWIFTHOOK_FORCEINLINE __forceinline
#define SWIFTHOOK_NOINLINE __declspec(noinline)
#elif SWIFTHOOK_GCC || SWIFTHOOK_CLANG
#define SWIFTHOOK_FORCEINLINE __attribute__((always_inline)) inline
#define SWIFTHOOK_NOINLINE __attribute__((noinline))
#else
#define SWIFTHOOK_FORCEINLINE inline
#define SWIFTHOOK_NOINLINE
#endif