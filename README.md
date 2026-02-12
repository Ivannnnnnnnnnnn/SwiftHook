# SwiftHook

A modern, safe, and efficient C++ API hooking library for Windows (with cross-platform support planned).

## Features

- **Modern C++17** - Uses smart pointers, RAII, and modern patterns
- **Thread-Safe** - Built-in thread synchronization and safe hook installation
- **Type-Safe API** - Template functions for compile-time type checking
- **High Performance** - Minimal overhead and efficient memory management
- **Easy to Use** - Simple, intuitive API inspired by MinHook
- **CMake Build System** - Easy integration into projects

## Supported Platforms

| Platform | Architecture | Status |
|----------|-------------|--------|
| Windows  | x86         | ✅ Supported |
| Windows  | x64         | ✅ Supported |
| Linux    | x64         | ✅ Supported |
| Linux    | ARM64       | ✅ Basic Support |
| macOS    | x64/ARM64   | 🚧 Planned |

## Quick Start

### Building

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### Basic Usage

```cpp
#include "SwiftHook/SwiftHook.h"

// Original function pointer
using MessageBoxA_t = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t pOriginalMessageBoxA = nullptr;

// Your detour function
int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Do something before
    printf("MessageBox called: %s\n", lpCaption);
    
    // Call original
    return pOriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
}

int main() {
    // Initialize SwiftHook
    SwiftHook::Initialize();
    
    // Create and enable hook
    SwiftHook::CreateHookT(&MessageBoxA, &MyMessageBoxA, &pOriginalMessageBoxA);
    SwiftHook::EnableHook(&MessageBoxA);
    
    // MessageBoxA is now hooked!
    MessageBoxA(NULL, "Test", "Test", MB_OK);
    
    // Cleanup
    SwiftHook::Uninitialize();
    
    return 0;
}
```

## API Reference

### Initialization

```cpp
Status Initialize();        // Initialize the library
Status Uninitialize();      // Cleanup and remove all hooks
```

### Hook Management

```cpp
// Create a hook
Status CreateHook(void* pTarget, void* pDetour, void** ppOriginal);

// Type-safe version (recommended)
template<typename T>
Status CreateHookT(T pTarget, T pDetour, T* ppOriginal);

// Enable/Disable hooks
Status EnableHook(void* pTarget);
Status DisableHook(void* pTarget);
Status RemoveHook(void* pTarget);

// Batch operations
Status EnableAllHooks();
Status DisableAllHooks();
Status RemoveAllHooks();

// Query
bool IsHookEnabled(void* pTarget);
```

### Status Codes

```cpp
enum class Status {
    OK,
    ERROR_ALREADY_INITIALIZED,
    ERROR_NOT_INITIALIZED,
    ERROR_ALREADY_CREATED,
    ERROR_NOT_CREATED,
    ERROR_ENABLED,
    ERROR_DISABLED,
    ERROR_NOT_EXECUTABLE,
    ERROR_UNSUPPORTED_FUNCTION,
    ERROR_MEMORY_ALLOC,
    ERROR_MEMORY_PROTECT,
    ERROR_INVALID_PARAMETER,
    ERROR_THREAD_FREEZE,
    ERROR_UNKNOWN
};
```

## Examples

See the `examples/` directory for complete examples:
- **SimpleHook.cpp** - Basic MessageBoxA hooking example
- **FunctionInterception.cpp** - Multiple function hooks with modification

## Testing

Build and run the tests:

```bash
cd build
./bin/BasicTests
./bin/TestHooks
```

## Architecture

SwiftHook consists of several key components:

1. **HookManager** - Manages all hooks and their lifecycle
2. **TrampolineAllocator** - Allocates memory for trampolines near target functions
3. **ThreadFreezer** - Safely suspends threads during hook installation
4. **Disassembler** - Length disassembler for safely copying instructions

## Comparison with MinHook

| Feature | SwiftHook | MinHook |
|---------|-----------|---------|
| C++ Standard | C++17 | C |
| API Style | Modern C++, Templates | C-style |
| Memory Management | RAII, Smart Pointers | Manual |
| Thread Safety | Built-in mutexes | Manual |
| Error Handling | Enum class with descriptions | Error codes |
| Cross-platform | Planned | Windows only |

## Safety Considerations

SwiftHook is designed for **legitimate use cases** such as:
- Debugging and diagnostics
- Performance profiling
- Testing and mocking
- Game modding (with permission)
- Application extension

**Important**: Always ensure you have the right to hook the target application.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Acknowledgments

- Inspired by [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu
- Uses principles from Hacker Disassembler Engine for instruction length detection

## Roadmap

- [ ] Linux support (x64)
- [ ] macOS support
- [ ] ARM/ARM64 support
- [ ] Better instruction relocation
- [ ] Python bindings
- [ ] More comprehensive test suite

- [ ] Detailed documentation
