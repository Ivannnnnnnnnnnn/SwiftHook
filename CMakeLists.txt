cmake_minimum_required(VERSION 3.15)

project(SwiftHook 
    VERSION 1.0.0
    DESCRIPTION "Modern C++ API Hooking Library"
    LANGUAGES CXX)

# Disable MSVC Build Insights to prevent hanging
if(MSVC)
    set(CMAKE_VS_GLOBALS "EnableMicrosoftCodeAnalysis=false")
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Library source files (all in src/)
set(SWIFTHOOK_SOURCES
    src/SwiftHook.cpp
    src/Disassembler.cpp
    src/HookManager.cpp
    src/ThreadFreezer.cpp
    src/TrampolineAllocator.cpp
)

set(SWIFTHOOK_HEADERS
    src/SwiftHook.h
    src/Types.h
    src/Config.h
    src/Disassembler.h
    src/HookManager.h
    src/ThreadFreezer.h
    src/TrampolineAllocator.h
)

# Create static library
add_library(SwiftHook STATIC ${SWIFTHOOK_SOURCES} ${SWIFTHOOK_HEADERS})

# Include directories (just src/ since everything is there)
target_include_directories(SwiftHook
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

# Compiler options
if(MSVC)
    target_compile_options(SwiftHook PRIVATE /W4)
else()
    target_compile_options(SwiftHook PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(SwiftHook PRIVATE SWIFTHOOK_WINDOWS=1)
endif()

# Add subdirectories
add_subdirectory(examples)
add_subdirectory(tests)

# Installation rules
install(TARGETS SwiftHook
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES 
    src/SwiftHook.h
    src/Types.h
    src/Config.h
    DESTINATION include/SwiftHook
)