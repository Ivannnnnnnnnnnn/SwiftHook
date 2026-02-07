cmake_minimum_required(VERSION 3.15)

# Basic tests executable
add_executable(BasicTests BasicTests.cpp)
target_link_libraries(BasicTests PRIVATE SwiftHook)

# Test hooks executable
add_executable(TestHooks TestHooks.cpp)
target_link_libraries(TestHooks PRIVATE SwiftHook)

# Set output directory
set_target_properties(BasicTests TestHooks
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)