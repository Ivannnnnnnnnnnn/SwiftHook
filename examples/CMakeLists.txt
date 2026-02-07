cmake_minimum_required(VERSION 3.15)

# Simple hook example
add_executable(SimpleHook SimpleHook.cpp)
target_link_libraries(SimpleHook PRIVATE SwiftHook)

# Function interception example
add_executable(FunctionInterception FunctionInterception.cpp)
target_link_libraries(FunctionInterception PRIVATE SwiftHook)

# Set output directory
set_target_properties(SimpleHook FunctionInterception
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)