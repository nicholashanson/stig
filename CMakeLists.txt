cmake_minimum_required(VERSION 3.16)
project(stig_x86_parser)

# Use C++17
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files for the library
set(LIB_SOURCES
    src/x86.cpp
    src/x86.hpp
)

# Include directories
include_directories(src include)

# Add the test executable
add_executable(test_x86
    test/test_x86/test_parse_x86_instruction.cpp
    test/test_x86/test_parse_address.cpp
    test/test_x86/test_extract_machine_bytes.cpp
    test/test_x86/test_split_token.cpp
    test/test_x86/test_parse_displacement.cpp
    test/test_x86/test_get_memory.cpp
    test/test_x86/test_parse_function.cpp
    test/test_x86/test_execute_xor.cpp
    test/test_x86/test_execute_mov.cpp
    test/test_x86/test_execute_cmp.cpp
    test/test_x86/test_execute_push.cpp
    src/x86.cpp
)

# Link test executable with library source and GTest
target_link_libraries(test_x86
    "${CMAKE_SOURCE_DIR}/lib/libgtest.a"
    "${CMAKE_SOURCE_DIR}/lib/libgtest_main.a"
    pthread   # required by GTest
)