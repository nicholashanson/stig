cmake_minimum_required(VERSION 3.16)
project(stig_x86_parser)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Sources shared by both executables ----
set(LIB_SOURCES
    src/x86.cpp
    src/x86.hpp
)

include_directories(src include)

# ---- FTXUI ----
find_package(ftxui REQUIRED)

# ------------------------------------------
# 1. TEST EXECUTABLE (no FTXUI)
# ------------------------------------------
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
    test/test_x86/test_execute_pop.cpp
    test/test_x86/test_execute_shr.cpp
    test/test_x86/test_execute_sar.cpp
    test/test_x86/test_execute_ret.cpp
    test/test_x86/test_execute_lea.cpp
    test/test_x86/test_execute_jne.cpp
    test/test_x86/test_execute_je.cpp
    test/test_x86/test_execute_add.cpp
    test/test_x86/test_convert_to_program.cpp
    test/test_x86/test_get_empty_line_offset.cpp
    test/test_x86/test_get_function_name_line_no.cpp
    test/test_x86/test_get_function_str.cpp
    test/test_x86/test_extract_function.cpp
    test/test_x86/test_extract_function_names.cpp
    test/test_x86/test_get_elf_header.cpp
    test/test_x86/test_parse_elf64_shdr.cpp
    test/test_x86/test_get_immediate.cpp
    src/x86.cpp        # shared source
)

target_link_libraries(test_x86
    "${CMAKE_SOURCE_DIR}/lib/libgtest.a"
    "${CMAKE_SOURCE_DIR}/lib/libgtest_main.a"
    pthread
)

# ------------------------------------------
# 2. FTXUI APPLICATION EXECUTABLE
# ------------------------------------------
add_executable(cpu_tui
    src/cpu_ui.cpp      # your new TUI implementation
    src/x86.cpp         # shared source
)

target_link_libraries(cpu_tui
    ftxui::screen
    ftxui::dom
    ftxui::component
)

