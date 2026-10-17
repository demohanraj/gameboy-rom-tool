cmake_minimum_required(VERSION 3.20)

project(tool VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

option(TOOL_BUILD_TESTS "Build the unit tests" ${BUILD_TESTING})
option(TOOL_FETCH_GTEST "Fetch GoogleTest when it is not installed" ON)
option(TOOL_BUILD_GUI "Build the optional Windows desktop GUI demo" ON)

add_library(tool_core
    src/analysis/CodeDataAnalyzer.cpp
    src/analysis/ControlFlowGraph.cpp
    src/analysis/CrossReferences.cpp
    src/analysis/FunctionDiscovery.cpp
    src/analysis/MemoryDataAnalyzer.cpp
    src/cli/Cli.cpp
    src/cpu/Instruction.cpp
    src/cpu/OpcodeTable.cpp
    src/cpu/SM83.cpp
    src/core/Logger.cpp
    src/disasm/Disassembler.cpp
    src/rom/Cartridge.cpp
    src/rom/Rom.cpp
    src/rom/RomBank.cpp
    src/rom/RomHeader.cpp
    src/memory/MemoryMap.cpp
    src/ir/IR.cpp
)
add_library(tool::core ALIAS tool_core)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated/include/tool")

target_compile_features(tool_core PUBLIC cxx_std_20)
target_include_directories(tool_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
        $<INSTALL_INTERFACE:include>
)

configure_file(
    include/tool/version.h.in
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/tool/version.h"
    @ONLY
)

if(MSVC)
    target_compile_options(tool_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(tool_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
endif()

add_executable(tool src/main.cpp)
target_link_libraries(tool PRIVATE tool::core)

if(WIN32 AND TOOL_BUILD_GUI)
    add_executable(tool-gui WIN32 src/gui/WindowsGui.cpp)
    target_link_libraries(tool-gui PRIVATE tool::core comctl32 comdlg32)
    target_compile_features(tool-gui PRIVATE cxx_std_20)
    target_compile_definitions(tool-gui PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(tool-gui PRIVATE /W4 /permissive-)
    else()
        target_compile_options(tool-gui PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
    endif()
endif()

if(MSVC)
    target_compile_options(tool PRIVATE /W4 /permissive-)
else()
    target_compile_options(tool PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
endif()

if(TOOL_BUILD_TESTS)
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        if(NOT TOOL_FETCH_GTEST)
            message(FATAL_ERROR
                "GoogleTest was not found. Install it, or leave TOOL_FETCH_GTEST=ON to fetch it."
            )
        endif()

        include(FetchContent)
        set(gtest_force_shared_crt ON CACHE BOOL "Use the shared MSVC runtime for GoogleTest")
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip
        )
        FetchContent_MakeAvailable(googletest)
    endif()

    add_executable(tool_tests
        tests/analysis/CodeDataAnalyzerTests.cpp
        tests/analysis/ControlFlowGraphTests.cpp
        tests/analysis/CrossReferencesTests.cpp
        tests/analysis/FunctionDiscoveryTests.cpp
        tests/analysis/MemoryDataAnalyzerTests.cpp
        tests/cli/CliTests.cpp
        tests/core/LoggerTests.cpp
        tests/cpu/SM83Tests.cpp
        tests/disasm/DisassemblerTests.cpp
        tests/rom/RomTests.cpp
        tests/memory/MemoryMapTests.cpp
        tests/ir/IRTests.cpp
    )
    target_link_libraries(tool_tests PRIVATE tool::core GTest::gtest_main)
    target_compile_features(tool_tests PRIVATE cxx_std_20)
    target_include_directories(tool_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")

    if(MSVC)
        target_compile_options(tool_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(tool_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
    endif()

    include(GoogleTest)
    gtest_discover_tests(tool_tests)
endif()

install(TARGETS tool tool_core
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
if(TARGET tool-gui)
    install(TARGETS tool-gui RUNTIME DESTINATION bin)
endif()
install(DIRECTORY include/tool DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/include/tool/version.h" DESTINATION include/tool)
