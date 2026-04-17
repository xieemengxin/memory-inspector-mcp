cmake_minimum_required(VERSION 3.24)
project(inspector LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "inspector DLL targets Windows — use the MinGW toolchain (toolchain-mingw-w64.cmake).")
endif()

# ---------------------------------------------------------------------------
# Zydis (static, amalgamated).  We build only what we need: Zydis + Zycore.
# ---------------------------------------------------------------------------
set(ZYDIS_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN  OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN      OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)

add_subdirectory(thirdparty/zydis EXCLUDE_FROM_ALL)

# ---------------------------------------------------------------------------
# Inspector DLL
# ---------------------------------------------------------------------------
add_library(inspector SHARED
    src/dllmain.cpp
    src/server.cpp
    src/service.cpp
    src/service_memory.cpp
    src/service_scan.cpp
    src/service_snapshot.cpp
    src/service_watch.cpp
    src/service_dissect.cpp
    src/service_struct.cpp
    src/service_module.cpp
    src/service_disasm.cpp
    src/service_thread.cpp
)

target_include_directories(inspector
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(inspector PRIVATE cxx_std_20)

target_compile_definitions(inspector PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
)

target_link_libraries(inspector PRIVATE
    Zydis
    ws2_32
    psapi
)

if(MSVC)
    target_compile_options(inspector PRIVATE /W4 /permissive- /EHsc /utf-8)
else()
    target_compile_options(inspector PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-function
        -Wno-unused-parameter
        -Wno-unused-but-set-variable
    )
endif()

set_target_properties(inspector PROPERTIES
    OUTPUT_NAME "inspector"
    PREFIX ""
)
