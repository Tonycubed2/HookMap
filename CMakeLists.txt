cmake_minimum_required(VERSION 3.21)

project(HookMap VERSION 1.4.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT so the exe runs on any PC without the VC++ redistributable (users can run it too).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Zydis (MIT) decodes the instructions each patch touches. Downloaded from GitHub on first configure.
include(FetchContent)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)
FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.1
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(zydis)

add_executable(HookMap
    src/main.cpp
    src/Common.cpp
    src/PEImage.cpp
    src/Process.cpp
    src/Disasm.cpp
    src/AddressLib.cpp
    src/Analyzer.cpp
    src/Report.cpp
    src/Json.cpp
    src/SteamStub.cpp
    src/Health.cpp
)

target_compile_definitions(HookMap PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS PSAPI_VERSION=2)

if(MSVC)
    target_compile_options(HookMap PRIVATE /W4 /utf-8 /permissive- /EHsc /wd4100 /wd4244 /wd4267)
    target_link_options(HookMap PRIVATE /MANIFESTUAC:level='asInvoker')
else()
    target_link_options(HookMap PRIVATE -municode -static)
endif()

target_link_libraries(HookMap PRIVATE Zydis version shell32 advapi32 bcrypt)

# Ship the editable allowlist next to the exe.
add_custom_command(TARGET HookMap POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/allowlist.txt
            $<TARGET_FILE_DIR:HookMap>/allowlist.txt)
