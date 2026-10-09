cmake_minimum_required(VERSION 3.21)

project(HookMap VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT so the exe runs on any PC without the VC++ redistributable (users can run it too).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

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
)

target_compile_definitions(HookMap PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS PSAPI_VERSION=2)

if(MSVC)
    target_compile_options(HookMap PRIVATE /W4 /utf-8 /permissive- /EHsc /wd4100 /wd4244 /wd4267)
    target_link_options(HookMap PRIVATE /MANIFESTUAC:level='asInvoker')
else()
    target_link_options(HookMap PRIVATE -municode -static)
endif()

target_link_libraries(HookMap PRIVATE version shell32 advapi32)

# Ship the editable allowlist next to the exe.
add_custom_command(TARGET HookMap POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/allowlist.txt
            $<TARGET_FILE_DIR:HookMap>/allowlist.txt)
