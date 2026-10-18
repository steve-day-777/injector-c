cmake_minimum_required(VERSION 3.16)
project(linjector_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Shellcode is assembled manually (no external assembler dependency).
add_library(linjector_cpp
    src/injector.cpp
    src/log.cpp
    src/remote_mem.cpp
    src/remote_module.cpp
    src/remote_proc.cpp
    src/shellcode.cpp
    src/utils.cpp
)

# On Android link the system log library for logcat output.
if(ANDROID)
    find_library(ANDROID_LOG_LIB log)
    target_link_libraries(linjector_cpp PUBLIC ${ANDROID_LOG_LIB})
endif()

target_include_directories(linjector_cpp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(linjector-cli src/main.cpp)
target_link_libraries(linjector-cli PRIVATE linjector_cpp)

