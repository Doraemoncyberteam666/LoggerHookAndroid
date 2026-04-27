cmake_minimum_required(VERSION 3.22.1)

project(dcthook LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Strip / optimize a bit; keep debug info disabled for release builds (Gradle will
# handle ABI-specific flags).
add_compile_options(
    -Wall
    -Wextra
    -Wno-unused-parameter
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -ffunction-sections
    -fdata-sections
)

add_library(dcthook SHARED nativehook.cpp)

target_link_libraries(dcthook log)
target_link_options(dcthook PRIVATE -Wl,--gc-sections)
