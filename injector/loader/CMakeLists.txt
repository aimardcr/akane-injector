cmake_minimum_required(VERSION 3.4.1)
project(csoloader C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

file(GLOB SOURCES "src/*.c")

add_library(csoloader STATIC ${SOURCES})

target_include_directories(csoloader PUBLIC include)

target_compile_definitions(csoloader PRIVATE
    _FORTIFY_SOURCE=2
    $<$<CONFIG:Debug>:CSOLOADER_DEBUG>
)

target_compile_options(csoloader PRIVATE
    -Wno-int-conversion
    -fstack-protector-strong
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Release>:-O3>
)
