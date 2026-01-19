cmake_minimum_required(VERSION 3.16)
project(cindersentinel LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_executable(cindersentineld
    src/cindersentineld.cpp
)

target_include_directories(cindersentineld PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

target_compile_options(cindersentineld PRIVATE
    ${LIBBPF_CFLAGS_OTHER}
)

target_link_libraries(cindersentineld PRIVATE
    ${LIBBPF_LIBRARIES}
    elf
    z
)
