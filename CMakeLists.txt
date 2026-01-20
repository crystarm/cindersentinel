cmake_minimum_required(VERSION 3.16)
project(cindersentinel LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_executable(cindersentineld
    src/cindersentineld.cpp
)

add_executable(cindersentinel
    src/cindersentinel.cpp
)

target_include_directories(cindersentinel PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

target_compile_options(cindersentinel PRIVATE
    ${LIBBPF_CFLAGS_OTHER}
)

target_link_libraries(cindersentinel PRIVATE
    ${LIBBPF_LIBRARIES}
    elf
    z
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

execute_process(
  COMMAND dpkg-architecture -qDEB_HOST_MULTIARCH
  OUTPUT_VARIABLE DEB_MULTIARCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

find_program(CLANG clang REQUIRED)

set(BPF_OUTPUT_DIR ${CMAKE_SOURCE_DIR}/build)
set(BPF_TC_OBJ ${BPF_OUTPUT_DIR}/cindersentinel_tc.bpf.o)

add_custom_command(
  OUTPUT ${BPF_TC_OBJ}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${BPF_OUTPUT_DIR}
  COMMAND ${CLANG} -O2 -g -target bpf -D__TARGET_ARCH_x86
          -I/usr/include/${DEB_MULTIARCH}
          -I/usr/include
          -c ${CMAKE_SOURCE_DIR}/bpf/cindersentinel_tc.bpf.c
          -o ${BPF_TC_OBJ}
  DEPENDS ${CMAKE_SOURCE_DIR}/bpf/cindersentinel_tc.bpf.c
  VERBATIM
)

add_custom_target(cindersentinel_bpf ALL DEPENDS ${BPF_TC_OBJ})
add_dependencies(cindersentineld cindersentinel_bpf)
