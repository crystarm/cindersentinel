cmake_minimum_required(VERSION 3.16)
project(cindersentinel LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig QUIET)
if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config not found")
endif()

pkg_check_modules(LIBBPF QUIET libbpf)
if (NOT LIBBPF_FOUND)
  message(FATAL_ERROR "libbpf not found (pkg-config: libbpf)")
endif()

message(STATUS "Found libbpf, version ${LIBBPF_VERSION}")

find_package(OpenSSL REQUIRED)


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

add_executable(cindersentinel
    src/cindersentinel.cpp
    src/policy/cbor.cpp
    src/policy/scheme.cpp
    src/policy/hash.cpp
    src/policy/state_store.cpp
    src/policy/maps_pins.cpp
    src/policy/apply.cpp
)

target_include_directories(cindersentinel PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

target_compile_options(cindersentinel PRIVATE
    ${LIBBPF_CFLAGS_OTHER}
)

target_link_libraries(cindersentinel PRIVATE
    ${LIBBPF_LIBRARIES}
    OpenSSL::Crypto
    elf
    z
)

execute_process(
  COMMAND dpkg-architecture -qDEB_HOST_MULTIARCH
  OUTPUT_VARIABLE DEB_MULTIARCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (NOT DEFINED CLANG OR CLANG STREQUAL "")
  find_program(CLANG NAMES clang clang-19 clang-18 REQUIRED)
endif()


set(BPF_OUTPUT_DIR ${CMAKE_SOURCE_DIR}/build)
set(BPF_TC_OBJ ${BPF_OUTPUT_DIR}/cindersentinel_tc.bpf.o)
set(BPF_XDP_OBJ ${BPF_OUTPUT_DIR}/cindersentinel_xdp.bpf.o)

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

add_custom_command(
  OUTPUT ${BPF_XDP_OBJ}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${BPF_OUTPUT_DIR}
  COMMAND ${CLANG} -O2 -g -target bpf -D__TARGET_ARCH_x86
          -I/usr/include/${DEB_MULTIARCH}
          -I/usr/include
          -c ${CMAKE_SOURCE_DIR}/bpf/cindersentinel_xdp.bpf.c
          -o ${BPF_XDP_OBJ}
  DEPENDS ${CMAKE_SOURCE_DIR}/bpf/cindersentinel_xdp.bpf.c
  VERBATIM
)

add_custom_target(cindersentinel_bpf ALL DEPENDS ${BPF_TC_OBJ} ${BPF_XDP_OBJ})
add_dependencies(cindersentineld cindersentinel_bpf)
