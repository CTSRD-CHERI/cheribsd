cmake_minimum_required(VERSION 3.8)
project(CheriBSD LANGUAGES C CXX)


set(TARGET "" CACHE STRING "Target machine.")
set(TARGET_ARCH "" CACHE STRING "Target machine arch.")

if (NOT TARGET)
    message(FATAL_ERROR "TARGET must be set!")
endif()
if (NOT TARGET_ARCH)
    message(FATAL_ERROR "TARGET_ARCH must be set!")
endif()

set(MACHINE_HEADERS "${CMAKE_SOURCE_DIR}/sys/${TARGET}/include")

if("${TARGET}" STREQUAL "mips")
    if("${TARGET_ARCH}" STREQUAL "mips64")
        add_compile_options(-mabi=n64)
        set(CLANG_TRIPLE mips64-unknown-freebsd12)
    else()
        message(FATAL_ERROR "Unsupported MIPS TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
else()
    message(FATAL_ERROR "Unsupported TARGET: ${TARGET}:${TARGET_ARCH}!")
endif()

link_libraries(--target=${CLANG_TRIPLE})
add_compile_options(-target ${CLANG_TRIPLE})


# TODO: also copy this to tmpsysroot
include_directories(${CMAKE_SOURCE_DIR}/include)

set(TMPSYSROOT ${CMAKE_BINARY_DIR}/sysroot/usr)
file(MAKE_DIRECTORY ${TMPSYSROOT}/include/c++)
add_compile_options(--sysroot=${CMAKE_BINARY_DIR}/sysroot/)

# Ensure that we can find the clang builtin headers
add_compile_options(-nobuiltininc)
execute_process(COMMAND ${CMAKE_C_COMPILER} -print-resource-dir OUTPUT_VARIABLE BUILTIN_HEADERS_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "BUILTIN_HEADERS_DIR=${BUILTIN_HEADERS_DIR}")
add_compile_options(-idirafter ${BUILTIN_HEADERS_DIR}/include)

# Create symlinks
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${MACHINE_HEADERS} ${TMPSYSROOT}/include/machine)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys/errno.h ${TMPSYSROOT}/include/errno.h)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys/fcntl.h ${TMPSYSROOT}/include/fcntl.h)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys/_stdarg.h ${TMPSYSROOT}/include/stdarg.h)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys ${TMPSYSROOT}/include/sys)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/cheri ${TMPSYSROOT}/include/cheri)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/bsm ${TMPSYSROOT}/include/bsm)
# TODO: should only be for CHERI
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/contrib/cheri-libc++/include ${TMPSYSROOT}/include/c++/v1)


add_subdirectory(libexec/rtld-cheri-elf)
