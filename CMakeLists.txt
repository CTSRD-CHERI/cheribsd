set(CMAKE_CROSSCOMPILING ON)
set(CMAKE_SYSTEM_NAME FreeBSD)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
cmake_minimum_required(VERSION 3.8)
project(CheriBSD LANGUAGES NONE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TARGET "" CACHE STRING "Target machine.")
set(TARGET_ARCH "" CACHE STRING "Target machine arch.")

if (NOT TARGET)
    message(FATAL_ERROR "TARGET must be set!")
endif()
if (NOT TARGET_ARCH)
    message(FATAL_ERROR "TARGET_ARCH must be set!")
endif()

if("${TARGET}" STREQUAL "mips")
    if("${TARGET_ARCH}" STREQUAL "mips64")
        add_compile_options(-mabi=n64)
        set(CLANG_TRIPLE mips64-unknown-freebsd13)
        add_compile_definitions(__mips__)
        add_compile_definitions(__mips_n64)
    else()
        message(FATAL_ERROR "Unsupported MIPS TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
elseif("${TARGET}" STREQUAL "riscv")
    if("${TARGET_ARCH}" STREQUAL "riscv64")
        add_compile_options(-mabi=lp64)
        set(CLANG_TRIPLE riscv64-unknown-freebsd13)
        add_compile_definitions(__riscv)
        add_compile_definitions(__riscv__)
        add_compile_definitions(__riscv_xlen=64)
    else()
        message(FATAL_ERROR "Unsupported RISC-V TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
elseif("${TARGET}" STREQUAL "amd64")
    if("${TARGET_ARCH}" STREQUAL "amd64")
        set(CLANG_TRIPLE x86_64-unknown-freebsd13)
    else()
        message(FATAL_ERROR "Unsupported x86 TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
else()
    message(FATAL_ERROR "Unsupported TARGET: ${TARGET}:${TARGET_ARCH}!")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/sys)
include_directories(${CMAKE_SOURCE_DIR}/contrib/libxo)
include_directories(${CMAKE_SOURCE_DIR}/contrib/libc-vis)

set(TMPSYSROOT ${CMAKE_BINARY_DIR}/sysroot/usr)
file(MAKE_DIRECTORY ${TMPSYSROOT}/include/)

# Create symlinks
set(MACHINE_HEADERS "${CMAKE_SOURCE_DIR}/sys/${TARGET}/include")
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${MACHINE_HEADERS} ${TMPSYSROOT}/include/machine)
if("${TARGET}" STREQUAL "amd64")
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink "${CMAKE_SOURCE_DIR}/sys/x86/include" ${TMPSYSROOT}/include/x86)
endif()
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys/errno.h ${TMPSYSROOT}/include/errno.h)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys/fcntl.h ${TMPSYSROOT}/include/fcntl.h)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/sys/sys/_stdarg.h ${TMPSYSROOT}/include/stdarg.h)
# TODO: should only be for CHERI
file(MAKE_DIRECTORY ${TMPSYSROOT}/include/c++)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_SOURCE_DIR}/contrib/subrepo-cheri-libc++/include ${TMPSYSROOT}/include/c++/v1)

file(MAKE_DIRECTORY ${TMPSYSROOT}/kern_opt)
file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_ddb.h "#define DDB 1\n")
file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_ktrace.h "#define KTRACE 1\n")
file(WRITE ${CMAKE_BINARY_DIR}/cheri_builtins.h "
// Pretend that we have capabilities in CLion
#ifdef __JETBRAINS_IDE__
#define __CHERI__
#define __has_feature(x) __fake_has_feature_##x
#define __fake_has_feature_capabilities 1
// But we don't really so define __capability to nothing
#define __capability
// And provide the builtins for code completion
long __builtin_cheri_length_get(const void* __capability);
long __builtin_cheri_base_get(const void* __capability);
long __builtin_cheri_offset_get(const void* __capability);
long __builtin_cheri_address_get(const void* __capability);
long __builtin_cheri_flags_get(const void* __capability);
long __builtin_cheri_perms_get(const void* __capability);
long __builtin_cheri_sealed_get(const void* __capability);
long __builtin_cheri_tag_get(const void* __capability);
long __builtin_cheri_type_get(const void* __capability));
void* __capability __builtin_cheri_perms_and(const void* __capability, long);
void* __capability __builtin_cheri_tag_clear(const void* __capability);
void* __capability __builtin_cheri_offset_increment(const void* __capability, long);
void* __capability __builtin_cheri_offset_set(const void* __capability, long);
void* __capability __builtin_cheri_address_set(const void* __capability, long);
void* __capability __builtin_cheri_flags_set(const void* __capability, long);
void* __capability __builtin_cheri_seal(const void* __capability, void* __capability);
void* __capability __builtin_cheri_unseal(const void* __capability, void* __capability);
void __builtin_cheri_perms_check(const void* __capability, long);
void __builtin_cheri_type_check(const void* __capability, const void* __capability);
void* __capability __builtin_cheri_global_data_get(void);
void* __capability __builtin_cheri_program_counter_get(void);
void* __capability __builtin_cheri_stack_get(void);
void* __capability __builtin_cheri_bounds_set(const void* __capability, long);
void* __capability __builtin_cheri_bounds_set_exact(const void* __capability, long);
// Also define some compiler defines:
#define __CHERI_ADDRESS_BITS__ 64
#define __CHERI_CAPABILITY_WIDTH__ 128
#define __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__ 1024
#define __CHERI_CAP_PERMISSION_GLOBAL__ 1
#define __CHERI_CAP_PERMISSION_PERMIT_CCALL__ 256
#define __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__ 2
#define __CHERI_CAP_PERMISSION_PERMIT_LOAD_CAPABILITY__ 16
#define __CHERI_CAP_PERMISSION_PERMIT_LOAD__ 4
#define __CHERI_CAP_PERMISSION_PERMIT_SEAL__ 128
#define __CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ 32
#define __CHERI_CAP_PERMISSION_PERMIT_STORE_LOCAL__ 64
#define __CHERI_CAP_PERMISSION_PERMIT_STORE__ 8
#define __CHERI_CAP_PERMISSION_PERMIT_UNSEAL__ 512
#define __SIZEOF_CHERI_CAPABILITY__ 16
#define __SIZEOF_UINTCAP__ 16
#define __SIZEOF_INTCAP__ 16
#endif /* __JETBRAINS_IDE__ */
")

file(WRITE ${CMAKE_BINARY_DIR}/cheri_purecap.h "
// Pretend that we have capabilities in CLion
#ifdef __JETBRAINS_IDE__
#define __CHERI_PURE_CAPABILITY__ 1
#define __CHERI_CAPABILITY_TABLE__ 3
#include \"cheri_builtins.h\"
#endif
")
add_compile_options(-include ${CMAKE_BINARY_DIR}/cheri_purecap.h)

file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_global.h "
#include \"../cheri_builtins.h\"
#undef __CHERI_PURE_CAPABILITY__
#define KDB 1
// #define COMPAT_FREEBSD11 1
#define COMPAT_FREEBSD32 1
#define COMPAT_FREEBSD64 1
#define CPU_CHERI 1
#define INVARIANT_SUPPORT 1
#define INVARIANTS 1
#define FDT 1
#define CPU_MALTA 1
#define TICK_USE_YAMON_FREQ defined
#define YAMON 1
#define INVARIANTS 1
#define CPU_QEMU_RISCV
// #define MAC 1
// #define AUDIT 1")


set(CMAKE_C_COMPILER_TARGET ${CLANG_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${CLANG_TRIPLE})
set(CMAKE_SYSROOT ${CMAKE_BINARY_DIR}/sysroot)
enable_language(C)
enable_language(CXX)

# Ensure that we can find the clang builtin headers
add_compile_options(-nobuiltininc)
add_compile_options(-v)
execute_process(COMMAND ${CMAKE_C_COMPILER} -print-resource-dir OUTPUT_VARIABLE BUILTIN_HEADERS_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "BUILTIN_HEADERS_DIR=${BUILTIN_HEADERS_DIR}")
add_compile_options(-idirafter ${BUILTIN_HEADERS_DIR}/include)

add_subdirectory(libexec/rtld-elf)

function(add_fake_targets_for_subdir _subdir)
    file(GLOB _dirs LIST_DIRECTORIES TRUE "${_subdir}/*")
    foreach(_dirpath ${_dirs})
        message(STATUS "Checking ${_dirpath}")
        if (IS_DIRECTORY "${_dirpath}")
            get_filename_component(_dirname "${_dirpath}" NAME)
            file(GLOB_RECURSE _fake_srcs LIST_DIRECTORIES FALSE "${_dirpath}/*.c" "${_dirpath}/*.cc" "${_dirpath}/*.cpp")
            if (NOT _fake_srcs)
                message(STATUS "No sources found for ${_subdir}/${_dirname}. Contrib program?")
                continue()
            endif()
            add_executable(${_subdir}_${_dirname} ${_fake_srcs})
            # Add include paths for commonly used libraries
            target_include_directories(${_subdir}_${_dirname} PRIVATE
                lib/libutil
                contrib/libxo
                contrib/atf  # for tests
            )
        endif()
    endforeach()
endfunction()

add_fake_targets_for_subdir(bin)
add_fake_targets_for_subdir(usr.bin)
add_fake_targets_for_subdir(sbin)
add_fake_targets_for_subdir(usr.sbin)
target_include_directories(usr.bin_truss PRIVATE lib/libsysdecode)


set(AWK "awk" CACHE FILEPATH "Path to awk")
function(generate_if_headers _if_files_dir)
    file(GLOB_RECURSE _if_files LIST_DIRECTORIES FALSE "${_if_files_dir}/*_if.m")
    # message(STATUS "interfaces: ${_if_files}")
    foreach(_if ${_if_files})
        execute_process(COMMAND ${AWK} -f "${CMAKE_SOURCE_DIR}/sys/tools/makeobjops.awk" "${_if}" -h
                        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/kern_opt
                        # ECHO_OUTPUT_VARIABLE ECHO_ERROR_VARIABLE
                        COMMAND_ECHO STDOUT
                        )
    endforeach()
endfunction()
set(FAKE_KERNEL_SRCS)
function(add_kernel_srcs _dir)
    set(_new_kernel_srcs ${FAKE_KERNEL_SRCS})
    file(GLOB_RECURSE _found_c_files LIST_DIRECTORIES FALSE "${_dir}/*.c")
    list(APPEND _new_kernel_srcs ${_found_c_files})
    set(FAKE_KERNEL_SRCS ${_new_kernel_srcs} PARENT_SCOPE)
    generate_if_headers("${_dir}")
endfunction()

add_kernel_srcs("sys/${TARGET}")
if("${TARGET}" STREQUAL "amd64")
    add_kernel_srcs("sys/x86")
endif()
add_kernel_srcs("sys/ddb")
add_kernel_srcs("sys/cheri")
add_kernel_srcs("sys/kern")
add_kernel_srcs("sys/libkern")
add_kernel_srcs("sys/fs")
add_kernel_srcs("sys/dev/virtio")
add_library(fake_kernel STATIC ${FAKE_KERNEL_SRCS})
target_compile_definitions(fake_kernel PRIVATE _KERNEL=1)
target_include_directories(fake_kernel PRIVATE ${CMAKE_BINARY_DIR}/kern_opt)
target_include_directories(fake_kernel PRIVATE ${CMAKE_SOURCE_DIR}/sys/contrib/ck/include)
target_compile_options(fake_kernel PRIVATE "-include${CMAKE_BINARY_DIR}/kern_opt/opt_global.h")
