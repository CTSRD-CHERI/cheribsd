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
        # Default to purecap compilation mode for code completion
        add_compile_options(-mabi=purecap -msoft-float)
        set(CLANG_TRIPLE mips64-unknown-freebsd14)
    else()
        message(FATAL_ERROR "Unsupported MIPS TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
elseif("${TARGET}" STREQUAL "riscv")
    if("${TARGET_ARCH}" STREQUAL "riscv64")
        # Default to purecap compilation mode for code completion
        add_compile_options(-march=rv64imafdcxcheri -mabi=l64pc128d -mno-relax)
        set(CLANG_TRIPLE riscv64-unknown-freebsd14)
    else()
        message(FATAL_ERROR "Unsupported RISC-V TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
elseif("${TARGET}" STREQUAL "arm64")
    if("${TARGET_ARCH}" STREQUAL "aarch64")
        set(CLANG_TRIPLE aarch64-unknown-freebsd14)
    else()
        message(FATAL_ERROR "Unsupported ARM64 TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
elseif("${TARGET}" STREQUAL "amd64")
    if("${TARGET_ARCH}" STREQUAL "amd64")
        set(CLANG_TRIPLE x86_64-unknown-freebsd14)
    else()
        message(FATAL_ERROR "Unsupported x86 TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
elseif("${TARGET}" STREQUAL "i386")
    if("${TARGET_ARCH}" STREQUAL "i386")
        set(CLANG_TRIPLE i686-unknown-freebsd14)
    else()
        message(FATAL_ERROR "Unsupported x86 TARGET_ARCH: ${TARGET}:${TARGET_ARCH}!")
    endif()
else()
    message(FATAL_ERROR "Unsupported TARGET: ${TARGET}:${TARGET_ARCH}!")
endif()

include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/include)
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/sys)
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/contrib/libxo)
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/contrib/libc-vis)
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/lib/libstatcounters)

set(TMPSYSROOT ${CMAKE_BINARY_DIR}/sysroot/usr)
file(MAKE_DIRECTORY ${TMPSYSROOT}/include/)

# Create symlinks
set(MACHINE_HEADERS "${CMAKE_SOURCE_DIR}/sys/${TARGET}/include")
file(CREATE_LINK ${MACHINE_HEADERS} ${TMPSYSROOT}/include/machine SYMBOLIC)
file(CREATE_LINK ${CMAKE_SOURCE_DIR}/sys/sys ${TMPSYSROOT}/include/sys SYMBOLIC)
if("${TARGET}" STREQUAL "amd64" OR "${TARGET}" STREQUAL "i386")
    file(CREATE_LINK "${CMAKE_SOURCE_DIR}/sys/x86/include" ${TMPSYSROOT}/include/x86 SYMBOLIC)
endif()
set(_symlinked_sysincs aio.h errno.h fcntl.h linker_set.h poll.h stdatomic.h stdint.h syslog.h ucontext.h)
list(APPEND _symlinked_sysincs sched.h _semaphore.h)
foreach(_hdr ${_symlinked_sysincs})
    file(CREATE_LINK sys/${_hdr} ${TMPSYSROOT}/include/${_hdr} SYMBOLIC)
endforeach()
set(_symlinked_machineincs float.h floatingpoint.h stdarg.h)
foreach(_hdr ${_symlinked_machineincs})
    file(CREATE_LINK machine/${_hdr} ${TMPSYSROOT}/include/${_hdr} SYMBOLIC)
endforeach()
# math.h and fenv.h
file(CREATE_LINK "${CMAKE_SOURCE_DIR}/lib/msun/src/math.h" ${TMPSYSROOT}/include/math.h SYMBOLIC)
if("${TARGET}" STREQUAL "amd64")
    file(CREATE_LINK "${CMAKE_SOURCE_DIR}/lib/msun/x86/fenv.h" ${TMPSYSROOT}/include/fenv.h SYMBOLIC)
elseif("${TARGET}" STREQUAL "arm64")
    file(CREATE_LINK "${CMAKE_SOURCE_DIR}/lib/msun/aarch64/fenv.h" ${TMPSYSROOT}/include/fenv.h SYMBOLIC)
else()
    file(CREATE_LINK "${CMAKE_SOURCE_DIR}/lib/msun/${TARGET}/fenv.h" ${TMPSYSROOT}/include/fenv.h SYMBOLIC)
endif()

# Add code completion for casper
file(MAKE_DIRECTORY ${TMPSYSROOT}/include/casper)
file(GLOB _casper_hdrs LIST_DIRECTORIES FALSE "lib/libcasper/services/*/*.h")
foreach(_hdrpath ${_casper_hdrs})
    get_filename_component(_hdrname "${_hdrpath}" NAME)
    file(CREATE_LINK "${_hdrpath}" ${TMPSYSROOT}/include/casper/${_hdrname} SYMBOLIC)
endforeach()
file(CREATE_LINK "${CMAKE_SOURCE_DIR}/lib/libcapsicum/capsicum_helpers.h" ${TMPSYSROOT}/include/capsicum_helpers.h SYMBOLIC)
file(CREATE_LINK "${CMAKE_SOURCE_DIR}/lib/libcasper/libcasper/libcasper.h" ${TMPSYSROOT}/include/libcasper.h SYMBOLIC)
add_compile_definitions(HAVE_CASPER=1)

# TODO: should only be for CHERI
file(MAKE_DIRECTORY ${TMPSYSROOT}/include/c++)
file(CREATE_LINK ${CMAKE_SOURCE_DIR}/contrib/subrepo-cheri-libc++/include ${TMPSYSROOT}/include/c++/v1 SYMBOLIC)
file(CREATE_LINK ${CMAKE_SOURCE_DIR}/lib/libc++/__config_site ${TMPSYSROOT}/include/c++/v1/__config_site SYMBOLIC)

file(MAKE_DIRECTORY ${TMPSYSROOT}/kern_opt)
file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_ddb.h "#define DDB 1\n")
file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_ktrace.h "#define KTRACE 1\n")
file(WRITE ${CMAKE_BINARY_DIR}/cheri_builtins.h "
#ifdef __JETBRAINS_IDE__
// Pretend that we have capabilities in CLion
#define __CHERI__
#define __has_feature(x) __fake_has_feature_##x
#define __fake_has_feature_capabilities 1
#define __fake_has_feature_nullability 1
// But we don't really so define __capability to nothing
#define __capability
// Same thing for __(u)intcap_t
typedef unsigned long __uintcap_t;
typedef long __intcap_t;
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
unsigned long __builtin_cheri_representable_alignment_mask(unsigned long);
unsigned long __builtin_cheri_round_representable_length(unsigned long);
// Also define some compiler defines:
#define __CHERI_ADDRESS_BITS__ 64
#define __CHERI_CAPABILITY_WIDTH__ 128
#define __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__ 1024
#define __CHERI_CAP_PERMISSION_GLOBAL__ 1
#define __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__ 2
#define __CHERI_CAP_PERMISSION_PERMIT_INVOKE__ 256
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
#include \"cheri_builtins.h\"
")

file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_global.h "
#include \"../cheri_builtins.h\"
#define KDB 1
#define COMPAT_FREEBSD11 1
#define COMPAT_FREEBSD12 1
#define COMPAT_FREEBSD13 1
#define COMPAT_FREEBSD32 1
#define COMPAT_FREEBSD64 1
#define CPU_CHERI 1
#define INVARIANT_SUPPORT 1
#define INVARIANTS 1
#define FDT 1
#define DEV_ACPI 1
#define CPU_MALTA 1
#define TICK_USE_YAMON_FREQ defined
#define YAMON 1
#define INVARIANTS 1
#define CPU_QEMU_RISCV 1
#define MAC 1
#define AUDIT 1
#define SMP 1
#define INET 1
#define INET6 1
#define DEV_NETMAP 1
#define VFP 1

struct thread_lite {
    unsigned td_pinned;
    unsigned td_critnest;
    unsigned td_owepreempt;
};
")

file(WRITE ${CMAKE_BINARY_DIR}/kern_opt/opt_capsicum.h "
#define CAPABILITIES 1
#define CAPABILITY_MODE 1
")


set(CMAKE_C_COMPILER_TARGET ${CLANG_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${CLANG_TRIPLE})
set(CMAKE_SYSROOT ${CMAKE_BINARY_DIR}/sysroot)
enable_language(C)
enable_language(CXX)
# Work around https://youtrack.jetbrains.com/issue/CPP-21358
add_compile_options(-target ${CLANG_TRIPLE})

# Ensure that the libc++ include paths are used.
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)

# Ensure that we can find the clang builtin headers
add_compile_options(-nobuiltininc)
execute_process(COMMAND ${CMAKE_C_COMPILER} -print-resource-dir OUTPUT_VARIABLE BUILTIN_HEADERS_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "BUILTIN_HEADERS_DIR=${BUILTIN_HEADERS_DIR}")
add_compile_options(-idirafter ${BUILTIN_HEADERS_DIR}/include)
add_compile_options(-Wall -Wextra -Wcast-align)
add_compile_options(-Wno-pointer-sign)

# Generate osreldate.h
execute_process(
    COMMAND env "NEWVERS_SH=${CMAKE_SOURCE_DIR}/sys/conf/newvers.sh"
        "PARAMFILE=${CMAKE_SOURCE_DIR}/sys/sys/param.h"
        "SYSDIR=${CMAKE_SOURCE_DIR}/sys" sh
        "${CMAKE_SOURCE_DIR}/include/mk-osreldate.sh"
    WORKING_DIRECTORY ${TMPSYSROOT}/include)

function(add_fake_targets_for_subdir _subdir)
    cmake_parse_arguments(aftfs "LIBRARIES" "PREFIX" "" ${ARGN})
    file(GLOB _dirs LIST_DIRECTORIES TRUE "${_subdir}/*")
    if (aftfs_PREFIX)
        set(_prefix ${aftfs_PREFIX})
    else()
        set(_prefix ${_subdir})
    endif()
    foreach(_dirpath ${_dirs})
        message(STATUS "Checking ${_dirpath}")
        if (IS_DIRECTORY "${_dirpath}")
            get_filename_component(_dirname "${_dirpath}" NAME)
            file(GLOB_RECURSE _fake_srcs LIST_DIRECTORIES FALSE "${_dirpath}/*.c" "${_dirpath}/*.cc" "${_dirpath}/*.cpp")
            if (NOT _fake_srcs)
                message(STATUS "No sources found for ${_subdir}/${_dirname}. Contrib program?")
                # Need at least one source for add_library() unless we add target_sources calls for all of them.
                add_library(${_prefix}_${_dirname} STATIC tools/build/dummy.c)
                continue()
            endif()
            if (aftfs_LIBRARIES)
                add_library(${_prefix}_${_dirname} STATIC ${_fake_srcs})
            else()
                # TODO: add_executable(${_prefix}_${_dirname} ${_fake_srcs})
                # target_link_libraries(${_prefix}_${_dirname} PRIVATE -fuse-ld=lld)
                add_library(${_prefix}_${_dirname} STATIC ${_fake_srcs})
            endif()
            # Add the source dir as an include path
            target_include_directories(${_prefix}_${_dirname} PUBLIC ${_dirpath} ${_dirpath}/include)
            # Add include paths for commonly used libraries
            target_include_directories(${_prefix}_${_dirname} PRIVATE
                lib/libutil
                contrib/libxo
                contrib/atf  # for tests
            )
            target_compile_options(${_prefix}_${_dirname} PRIVATE "-include${CMAKE_BINARY_DIR}/cheri_purecap.h")
        endif()
    endforeach()
endfunction()

function(add_contrib_sources _tgt _dir)
    file(GLOB_RECURSE _contrib_srcs LIST_DIRECTORIES FALSE "${_dir}/*.c")
    target_sources(${_tgt} PRIVATE ${_contrib_srcs})
    target_include_directories(${_tgt} PUBLIC "${_dir}" "${_dir}/include")
endfunction()

add_fake_targets_for_subdir(lib LIBRARIES)
add_contrib_sources(lib_libc contrib/jemalloc)
add_contrib_sources(lib_ncurses contrib/jemalloc)
add_contrib_sources(lib_libelf contrib/elftoolchain/libelf)
target_include_directories(lib_libelf PUBLIC contrib/elftoolchain/common)
target_link_libraries(lib_libkvm PUBLIC lib_libelf)
target_include_directories(lib_libpmc PRIVATE lib/libpmcstat)
target_link_libraries(lib_libpmc PUBLIC lib_libelf)
target_link_libraries(lib_libpmcstat PUBLIC lib_libelf PRIVATE lib_libpmc)
target_include_directories(lib_msun PRIVATE lib/msun/src)
target_compile_definitions(lib_msun PRIVATE -DDOPRINT -DDEBUG -DDOPRINT_LD80)
target_include_directories(lib_libsimple_printf PRIVATE lib/libc/stdio)
add_fake_targets_for_subdir(bin)
add_fake_targets_for_subdir(usr.bin)
add_fake_targets_for_subdir(sbin)
add_fake_targets_for_subdir(usr.sbin)
add_fake_targets_for_subdir(tests/sys PREFIX tests_sys)
target_include_directories(tests_sys_audit PRIVATE contrib/openbsm)
target_include_directories(usr.bin_truss SYSTEM PRIVATE lib/libsysdecode)
add_contrib_sources(usr.sbin_makefs contrib/mtree)
add_contrib_sources(usr.sbin_makefs contrib/mknod)
target_include_directories(usr.sbin_makefs PRIVATE lib/libnetbsd sys/fs/cd9660 sys/ufs/ffs sys/fs/msdosfs sbin/newfs_msdos)
add_contrib_sources(usr.sbin_nmtree contrib/mtree)
add_contrib_sources(usr.sbin_nmtree contrib/mknod)
target_link_libraries(usr.sbin_nmtree PRIVATE lib_libnetbsd)
target_link_libraries(usr.sbin_pmcstat PRIVATE lib_libpmcstat lib_libpmc lib_libelf lib_libkvm)


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
if("${TARGET}" STREQUAL "amd64" OR "${TARGET}" STREQUAL "i386")
    add_kernel_srcs("sys/x86")
endif()
add_kernel_srcs("sys/cheri")
add_kernel_srcs("sys/cddl")
add_kernel_srcs("sys/ddb")
add_kernel_srcs("sys/kern")
add_kernel_srcs("sys/libkern")
add_kernel_srcs("sys/fs")
add_kernel_srcs("sys/net")
add_kernel_srcs("sys/netinet")
add_kernel_srcs("sys/netinet6")
add_kernel_srcs("sys/security")
add_kernel_srcs("sys/ufs")
add_kernel_srcs("sys/vm")
add_kernel_srcs("sys/xdr")
function(add_kernel_compile_flags _target)
    target_compile_definitions(${_target} PRIVATE _KERNEL=1)
    target_include_directories(${_target} PRIVATE ${CMAKE_BINARY_DIR}/kern_opt ${CMAKE_SOURCE_DIR}/sys/contrib/ck/include)
    target_compile_options(${_target} PRIVATE "-include${CMAKE_BINARY_DIR}/kern_opt/opt_global.h" -ffreestanding -Wno-cast-align)
endfunction()
# Add targets for sys/dev:
function(add_kernel_modules _prefix _subdir)
    file(GLOB _subdirs LIST_DIRECTORIES TRUE "${_subdir}/*")
    # message(STATUS "interfaces: ${_if_files}")
    foreach(_dirpath ${_subdirs})
        if (NOT IS_DIRECTORY ${_dirpath})
            continue()
        endif()
        get_filename_component(_dirname "${_dirpath}" NAME)
        file(GLOB_RECURSE _srcs LIST_DIRECTORIES FALSE "${_dirpath}/*.c" "${_dirpath}/*.cc" "${_dirpath}/*.cpp")
        file(GLOB_RECURSE _hdrs LIST_DIRECTORIES FALSE "${_dirpath}/*.h")
        if (NOT _srcs)
            message(STATUS "No sources found for ${_dirpath}?")
            add_library(${_prefix}_${_dirname} STATIC tools/build/dummy.c ${_hdrs})
        else()
            # message(STATUS "Adding ${_prefix}_${_dirname}")
            add_library(${_prefix}_${_dirname} STATIC ${_srcs} ${_hdrs})
        endif()
        generate_if_headers("${_dirpath}")
        add_kernel_compile_flags(${_prefix}_${_dirname})
    endforeach()
endfunction()

add_kernel_modules(sys_dev sys/dev)
add_library(fake_kernel STATIC ${FAKE_KERNEL_SRCS})
execute_process(COMMAND ${AWK} -f "${CMAKE_SOURCE_DIR}/sys/tools/vnode_if.awk" "${CMAKE_SOURCE_DIR}/sys/kern/vnode_if.src" -h
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/kern_opt COMMAND_ECHO STDOUT)
execute_process(COMMAND ${AWK} -f "${CMAKE_SOURCE_DIR}/sys/tools/vnode_if.awk" "${CMAKE_SOURCE_DIR}/sys/kern/vnode_if.src" -p
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/kern_opt COMMAND_ECHO STDOUT)
execute_process(COMMAND ${AWK} -f "${CMAKE_SOURCE_DIR}/sys/tools/vnode_if.awk" "${CMAKE_SOURCE_DIR}/sys/kern/vnode_if.src" -q
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/kern_opt COMMAND_ECHO STDOUT)

add_kernel_compile_flags(fake_kernel)
# Correct completion for imgact_elf.c:
target_compile_definitions(fake_kernel PRIVATE -D__ELF_CHERI=1 -D__ELF_WORD_SIZE=64)

# Default to purecap compile options for all other files
add_compile_options("-include${CMAKE_BINARY_DIR}/cheri_purecap.h")

add_subdirectory(libexec/rtld-elf)
