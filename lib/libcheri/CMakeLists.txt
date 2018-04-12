# CMakeLists.txt to build libcheri sandboxloader on the host (for debugging)
cmake_minimum_required(VERSION 3.7.0)
if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    project(libcheri_sandbox_loader LANGUAGES C)
endif()
add_executable(sandbox_loadelf64 libcheri_sandbox_elf.c)
target_compile_definitions(sandbox_loadelf64 PRIVATE -DTEST_LOADELF64=1)
target_compile_options(sandbox_loadelf64 PRIVATE -Wall)
if(APPLE)
    target_compile_definitions(sandbox_loadelf64 PRIVATE -D_DARWIN_C_SOURCE=1)
elseif("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    # Add all the typedefs like caddr_t
    target_compile_definitions(sandbox_loadelf64 PRIVATE -D_GNU_SOURCE=1)
    # target_include_directories(sandbox_loadelf64 SYSTEM PRIVATE -D_GNU_SOURCE=1)
    # target_compile_definitions(sandbox_loadelf64 PRIVATE -DLIBBSD_OVERLAY=1)
    target_link_libraries(sandbox_loadelf64 PRIVATE -lbsd)
endif()

# Add the elf.h headers needed to compile this program:
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/machine)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/sys)
execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
                ${CMAKE_CURRENT_SOURCE_DIR}/../../include/elf.h ${CMAKE_CURRENT_BINARY_DIR}/include/elf.h)
function(symlink_cheribsd_header _srcdir _destdir _header)
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../${_srcdir}/${_header}
                    ${CMAKE_CURRENT_BINARY_DIR}/include/${_destdir}/${_header})
endfunction()
symlink_cheribsd_header(include          ""      elf.h)
symlink_cheribsd_header(sys/sys          sys     elf32.h)
symlink_cheribsd_header(sys/sys          sys     elf64.h)
symlink_cheribsd_header(sys/sys          sys     elf_generic.h)
symlink_cheribsd_header(sys/sys          sys     elf_common.h)
symlink_cheribsd_header(sys/mips/include machine elf.h)

if(APPLE)
    symlink_cheribsd_header(sys/sys      sys     endian.h)
elseif("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/include/sys/endian.h "#include <endian.h>")
endif()


target_include_directories(sandbox_loadelf64 PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include)
target_compile_options(sandbox_loadelf64 PRIVATE -std=c11)
