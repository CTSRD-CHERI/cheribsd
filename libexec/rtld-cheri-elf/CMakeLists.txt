

set(RTLD_ARCH ${TARGET})

set(rtld_SRCS ${RTLD_ARCH}/rtld_start.S ${RTLD_ARCH}/cheri_reloc.c ${RTLD_ARCH}/cheri_plt.cpp)

list(APPEND rtld_SRCS
	../../lib/libmalloc_simple/heap.c
	../rtld-elf/${RTLD_ARCH}/reloc.c
	../rtld-elf/rtld.c
	../rtld-elf/rtld_malloc.c
	../rtld-elf/rtld_lock.c
	../rtld-elf/map_object.c
	../rtld-elf/xmalloc.c
	../rtld-elf/debug.c
	../rtld-elf/libmap.c
)

# For code completion:
add_definitions(-D__CHERI_PURE_CAPABILITY__=2)
add_definitions(-D__CHERI__=1)
add_definitions(-DRTLD_SUPPORT_PER_FUNCTION_CAPTABLE=1)
add_definitions(-DIN_RTLD=1)
# add_compile_options(-v)
add_compile_options(-mabi=purecap)
add_compile_options(-cheri=128)
include_directories(${RTLD_ARCH})
include_directories(../rtld-elf)
include_directories(../rtld-elf/${RTLD_ARCH})
include_directories(${CMAKE_SOURCE_DIR}/lib/csu/common)
include_directories(${CMAKE_SOURCE_DIR}/lib/libc/${RTLD_ARCH})
include_directories(${CMAKE_SOURCE_DIR}/lib/libsimple_printf)


add_library(rtld-cheri-elf SHARED ${rtld_SRCS})
set_target_properties(rtld-cheri-elf PROPERTIES OUTPUT_NAME ld-cheri-elf VERSION 1)

# Build the CHERI PLT stuff as C++
# CXXFLAGS+= -std=c++11 -fno-rtti -fno-exceptions

target_include_directories(rtld-cheri-elf PRIVATE ${CMAKE_SOURCE_DIR}/contrib/uthash/src)
target_compile_definitions(rtld-cheri-elf PRIVATE -DSIMPLE_PRINTF_PREFIX=rtld)
target_link_libraries(rtld-cheri-elf PRIVATE -nostdlib -Wl,-e,rtld_start)

# require c++11:
target_compile_features(rtld-cheri-elf PRIVATE cxx_range_for)
