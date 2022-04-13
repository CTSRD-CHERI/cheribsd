if (IS_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/${TARGET_ARCH})
	set(RTLD_ARCH ${TARGET_ARCH})
else()
	set(RTLD_ARCH ${TARGET})
endif()
set(rtld_SRCS
	${RTLD_ARCH}/rtld_start.S
	${RTLD_ARCH}/reloc.c
	rtld.c
	rtld_lock.c
	map_object.c
	xmalloc.c
	debug.c
	libmap.c
	rtld_malloc.c
	rtld_printf.c
	../../lib/libmalloc_simple/heap.c
	../../lib/libmalloc_simple/malloc.c
	cheri/cheri_reloc.c
)
if (EXISTS ${RTLD_ARCH}/cheri_plt.cpp)
    list(APPEND rtld_SRCS ${RTLD_ARCH}/cheri_plt.cpp)
endif()

# For code completion:
add_definitions(-DIN_RTLD=1)
include_directories(${RTLD_ARCH})
include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(cheri)
include_directories(rtld-libc)
include_directories(${CMAKE_SOURCE_DIR}/lib/csu/common)
include_directories(${CMAKE_SOURCE_DIR}/lib/libc/${RTLD_ARCH})
include_directories(${CMAKE_SOURCE_DIR}/lib/libsimple_printf)

add_library(rtld-elf SHARED ${rtld_SRCS})
set_target_properties(rtld-elf PROPERTIES OUTPUT_NAME ld-elf VERSION 1)

# Build the CHERI PLT stuff as C++
# CXXFLAGS+= -std=c++11 -fno-rtti -fno-exceptions
target_include_directories(rtld-elf PRIVATE ${CMAKE_SOURCE_DIR}/contrib/uthash/src)
target_compile_definitions(rtld-elf PRIVATE -DSIMPLE_PRINTF_PREFIX=rtld)
target_link_libraries(rtld-elf PRIVATE -nostdlib -Wl,-e,rtld_start)

# require c++11:
target_compile_features(rtld-elf PRIVATE cxx_range_for)
