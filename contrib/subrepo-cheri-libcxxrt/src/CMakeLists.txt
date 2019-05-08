
set(CXXRT_SOURCES
    guard.cc
    memory.cc
    auxhelper.cc
    stdexcept.cc
    libelftc_dem_gnu3.c
   )

if (NO_UNWIND_LIBRARY)
    list(APPEND CXXRT_SOURCES unwind_stubs.c)
endif()

if (DISABLE_EXCEPTIONS_RTTI)
    list(APPEND CXXRT_SOURCES exception_stubs.cc)
else()
    list(APPEND CXXRT_SOURCES
         exception.cc
         typeinfo.cc
         dynamic_cast.cc
     )
endif()

add_definitions(-D_GNU_SOURCE)

add_library(cxxrt-static STATIC ${CXXRT_SOURCES})
target_link_libraries(cxxrt-static PUBLIC ${CMAKE_DL_LIBS})
target_compile_features(cxxrt-static PRIVATE cxx_static_assert)
set_target_properties(cxxrt-static PROPERTIES OUTPUT_NAME "cxxrt")

if (NOT NO_SHARED)
    add_library(cxxrt-shared SHARED ${CXXRT_SOURCES})
    target_link_libraries(cxxrt-shared PUBLIC ${CMAKE_DL_LIBS})
    # Do not attempt to link libcxxrt against libc++/libstdc++
    target_link_libraries(cxxrt-shared PUBLIC -nostdlib++)
    if(NOT NO_UNWIND_LIBRARY)
        target_link_libraries(cxxrt-shared PUBLIC ${LIBUNWIND_SHARED})
        target_link_libraries(cxxrt-static PUBLIC ${LIBUNWIND_STATIC})
    endif()
    target_compile_features(cxxrt-shared PRIVATE cxx_static_assert)
    set_target_properties(cxxrt-shared PROPERTIES OUTPUT_NAME "cxxrt")
endif()

