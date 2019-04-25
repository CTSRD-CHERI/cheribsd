
set(CXXTEST_SOURCES
    test.cc
    test_guard.cc
   )
if(NOT DISABLE_EXCEPTIONS_RTTI)
  list(APPEND CXXTEST_SOURCES test_exception.cc test_typeinfo.cc)
endif()

include(CheckCXXSymbolExists)
check_cxx_symbol_exists(std::uncaught_exceptions stdexcept HAVE_STD_UNCAUGHT_EXCEPTIONS)
if(HAVE_STD_UNCAUGHT_EXCEPTIONS)
    add_definitions(-DHAVE_STD_UNCAUGHT_EXCEPTIONS)
endif()

option(COMPARE_TEST_OUTPUT_TO_SYSTEM_OUTPUT "Compare tests with system output" ON)

if(NOT NO_SHARED AND COMPARE_TEST_OUTPUT_TO_SYSTEM_OUTPUT)
    add_executable(system-test ${CXXTEST_SOURCES})

    # Generating excpected output with system-test
    add_custom_target(test-expected-output ALL
                      COMMAND system-test > ${CMAKE_CURRENT_BINARY_DIR}/expected_output.log 2>&1
                      DEPENDS system-test)
    set(HAVE_EXPECTED_OUTPUT TRUE)
else()
    set(HAVE_EXPECTED_OUTPUT FALSE)
endif()

function(add_cxxrt_test _target _output_log_file)
    if (HAVE_EXPECTED_OUTPUT)
        add_test(${_target}-test
             ${CMAKE_CURRENT_SOURCE_DIR}/run_test.sh
             ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${_target}
             ${CMAKE_CURRENT_BINARY_DIR}/expected_output.log
             ${CMAKE_CURRENT_BINARY_DIR}/${_output_log_file})
    else()
        add_test(${_target}-test ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${_target})
    endif()
endfunction()

set(NO_STATIC_TEST_DEFAULT OFF)
if(APPLE)
    set(NO_STATIC_TEST_DEFAULT ON)
endif()
option(NO_STATIC_TEST "Don't build the static test" ${NO_STATIC_TEST_DEFAULT})
set(STATIC_LIB_DEPS gcc_eh)
find_library(LIBCOMPILER_RT_STATIC libcompiler_rt.a)
if(LIBCOMPILER_RT_STATIC)
    list(APPEND STATIC_LIB_DEPS ${LIBCOMPILER_RT_STATIC})
endif()
message(STATUS "static lib deps: ${STATIC_LIB_DEPS}")

if(NOT NO_STATIC_TEST)
    add_executable(cxxrt-test-static ${CXXTEST_SOURCES})
    set_property(TARGET cxxrt-test-static PROPERTY LINK_FLAGS "-nodefaultlibs -static")
    target_link_libraries(cxxrt-test-static cxxrt-static pthread ${CMAKE_DL_LIBS} c ${STATIC_LIB_DEPS})
    add_cxxrt_test(cxxrt-test-static test-static-output.log)
endif()

if(NOT NO_SHARED)
    add_executable(cxxrt-test-shared ${CXXTEST_SOURCES})
    set_property(TARGET cxxrt-test-shared PROPERTY LINK_FLAGS -nodefaultlibs)
    if(NOT CMAKE_CROSSCOMPILING)
        set_target_properties(cxxrt-test-shared PROPERTIES
           INSTALL_RPATH "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
           INSTALL_RPATH_USE_LINK_PATH ON
           BUILD_WITH_INSTALL_RPATH ON)
    endif()
    target_link_libraries(cxxrt-test-shared cxxrt-shared pthread ${CMAKE_DL_LIBS} c)
    add_cxxrt_test(cxxrt-test-shared test-shared-output.log)
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)
if(NOT DISABLE_EXCEPTIONS_RTTI AND NOT APPLE)
    add_executable(cxxrt-test-foreign-exceptions test_foreign_exceptions.cc)
    set_property(TARGET cxxrt-test-foreign-exceptions PROPERTY LINK_FLAGS "-nodefaultlibs -Wl,--wrap,_Unwind_RaiseException")
    target_link_libraries(cxxrt-test-foreign-exceptions cxxrt-static gcc_s pthread ${CMAKE_DL_LIBS} c)
    add_test(cxxrt-test-foreign-exceptions
             ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cxxrt-test-foreign-exceptions)
endif()

set(valgrind "valgrind -q")

if(TEST_VALGRIND)
    add_test(cxxrt-test-static-test-valgrind
             ${CMAKE_CURRENT_SOURCE_DIR}/run_test.sh
             "${valgrind} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cxxrt-test-static"
             ${CMAKE_CURRENT_BINARY_DIR}/expected_output.log
             ${CMAKE_CURRENT_BINARY_DIR}/test-static-output.log)

    add_test(cxxrt-test-shared-test-valgrind
             ${CMAKE_CURRENT_SOURCE_DIR}/run_test.sh
             "${valgrind} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cxxrt-test-shared"
             ${CMAKE_CURRENT_BINARY_DIR}/expected_output.log
             ${CMAKE_CURRENT_BINARY_DIR}/test-shared-output.log)
endif()


# Testing with libunwind
option(TEST_LIBUNWIND "Test libcxxrt with libunwind" OFF)

if(TEST_LIBUNWIND)
    add_executable(cxxrt-test-libunwind-allstatic ${CXXTEST_SOURCES})
    set_property(TARGET cxxrt-test-libunwind-allstatic PROPERTY LINK_FLAGS
                 "-L${LIBUNWIND_PATH} -nodefaultlibs -static")
    target_link_libraries(cxxrt-test-libunwind-allstatic cxxrt-static
                          ${LIBUNWIND_STATIC} pthread ${CMAKE_DL_LIBS} c ${STATIC_LIB_DEPS}
                          )

    add_executable(cxxrt-test-libunwind-static ${CXXTEST_SOURCES})
    set_property(TARGET cxxrt-test-libunwind-static PROPERTY LINK_FLAGS
                 "-L${LIBUNWIND_PATH} -nodefaultlibs")
    target_link_libraries(cxxrt-test-libunwind-static cxxrt-static
                          ${LIBUNWIND_STATIC} pthread ${CMAKE_DL_LIBS} c)
    if(NOT APPLE)
        target_link_libraries(cxxrt-test-libunwind-static gcc)
    endif()
    option(LIBUNWIND_NEEDS_LZMA "" OFF)
    if(LIBUNWIND_NEEDS_LZMA)
        find_library(LIBLZMA_STATIC liblzma.a HINTS ${LIBUNWIND_PATH})
        target_link_libraries(cxxrt-test-libunwind-static ${LIBLZMA_STATIC})
    endif()

    add_cxxrt_test(cxxrt-test-libunwind-static test-libunwind-static-output.log)

    if(NOT NO_SHARED)
        add_executable(cxxrt-test-libunwind-shared ${CXXTEST_SOURCES})
        set_property(TARGET cxxrt-test-libunwind-shared PROPERTY LINK_FLAGS
                     "-L${LIBUNWIND_PATH} -nodefaultlibs")
        target_link_libraries(cxxrt-test-libunwind-shared cxxrt-shared
                             ${LIBUNWIND_SHARED} pthread ${CMAKE_DL_LIBS} c)

        add_cxxrt_test(cxxrt-test-libunwind-shared test-libunwind-shared-output.log)
    endif()

    if(TEST_VALGRIND)
        add_test(cxxrt-test-libunwind-static-test-valgrind
                 ${CMAKE_CURRENT_SOURCE_DIR}/run_test.sh
                 "${valgrind} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cxxrt-test-libunwind-static"
                 ${CMAKE_CURRENT_BINARY_DIR}/expected_output.log
                 ${CMAKE_CURRENT_BINARY_DIR}/test-libunwind-static-output.log)
        if(NOT NO_SHARED)
            add_test(cxxrt-test-libunwind-shared-test-valgrind
                     ${CMAKE_CURRENT_SOURCE_DIR}/run_test.sh
                     "${valgrind} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cxxrt-test-libunwind-shared"
                     ${CMAKE_CURRENT_BINARY_DIR}/expected_output.log
                     ${CMAKE_CURRENT_BINARY_DIR}/test-libunwind-shared-output.log)
        endif()
    endif()
endif()

