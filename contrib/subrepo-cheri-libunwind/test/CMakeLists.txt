include(AddLLVM) # for add_lit_testsuite
macro(pythonize_bool var)
  if (${var})
    set(${var} True)
  else()
    set(${var} False)
  endif()
endmacro()

# Setup the default options if LIBCXX_CXX_ABI is not specified.
set(_cxx_abi_link_flag "${LIBUNWIND_TEST_CXX_ABI_LIB_PATH}")
if(NOT _cxx_abi_link_flag)
  if ("${LIBUNWIND_CXX_ABI}" STREQUAL "default")
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
      set(_cxx_abi_link_flag "libsupc++")
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
      set(_cxx_abi_link_flag "-lcxxrt")
    elseif(APPLE)
      set(_cxx_abi_link_flag "-lc++abi")
    endif()
  elseif ("${LIBUNWIND_CXX_ABI}" STREQUAL "libsupc++")
    set(_cxx_abi_link_flag "-lsupc++")
  elseif ("${LIBUNWIND_CXX_ABI}" STREQUAL "libstd++")
    set(_cxx_abi_link_flag "-lsupc++")
  elseif ("${LIBUNWIND_CXX_ABI}" STREQUAL "libcxxrt")
    set(_cxx_abi_link_flag "libcxxabi")
  elseif ("${LIBUNWIND_CXX_ABI}" STREQUAL "libcxxabi")
    set(_cxx_abi_link_flag "-lc++abi")
  else()
    message(WARNING "Set LIBUNWIND_TEST_CXX_ABI_LIB to build the exceptions tests")
  endif()
endif()
if (NOT _cxx_abi_link_flag)
  message(WARNING "Set LIBUNWIND_TEST_CXX_ABI_LIB to build the exceptions tests")
  set(LIBUNWIND_TEST_ENABLE_EXCEPTIONS OFF)
endif()

set(_LIBUNWIND_TESTS alignment.compile libunwind_01 libunwind_02 libunwind_size unw_getcontext libunwind_get_registers frameheadercache_test)
if (LIBUNWIND_TEST_CXX_ABI_LIB)
  list(APPEND _LIBUNWIND_TESTS thread_unwind simple_exceptions simple_exceptions2)
endif()
set(_LIBUNWIND_TEST_BINARIES)
# Building static binaries might not be supported (e.g. macOS, Ubunutu 16.04)
option(LIBUINWIND_BUILD_STATIC_TEST_BINARIES "build static test binaries" ON)
foreach(_opt "" -O0 -O1 -O2 -O3)
  set(_suffix ${_opt})
  foreach(_test ${_LIBUNWIND_TESTS})
    string(REGEX MATCH ".*exceptions.*" _has_exceptions ${_test})
    if (_has_exceptions)
      set(_common_libs ${_cxx_abi_link_flag} -lpthread -lc -lpthread -ldl)
      set(_common_flags -fexceptions)
    else()
      set(_common_libs -lpthread -lc -lpthread -ldl)
      set(_common_flags -fno-exceptions)
    endif()
    # message(STATUS "NAME=test-${_test}-shared${_suffix}")
    if (LIBUNWIND_ENABLE_SHARED)
      add_executable(test-${_test}-shared${_suffix} EXCLUDE_FROM_ALL ${_test}.pass.cpp)
      target_link_libraries(test-${_test}-shared${_suffix} -nostdlib++ $<TARGET_FILE:unwind_shared> ${_common_libs} ${LIBUNWIND_LINK_FLAGS})
      target_compile_features(test-${_test}-shared${_suffix} PUBLIC cxx_std_11)
      target_compile_options(test-${_test}-shared${_suffix} PUBLIC ${_common_flags} ${LIBUNWIND_COMPILE_FLAGS})
      list(APPEND _LIBUNWIND_TEST_BINARIES test-${_test}-shared${_suffix})
      # Add all symbols to dynsymtab to improve test debugging
      set_target_properties(test-${_test}-shared${_suffix} PROPERTIES ENABLE_EXPORTS ON
                            BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "$ORIGIN/../lib")
    endif()
    if (LIBUNWIND_ENABLE_STATIC)
      add_executable(test-${_test}-static${_suffix} EXCLUDE_FROM_ALL ${_test}.pass.cpp)
      target_link_libraries(test-${_test}-static${_suffix} -nostdlib++ $<TARGET_FILE:unwind_static> ${_common_libs} ${LIBUNWIND_LINK_FLAGS})
      target_compile_features(test-${_test}-static${_suffix} PUBLIC cxx_std_11)
      target_compile_options(test-${_test}-static${_suffix} PUBLIC ${_common_flags} ${LIBUNWIND_COMPILE_FLAGS})
      list(APPEND _LIBUNWIND_TEST_BINARIES test-${_test}-static${_suffix})
      # Add all symbols to dynsymtab to improve test debugging
      set_target_properties(test-${_test}-static${_suffix} PROPERTIES ENABLE_EXPORTS ON)
    endif()
    if (NOT APPLE AND NOT WIN32 AND LIBUINWIND_BUILD_STATIC_TEST_BINARIES)
      add_executable(test-${_test}-allstatic${_suffix} EXCLUDE_FROM_ALL ${_test}.pass.cpp)
      target_link_libraries(test-${_test}-allstatic${_suffix} -nostdlib++ -static $<TARGET_FILE:unwind_static> ${_common_libs} ${LIBUNWIND_COMPILE_FLAGS})
      target_compile_features(test-${_test}-allstatic${_suffix} PUBLIC cxx_std_11)
      target_compile_options(test-${_test}-allstatic${_suffix} PUBLIC ${_common_flags} ${LIBUNWIND_LINK_FLAGS} -static)
      list(APPEND _LIBUNWIND_TEST_BINARIES test-${_test}-allstatic${_suffix})
      # Add all symbols to dynsymtab to improve test debugging
      set_target_properties(test-${_test}-allstatic${_suffix} PROPERTIES ENABLE_EXPORTS ON)
    endif()
  endforeach()
endforeach()

message(STATUS "TESTS: ${_LIBUNWIND_TEST_BINARIES}")
add_custom_target(unwind-test-binaries DEPENDS ${_LIBUNWIND_TEST_BINARIES})


if (NOT DEFINED LIBCXX_ENABLE_SHARED)
  set(LIBCXX_ENABLE_SHARED ON)
endif()

pythonize_bool(LIBUNWIND_BUILD_32_BITS)
pythonize_bool(LIBCXX_ENABLE_SHARED)
pythonize_bool(LIBUNWIND_ENABLE_SHARED)
pythonize_bool(LIBUNWIND_ENABLE_THREADS)
pythonize_bool(LIBUNWIND_TEST_ENABLE_EXCEPTIONS)
pythonize_bool(LIBUNWIND_USES_ARM_EHABI)
pythonize_bool(LIBUNWIND_USE_COMPILER_RT)
pythonize_bool(LIBUNWIND_BUILD_EXTERNAL_THREAD_LIBRARY)
set(LIBUNWIND_TARGET_INFO "libcxx.test.target_info.LocalTI" CACHE STRING
    "TargetInfo to use when setting up test environment.")
set(LIBUNWIND_EXECUTOR "${Python3_EXECUTABLE} ${LIBUNWIND_LIBCXX_PATH}/utils/run.py" CACHE STRING
    "Executor to use when running tests.")

set(AUTO_GEN_COMMENT "## Autogenerated by libunwind configuration.\n# Do not edit!")
set(SERIALIZED_LIT_PARAMS "# Lit parameters serialized here for llvm-lit to pick them up\n")

macro(serialize_lit_param param value)
  string(APPEND SERIALIZED_LIT_PARAMS "config.${param} = ${value}\n")
endmacro()

serialize_lit_param(enable_experimental False)

if (LLVM_USE_SANITIZER)
  serialize_lit_param(use_sanitizer "\"${LLVM_USE_SANITIZER}\"")
endif()

if (LIBUNWIND_TARGET_TRIPLE)
  serialize_lit_param(target_triple "\"${LIBUNWIND_TARGET_TRIPLE}\"")
endif()

if (LIBUNWIND_BUILD_32_BITS)
  serialize_lit_param(enable_32bit True)
endif()

if (NOT LIBUNWIND_TEST_ENABLE_EXCEPTIONS)
  serialize_lit_param(enable_exceptions False)
endif()

foreach(param IN LISTS LIBUNWIND_TEST_PARAMS)
  string(REGEX REPLACE "(.+)=(.+)" "\\1" name "${param}")
  string(REGEX REPLACE "(.+)=(.+)" "\\2" value "${param}")
  serialize_lit_param("${name}" "\"${value}\"")
endforeach()

configure_lit_site_cfg(
  "${LIBUNWIND_TEST_CONFIG}"
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
  MAIN_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py")

add_lit_testsuite(check-unwind "Running libunwind tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS unwind ${LIBUNWIND_TEST_DEPS})
