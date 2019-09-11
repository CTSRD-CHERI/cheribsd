//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// <stddef.h>

#include <stddef.h>
#include <cassert>
#include <type_traits>

#include "test_macros.h"

#ifndef NULL
#error NULL not defined
#endif

#ifndef offsetof
#error offsetof not defined
#endif

int main(int, char**)
{
    void *p = NULL;
    assert(!p);
#ifdef __CHERI_PURE_CAPABILITY__
    static_assert(sizeof(vaddr_t) == (__CHERI_ADDRESS_BITS__ / __CHAR_BIT__),
                  "Bad vaddr_t size");
    static_assert(std::is_unsigned<vaddr_t>::value,
                  "std::is_unsigned<size_t>::value");
    static_assert(std::is_integral<vaddr_t>::value,
                  "std::is_integral<size_t>::value");
    static_assert(sizeof(size_t) == sizeof(vaddr_t),
              "sizeof(size_t) == sizeof(vaddr_t)");
#else
    static_assert(sizeof(size_t) == sizeof(void*),
                  "sizeof(size_t) == sizeof(void*)");
#endif
    static_assert(std::is_unsigned<size_t>::value,
                  "std::is_unsigned<size_t>::value");
    static_assert(std::is_integral<size_t>::value,
                  "std::is_integral<size_t>::value");
#ifdef __CHERI_PURE_CAPABILITY__
    static_assert(sizeof(ptrdiff_t) == sizeof(vaddr_t),
              "sizeof(ptrdiff_t) == sizeof(vaddr_t)");
#else
    static_assert(sizeof(ptrdiff_t) == sizeof(void*),
                  "sizeof(ptrdiff_t) == sizeof(void*)");
#endif
    static_assert(std::is_signed<ptrdiff_t>::value,
                  "std::is_signed<ptrdiff_t>::value");
    static_assert(std::is_integral<ptrdiff_t>::value,
                  "std::is_integral<ptrdiff_t>::value");
    static_assert((std::is_same<decltype(nullptr), nullptr_t>::value),
                  "decltype(nullptr) == nullptr_t");
    static_assert(sizeof(nullptr_t) == sizeof(void*),
                  "sizeof(nullptr_t) == sizeof(void*)");
#if TEST_STD_VER > 17
//   P0767
    static_assert(std::is_trivial<max_align_t>::value,
                  "std::is_trivial<max_align_t>::value");
    static_assert(std::is_standard_layout<max_align_t>::value,
                  "std::is_standard_layout<max_align_t>::value");
#else
    static_assert(std::is_pod<max_align_t>::value,
                  "std::is_pod<max_align_t>::value");
#endif
    static_assert((std::alignment_of<max_align_t>::value >=
                  std::alignment_of<long long>::value),
                  "std::alignment_of<max_align_t>::value >= "
                  "std::alignment_of<long long>::value");
    static_assert(std::alignment_of<max_align_t>::value >=
                  std::alignment_of<long double>::value,
                  "std::alignment_of<max_align_t>::value >= "
                  "std::alignment_of<long double>::value");
    static_assert(std::alignment_of<max_align_t>::value >=
                  std::alignment_of<void*>::value,
                  "std::alignment_of<max_align_t>::value >= "
                  "std::alignment_of<void*>::value");

  return 0;
}
