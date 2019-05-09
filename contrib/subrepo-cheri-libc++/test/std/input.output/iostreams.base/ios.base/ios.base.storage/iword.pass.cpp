//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// <ios>

// class ios_base

// long& iword(int idx);

// This test compiles but never completes when compiled against the MSVC STL
// UNSUPPORTED: msvc

#include <ios>
#include <string>
#include <cassert>

#include "test_macros.h"

class test
    : public std::ios
{
public:
    test()
    {
        init(0);
    }
};

int main(int, char**)
{
    test t;
    std::ios_base& b = t;
#if TEST_SLOW_HOST()
    for (std::intptr_t i = 0; i < 500; ++i)
#else
    for (std::intptr_t i = 0; i < 10000; ++i)
#endif
    {
        assert(b.iword(i) == 0);
        b.iword(i) = i;
        assert(b.iword(i) == i);
        for (int j = 0; j <= i; ++j)
            assert(b.iword(j) == j);
    }

  return 0;
}
