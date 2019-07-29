//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// UNSUPPORTED: libcpp-has-no-threads
// UNSUPPORTED: c++98, c++03
// FLAKY_TEST.
// <future>

// class future<R>

// template <class Rep, class Period>
//   future_status
//   wait_for(const chrono::duration<Rep, Period>& rel_time) const;

#include <future>
#include <cassert>

#include "test_macros.h"

typedef std::chrono::milliseconds ms;

static ms DelayShort = ms(TEST_SLOW_HOST() ? 600 : 300);
static ms DelayLong = ms(TEST_SLOW_HOST() ? 1000 : 500);
static ms Tolerance = ms(TEST_SLOW_HOST() ? 200 : 50);

void func1(std::promise<int> p)
{
    std::this_thread::sleep_for(DelayLong);
    p.set_value(3);
}

int j = 0;

void func3(std::promise<int&> p)
{
    std::this_thread::sleep_for(DelayLong);
    j = 5;
    p.set_value(j);
}

void func5(std::promise<void> p)
{
    std::this_thread::sleep_for(DelayLong);
    p.set_value();
}

int main(int, char**)
{
    typedef std::chrono::high_resolution_clock Clock;
    {
        typedef int T;
        std::promise<T> p;
        std::future<T> f = p.get_future();
        std::thread(func1, std::move(p)).detach();
        assert(f.valid());
        assert(f.wait_for(DelayShort) == std::future_status::timeout);
        assert(f.valid());
        assert(f.wait_for(DelayShort) == std::future_status::ready);
        assert(f.valid());
        Clock::time_point t0 = Clock::now();
        f.wait();
        Clock::time_point t1 = Clock::now();
        assert(f.valid());
        assert(t1-t0 < Tolerance);
    }
    {
        typedef int& T;
        std::promise<T> p;
        std::future<T> f = p.get_future();
        std::thread(func3, std::move(p)).detach();
        assert(f.valid());
        assert(f.wait_for(DelayShort) == std::future_status::timeout);
        assert(f.valid());
        assert(f.wait_for(DelayShort) == std::future_status::ready);
        assert(f.valid());
        Clock::time_point t0 = Clock::now();
        f.wait();
        Clock::time_point t1 = Clock::now();
        assert(f.valid());
        assert(t1-t0 < Tolerance);
    }
    {
        typedef void T;
        std::promise<T> p;
        std::future<T> f = p.get_future();
        std::thread(func5, std::move(p)).detach();
        assert(f.valid());
        assert(f.wait_for(DelayShort) == std::future_status::timeout);
        assert(f.valid());
        assert(f.wait_for(DelayShort) == std::future_status::ready);
        assert(f.valid());
        Clock::time_point t0 = Clock::now();
        f.wait();
        Clock::time_point t1 = Clock::now();
        assert(f.valid());
        assert(t1-t0 < Tolerance);
    }

  return 0;
}
