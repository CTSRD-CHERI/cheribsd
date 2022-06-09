//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// UNSUPPORTED: libcpp-has-no-threads
// ALLOW_RETRIES: 2

// <mutex>

// class recursive_timed_mutex;

// template <class Rep, class Period>
//     bool try_lock_for(const chrono::duration<Rep, Period>& rel_time);

#include <mutex>
#include <thread>
#include <cstdlib>
#include <cassert>

#include "make_test_thread.h"
#include "test_macros.h"

std::recursive_timed_mutex m;

typedef std::chrono::steady_clock Clock;
typedef Clock::time_point time_point;
typedef Clock::duration duration;
typedef std::chrono::milliseconds ms;
typedef std::chrono::nanoseconds ns;

// Tolerance of 50ms (or 250ms on slow hosts)
static ns Tolerance = ns(TEST_SLOW_HOST()? 200000000 : 50000000);
static ms DelayLong = ms(TEST_SLOW_HOST()? 800 : 300);
static ms DelayShort = ms(TEST_SLOW_HOST()? 500 : 250);

void f1()
{
    time_point t0 = Clock::now();
    assert(m.try_lock_for(DelayLong) == true);
    time_point t1 = Clock::now();
    assert(m.try_lock());
    m.unlock();
    m.unlock();
    // Should get the lock after the main thread slept for DelayShort and released the lock
    ns d = t1 - t0 - ms(DelayShort);
    assert(d < Tolerance);  // within 50ms
}

void f2()
{
    time_point t0 = Clock::now();
    // Main thread sleeping longer than DelayShort -> should fail to get the lock
    // after DelayShort + Tolerance milliseconds
    assert(m.try_lock_for(DelayShort) == false);
    time_point t1 = Clock::now();
    ns d = t1 - t0 - ms(DelayShort);
    assert(d < Tolerance);  // within 50ms
}

int main(int, char**)
{
    {
        m.lock();
        std::thread t = support::make_test_thread(f1);
        std::this_thread::sleep_for(DelayShort);
        m.unlock();
        t.join();
    }
    {
        m.lock();
        std::thread t = support::make_test_thread(f2);
        std::this_thread::sleep_for(DelayLong);
        m.unlock();
        t.join();
    }

  return 0;
}
