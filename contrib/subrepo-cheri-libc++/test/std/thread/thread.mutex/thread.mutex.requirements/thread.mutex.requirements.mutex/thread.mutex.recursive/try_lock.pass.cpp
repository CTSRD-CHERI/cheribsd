//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// UNSUPPORTED: libcpp-has-no-threads
// ALLOW_RETRIES: 2

// <mutex>

// class recursive_mutex;

// bool try_lock();

#include <mutex>
#include <thread>
#include <cstdlib>
#include <cassert>

#include "make_test_thread.h"
#include "test_macros.h"

std::recursive_mutex m;

typedef std::chrono::system_clock Clock;
typedef Clock::time_point time_point;
typedef Clock::duration duration;
typedef std::chrono::milliseconds ms;
typedef std::chrono::nanoseconds ns;

#if !TEST_SLOW_HOST()
ms WaitTime = ms(250);
ms Tolerance = ms(200);
#else
ms WaitTime = ms(750);
ms Tolerance = ms(500);
#endif

void f()
{
    time_point t0 = Clock::now();
    assert(!m.try_lock());
    assert(!m.try_lock());
    assert(!m.try_lock());
    while(!m.try_lock())
        ;
    time_point t1 = Clock::now();
    assert(m.try_lock());
    m.unlock();
    m.unlock();
    ns d = t1 - t0 - WaitTime;
    assert(d < Tolerance);  // within 200ms
}

int main(int, char**)
{
    m.lock();
    std::thread t = support::make_test_thread(f);
    std::this_thread::sleep_for(WaitTime);
    m.unlock();
    t.join();

  return 0;
}
