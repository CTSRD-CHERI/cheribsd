//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// UNSUPPORTED: libcpp-has-no-threads

// FLAKY_TEST.

// <mutex>

// class mutex;

// void lock();

#include <mutex>
#include <thread>
#include <cstdlib>
#include <cassert>

#include <iostream>

std::mutex m;

typedef std::chrono::system_clock Clock;
typedef Clock::time_point time_point;
typedef Clock::duration duration;
typedef std::chrono::milliseconds ms;
typedef std::chrono::nanoseconds ns;

#if !defined(TEST_SLOW_HOST)
ms WaitTime = ms(250);
ms Tolerance = ms(50)
#else
ms WaitTime = ms(750);
ms Tolerance = ms(200)
#endif

void f()
{
    time_point t0 = Clock::now();
    m.lock();
    time_point t1 = Clock::now();
    m.unlock();
    ns d = t1 - t0 - WaitTime;
    assert(d < Tolerance);  // within 50ms
}

int main(int, char**)
{
    m.lock();
    std::thread t(f);
    std::this_thread::sleep_for(WaitTime);
    m.unlock();
    t.join();

  return 0;
}
