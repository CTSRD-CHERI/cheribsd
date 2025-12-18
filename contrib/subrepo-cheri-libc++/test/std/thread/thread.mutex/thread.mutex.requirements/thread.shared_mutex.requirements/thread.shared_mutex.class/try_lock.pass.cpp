//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// UNSUPPORTED: no-threads
// UNSUPPORTED: c++03, c++11, c++14

// ALLOW_RETRIES: 2

// UNSUPPORTED: availability-shared_mutex-missing

// <shared_mutex>

// class shared_mutex;

// bool try_lock();

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <shared_mutex>
#include <thread>

#include "make_test_thread.h"
#include "test_macros.h"

std::shared_mutex m;

typedef std::chrono::system_clock Clock;
typedef Clock::time_point time_point;
typedef Clock::duration duration;
typedef std::chrono::milliseconds ms;
typedef std::chrono::nanoseconds ns;

#if !defined(TEST_HAS_SANITIZERS) && !TEST_SLOW_HOST()
static ms main_thread_sleep_duration = ms(750);
static ms tolerance = ms(500);
#else
static ms main_thread_sleep_duration = ms(250);
static ms tolerance = ms(200);
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
    m.unlock();
    ns d = t1 - t0 - main_thread_sleep_duration;
    assert(d < tolerance);  // within 200ms (500ms on slow systems)
}

int main(int, char**)
{
    m.lock();
    std::thread t = support::make_test_thread(f);
    std::this_thread::sleep_for(main_thread_sleep_duration);
    m.unlock();
    t.join();

  return 0;
}
