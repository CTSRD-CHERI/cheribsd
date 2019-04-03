/*-
 * Copyright (c) 2013 Michael Roe
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#include "cheri_c_test.h"

/*
 * Test that a C program can read a floating point value via a capability,
 *
 * To make sure that the floating point number gets as far as the FPU
 * (not just into an integer register) we do some arithmetic on it - summing
 * the values from 1 to 4.
 *
 * This test will succeed without attempting any floating point if it is
 * run on a CPU that does not have floating point hardware (as determined by
 * the CP0.Config1 register).
 */

/*
 * Read coprocessor 0 config1 register to find out if the CPU has hardware
 * floating point.
 */

__unused static long get_config_reg()
{
  unsigned long val;

  asm volatile ("dmfc0 %0, $16, 1" : "=r"(val));

  return val;
}

static float array[4] = {
    1.0,
    2.0,
    3.0,
    4.0
};

static __attribute__((noinline)) int test_body(void)
{
int i;
float total;
float * __capability fp;

    fp = (__cheri_tocap float * __capability)&array[0];
    total = 0.0;
    for (i=0; i<4; i++)
    {
      total += *fp;
      fp++;
    }

    assert(total == 10.0);

    return 0;
}

BEGIN_TEST(clang_hybrid_load_float)
// dmfc0 can only be used in the kernel (or baremetal). This test should
// also work fine for soft-float.
#ifdef _KERNEL
  long config1 = get_config_reg();
  if (config1 & 0x1)
    test_body();
  else
    assert(1);
#else
  test_body();
#endif
  assert(faults == 0);
END_TEST
