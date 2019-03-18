/*-
 * Copyright (c) 2014 Michael Roe
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

/*
 * Test store to an unaligned element of a packed struct.
 *
 * clang will compile the assignment to x.b into swl and swr instructions.
 */

#include "cheri_c_test.h"

#pragma pack(1)
struct packed_s {
  char a;
  int b;
  char c;
};

static volatile struct packed_s x;

__attribute__((noinline)) static void check_struct()
{
/*
 * This test has been disabled by ifdef'ing out the assertions.
 * 
 * This test should work with the upstream clang/LLVM for MIPS, because
 * that compiler will use the special instructions for unaligned accesses.
 *
 * The CHERI-modified clang, on the other hand, does not use the unaligned
 * load/store instructions, and instead expects the load to be emulated by
 * the operating system. However, this test runs on bare metal and there is
 * no o[erating system to emulate the unaligned access, so it will fail on
 * a standard MIPS CPU, CHERI2, and the formal model.
 *
 * CHERI1 has an oprion to allow unaligned accesses as long as they lie
 * within a single cache line, so this test might work on CHERI1.
 *
 * XXX-LPT: test re-enabled for use under the OS.
 *
 * XXX-LPT: does this test need a __capability annotation?
 */

  assert(x.a == 0x00);
  assert(x.b == 0x01020304);
  assert(x.c == 0x05);
}

BEGIN_TEST(clang_hybrid_pack)

  x.a = 0x00;
  x.c = 0x05;
  x.b = 0x01020304;

  check_struct();

  assert(faults == 0);
END_TEST
