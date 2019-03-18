/*-
 * Copyright (c) 2014 David T. Chisnall
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
#define TEST_EXPECTED_FAULTS 2
#include "cheri_c_test.h"

int buffer[42];

BEGIN_TEST(clang_hybrid_cursor_trivial)
	int * __capability b = (__cheri_tocap int * __capability)&buffer[0];
	long long count = faults;
	b[41] = 12;
	// Explicitly set the length of the capability, in case the compiler
	// fails.
	volatile int * __capability v = __builtin_cheri_bounds_set(b,
		sizeof(buffer));
	// Set the cursor past the end and check that dereferencing fires an
	// exception.
	v = __builtin_cheri_offset_increment(__DEVOLATILE(void * __capability, v),
		42*sizeof(int));
	int unused = *v;
	assert(faults == count+1);
	// Move the cursor back into range and check that it works
	v = __builtin_cheri_offset_increment(__DEVOLATILE(void * __capability, v),
		(-1)*sizeof(int));
	assert(*v == 12);
	// Set the cursor before the start and check that dereferencing fires
	// an exception
	v = __builtin_cheri_offset_set(__DEVOLATILE(void * __capability, v), -1);
	unused = *v;
	assert(faults == count+2);
	// Move the cursor back into range and check that it works
	// XXX: This might not work with imprecise capabilities, as the
	// base might be lower than the start of the array.
	v = __builtin_cheri_offset_set(__DEVOLATILE(void * __capability, v), 41*sizeof(int));
	assert(*v == 12);

	assert(faults == 2);
END_TEST
