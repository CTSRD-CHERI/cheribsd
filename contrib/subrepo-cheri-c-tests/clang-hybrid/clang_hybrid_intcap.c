/*-
 * Copyright (c) 2015 Michael Roe
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

static __intcap_t x;

static void increment()
{
	x++;
}

static const char *digits = "0123456789";

BEGIN_TEST(clang_hybrid_intcap)
	const char *__capability cp;

	x = 1;
	increment();
	assert(x == 2);

	cp = (__cheri_tocap const char * __capability) digits;
	x = (__intcap_t) cp;
	increment();
	cp = (const char * __capability) x;
	assert(*cp == '1');
	assert(faults == 0);
END_TEST
