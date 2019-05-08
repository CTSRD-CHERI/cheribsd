/*-
 * Copyright (c) 2015 Michael Roe
 * All rights reserved.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the Rigorous Engineering of Mainstream Systems (REMS)
 * project, funded by EPSRC grant EP/K008528/1.
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
 * Test subtraction of capabilities
 *
 * If both capabilities are pointers into the same object (e.g. an array)
 * then subtraction should return the difference between the array indices.
 */

#include "cheri_c_test.h"

static const char *str = "0123456789ABCDEF";

BEGIN_TEST(clang_hybrid_sub)

	const char * __capability a;
	const char * __capability b;
	int x;

	a = (__cheri_tocap const char * __capability) str;
        b = a + 5;
        x = b - a;
	assert(x == 5);
	assert(faults == 0);
END_TEST
