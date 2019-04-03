/*-
 * Copyright (c) 2012 David T. Chisnall
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

#define TYPE signed char
#define NAME i8
#include "load_test.h"
#define TYPE unsigned char
#define NAME u8
#include "load_test.h"
#define TYPE signed short
#define NAME i16
#include "load_test.h"
#define TYPE unsigned short
#define NAME u16
#include "load_test.h"
#define TYPE signed int
#define NAME i32
#include "load_test.h"
#define TYPE unsigned int
#define NAME u32
#include "load_test.h"
#define TYPE signed long long
#define NAME i64
#include "load_test.h"
#define TYPE unsigned long long
#define NAME u64
#include "load_test.h"

BEGIN_TEST(clang_hybrid_load_data)
	u8_test();
	i8_test();
	u16_test();
	i16_test();
	u32_test();
	i32_test();
	u64_test();
	i64_test();
	assert(faults == 0);
END_TEST
