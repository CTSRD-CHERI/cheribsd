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
#define NAME hybrid_i8
#include "store_test.h"
#define TYPE unsigned char
#define NAME hybrid_u8
#include "store_test.h"
#define TYPE signed short
#define NAME hybrid_i16
#include "store_test.h"
#define TYPE unsigned short
#define NAME hybrid_u16
#include "store_test.h"
#define TYPE signed int
#define NAME hybrid_i32
#include "store_test.h"
#define TYPE unsigned int
#define NAME hybrid_u32
#include "store_test.h"
#define TYPE signed long long
#define NAME hybrid_i64
#include "store_test.h"
#define TYPE unsigned long long
#define NAME hybrid_u64
#include "store_test.h"

BEGIN_TEST(clang_hybrid_store_data)
	hybrid_u8_test();
	hybrid_i8_test();
	hybrid_u16_test();
	hybrid_i16_test();
	hybrid_u32_test();
	hybrid_i32_test();
	hybrid_u64_test();
	hybrid_i64_test();

	assert(faults == 0);
END_TEST
