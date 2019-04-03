/*-
 * Copyright (c) 2012-2014 David T. Chisnall
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

#ifndef _SIZE_T_DECLARED
typedef __SIZE_TYPE__ size_t;
#endif
// Currently, memcpy is called smemcpy.
// #define memcpy smemcpy

void * __capability cmemcpy_c(void * __capability dst,
                            const void * __capability src,
                            size_t len);
                       

void *cmemcpy(void *dst,
             const void *src,
             size_t len);

#define STANDALONE
#define CMEMCPY          
#include "memcpy.c"
#undef CMEMCPY
#define CMEMCPY_C
#include "memcpy.c"


// Test structure which will be memcpy'd.  Contains data and a capability in
// the middle.  The capability must be aligned, but memcpy should work for any
// partial copy of this structure that includes the capability, as long as both
// have the correct alignment.
struct Test 
{
	char pad0[32];
	void * __capability y;
	char pad1[32];
};

// Check that the copy has the data that we expect it to contain.  The start
// and end parameters describe the range in the padding to check.  For partial
// copies, the uncopied range will contain nonsense.
static void check(struct Test *t, int start, int end)
{
	for (int i=start ; i<32 ; i++)
	{
		assert(t->pad0[i] == i);
	}
	assert((__cheri_fromcap void*)t->y == t);
	assert(__builtin_cheri_tag_get(t->y));
	for (int i=0 ; i<end ; i++)
	{
		assert(t->pad1[i] == i);
	}
}

// Write an obviously invalid byte pattern over the output structure.
static void invalidate(struct Test *t1)
{
	unsigned char *x = (unsigned char*)t1;
	for (unsigned i=0 ; i<sizeof(*t1) ; i++)
	{
		*x = 0xa5;
	}
}

// Run the memcpy tests
BEGIN_TEST(clang_hybrid_memcpy)
	struct Test t1, t2;

	invalidate(&t2);
	for (int i=0 ; i<32 ; i++)
	{
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	t1.y = TO_CAP(&t2);
	invalidate(&t2);
	// Simple case: aligned start and end
	void * __capability cpy = cmemcpy_c(t1.y, TO_CAP(&t1), sizeof(t1));
	assert((__cheri_fromcap void*)cpy == &t2);
	check(&t2, 0, 32);
	invalidate(&t2);
	
	// Test that it still works with an unaligned start...
	cpy = cmemcpy_c(TO_CAP(&t2.pad0[3]), TO_CAP(&t1.pad0[3]), sizeof(t1) - 3);
	assert((__cheri_fromcap void*)cpy == &t2.pad0[3]);
	check(&t2, 3, 32);
	
	// ...or an unaligned end...
	cpy = cmemcpy_c(TO_CAP(&t2), TO_CAP(&t1), sizeof(t1) - 3);
	assert((__cheri_fromcap void*)cpy == &t2);
	check(&t2, 0, 29);
	
	// ...or both...
	cpy = cmemcpy_c(TO_CAP(&t2.pad0[3]), TO_CAP(&t1.pad0[3]), sizeof(t1) - 6);
	assert((__cheri_fromcap void*)cpy == &t2.pad0[3]);
	check(&t2, 3, 29);
	invalidate(&t2);
	// ...and finally a case where the alignment is different for both?
	cpy = cmemcpy_c(TO_CAP(&t2), TO_CAP(&t1.pad0[1]), sizeof(t1) - 1);
	assert((__cheri_fromcap void*)cpy == &t2);
	// This should have invalidated the capability
	assert(__builtin_cheri_tag_get(t2.y) == 0);
	
	// Check that the non-capability data has been copied correctly
	for (int i=0 ; i<31 ; i++)
	{
		assert(t2.pad0[i] == i+1);
		assert(t2.pad1[i] == i+1);
	}
	invalidate(&t2);
	// Simple case: aligned start and end
	DEBUG_DUMP_REG(13, 1);
	void *copy = cmemcpy(&t2, &t1, sizeof(t1));
	assert(copy == &t2);
	check(&t2, 0, 32);
	invalidate(&t2);
	// Test that it still works with an unaligned start...
	DEBUG_DUMP_REG(13, 2);
	copy = cmemcpy(&t2.pad0[3], &t1.pad0[3], sizeof(t1) - 3);
	assert(copy == &t2.pad0[3]);
	check(&t2, 3, 32);
	DEBUG_DUMP_REG(13, 3);
	// ...or an unaligned end...
	copy = cmemcpy(&t2, &t1, sizeof(t1) - 3);
	assert(copy == &t2);
	check(&t2, 0, 29);
	DEBUG_DUMP_REG(13, 4);
	// ...or both...
	copy = cmemcpy(&t2.pad0[3], &t1.pad0[3], sizeof(t1) - 6);
	assert(copy == &t2.pad0[3]);
	check(&t2, 3, 29);
	invalidate(&t2);
	DEBUG_DUMP_REG(13, 5);
	// ...and finally a case where the alignment is different for both?
	copy = cmemcpy(&t2, &t1.pad0[1], sizeof(t1) - 1);
	assert(copy == &t2);
	// This should have invalidated the capability
	assert(!__builtin_cheri_tag_get(t2.y));
	// Check that the non-capability data has been copied correctly
	for (int i=0 ; i<31 ; i++)
	{
		assert(t2.pad0[i] == i+1);
		assert(t2.pad1[i] == i+1);
	}
	
	// .. and finally finally tests that offsets are taken into
	// account when checking alignment.  These are regression tests
	// for a bug in cmemcpy_c.

	// aligned base, unaligned offset + base
	invalidate(&t2);
	cpy = cmemcpy_c(
		__builtin_cheri_offset_increment(TO_CAP(&t2), 3),
		__builtin_cheri_offset_increment(TO_CAP(&t1), 3),
		sizeof(t1)-6
		);
	assert((__cheri_fromcap void*)cpy == &t2.pad0[3]);
//	check(&t2, 3, 29);

	// unaligned base, aligned offset + base
	// FIXME: This currently gives an aligned base.  We should make the CAP
	// macro take a base and length so that it can do CIncBase / CSetLen on
	// CHERI256, CFromPtr / CSetBounds on CHERI128
	invalidate(&t2);
	cpy = cmemcpy_c(
		__builtin_cheri_offset_increment(TO_CAP(t2.pad0-1), 1),
		__builtin_cheri_offset_increment(TO_CAP(t1.pad0-1), 1),
		sizeof(t1)
		);
	assert((__cheri_fromcap void*)cpy == &t2.pad0);

	check(&t2, 0, 32);
	/*
	*/

	assert(faults == 0);
END_TEST

