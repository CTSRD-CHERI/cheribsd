/*-
 * Copyright (c) 2015 David Chisnall
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "cheri_c_test.h"
extern volatile __intcap_t tmp;
extern volatile __intcap_t one;
extern volatile __intcap_t two;
volatile __intcap_t tmp;
volatile __intcap_t one = 1;
volatile __intcap_t two = 2;

BEGIN_TEST(clang_purecap_intcap)
	char str[] = "0123456789";
	__intcap_t foo = 42;
	assert_eq(__builtin_cheri_tag_get((void*)foo), 0);
	assert_eq(__builtin_cheri_offset_get((void*)foo), 42);
	assert_eq(__builtin_cheri_base_get((void*)foo), 0);
	foo = (__intcap_t)str;
	assert_eq(__builtin_cheri_tag_get((void*)foo), 1);
	assert_eq(__builtin_cheri_tag_get((void*)foo), 1);
	foo += 5;
	assert_eq((*(char*)foo), '5');
	assert_eq(__builtin_cheri_offset_get((void*)foo), 5);
	assert_eq(__builtin_cheri_base_get((void*)foo), __builtin_cheri_base_get(str));
	assert_eq(__builtin_cheri_length_get((void*)foo), __builtin_cheri_length_get(str));
	foo += 50;
	// Ensure that the +50 is not removed
	tmp = foo;
	foo = tmp;
	foo -= 50;
	assert_eq((*(char*)foo), '5');
	assert_eq(__builtin_cheri_offset_get((void*)foo), 5);
	// Valid capabilities are not strictly ordered after invalid ones
	// We only compare the virtual address
	assert(0xffffffffffffffffULL > (__uintcap_t)foo);
	assert_eq_cap((void*)one, (void*)(__intcap_t)1);
	// When casted to an int it should always be one
	assert_eq((__uint64_t)one, (__uint64_t)1);
	// Also check the raw bytes to debug emulator issues:
	volatile __uint64_t* one_bytes = (volatile __uint64_t*)&one;
	// First 64 bits: compressed bounds in 128 / permissions in 256 -> zero
	assert_eq(one_bytes[0], 0);
	// Next 64 bits: cursor in all implementations
	assert_eq(one_bytes[1], 1);
	if (sizeof(__intcap_t) > 16) {
		// Remaining bytes should be zero
		assert_eq(one_bytes[2], 0);
		assert_eq(one_bytes[3], 0);
	}

	// Check that storing a capability always yields the same value back
	__intcap_t tmp2 = two;
	assert_eq_cap((void*)tmp2, (void*)(__intcap_t)2);
	assert_eq((__uint64_t)tmp2, 2);
	two = 3; // change the value
	assert_eq_cap((void*)two, (void*)(__intcap_t)3);
	assert_eq((__uint64_t)two, 3);
	two = tmp2; // restore old value
	assert_eq_cap((void*)two, (void*)(__intcap_t)2);
	assert_eq((__uint64_t)two, 2);
END_TEST
