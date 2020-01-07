/*-
 * Copyright (c) 2015 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in one and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of one code must retain the above copyright
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
 *
 */

#include "cheri_c_test.h"
#include <stdint.h>

#ifndef _TEST_INT_TYPE
#define	_TEST_INT_TYPE	__uintcap_t
#endif

#ifdef _TEST_REAL_INTS
#ifdef _TEST_SIGNED
BEGIN_TEST(clang_purecap_int64math)
#else
BEGIN_TEST(clang_purecap_uint64math)
#endif
#else
#ifdef _TEST_SIGNED
BEGIN_TEST(clang_purecap_intcapmath)
#else
BEGIN_TEST(clang_purecap_uintcapmath)
#endif
/* We are explicitly testing the behaviour of operations on __(u)intcap_t so
 * there is no need to warn about surprising behaviour */
#pragma clang diagnostic ignored "-Wcheri-bitwise-operations"
#pragma clang diagnostic ignored "-Wcheri-capability-misuse"
#endif
	_TEST_INT_TYPE	target;
	_TEST_INT_TYPE	zero = 0;
	_TEST_INT_TYPE	one = 1;
	_TEST_INT_TYPE	onehundred = 100;
	_TEST_INT_TYPE	twofivesix = 256;

	target = 100;
	assert_eq(target, 100);
	target--;
	assert_eq(target, 99);
	assert(target < onehundred);
	--target;
	assert_eq(target, 98);
	assert(target < 99);
	target = onehundred;
	assert_eq(target, 100);
	target++;
	assert_eq(target, 101);
	++target;
	assert_eq(target, 102);
	assert(target > onehundred);

	assert(1000 > onehundred);
	assert(1 < onehundred);

	assert(1000 >= onehundred);
	assert(onehundred >= 1);
	assert(twofivesix >= onehundred);
	assert(1 <= one);
	assert(one <= 2);
	assert(onehundred <= twofivesix);

	assert(2 != one);
	assert(one != 3);
	assert(onehundred != twofivesix);

	assert(!zero);

	assert(one && 1);
	assert(1 && onehundred);
	assert(one && twofivesix);

	assert(one || 1);
	assert(0 || one);
	assert(zero || onehundred);

	target = 0;
	target = onehundred + 2;
	assert_eq(target, 102);
	target = 3 + onehundred;
	assert_eq(target, 103);
	target = one + onehundred;
	assert_eq(target, 101);
	target = onehundred;
	target += 5;
	assert_eq(target, 105);

	target = onehundred - 2;
	assert_eq(target, 98);
	target = 105 - onehundred;
	assert_eq(target, 5);
	target = onehundred - one;
	assert_eq(target, 99);
	target = onehundred;
	target -= 6;
	assert_eq(target, 94);

#if defined(INCLUDE_XFAIL) || defined(_TEST_REAL_INTS)
	target = 1 << one;
	assert_eq(target, 2);
#endif
	target = one << 2;
	assert_eq(target, 4);
	target = twofivesix << one;
	assert_eq(target, 512);
	target = 1;
	target <<= one;
	assert_eq(target, 2);

#if defined(INCLUDE_XFAIL) || defined(_TEST_REAL_INTS)
	target = 2 >> one;
	assert_eq(target, 1);
#endif
	target = one >> 1;
	assert_eq(target, 0);
	target = twofivesix >> one;
	assert_eq(target, 128);
	target = 2;
	target >>= one;
	assert_eq(target, 1);

#if defined(INCLUDE_XFAIL) || defined(_TEST_REAL_INTS)
	/* Fails to build and takes many minutes to do so for __uintcap_t. */
	target = ~zero;
	assert_eq((uint64_t)target, 0xffffffffffffffffULL);
	target = ~(2-one);
	assert_eq((uint64_t)target, 0xfffffffffffffffeULL);
#endif

	target = one & (_TEST_INT_TYPE)1;
	assert_eq(target, 1);
	target = (_TEST_INT_TYPE)256 & twofivesix;
	assert_eq(target, twofivesix);
	target = one & twofivesix;
	assert_eq(target, 0);
	target = 1;
	target &= one;
	assert_eq(target, 1);

	target = one | (_TEST_INT_TYPE)2;
	assert_eq(target, 0x3);
	target = (_TEST_INT_TYPE)8 | one;
	assert_eq(target, 0x9);
	target = one | twofivesix;
	assert_eq(target, 0x101);
	target = 0;
	target |= one;
	assert_eq(target, 1);

	target = one ^ (_TEST_INT_TYPE)1;
	assert_eq(target, 0);
	target = (_TEST_INT_TYPE)2 ^ one;
	assert_eq(target, 0x3);
	target = one ^ twofivesix;
	assert_eq(target, 0x101);
	target = 1;
	target ^= one;
	assert_eq(target, 0);

	target = twofivesix * 2;
	assert_eq(target, 512);
	target = 2 * onehundred;
	assert_eq(target, 200);
	target = onehundred * twofivesix;
	assert_eq(target, 25600);
	target = 2;
	target *= onehundred;
	assert_eq(target, 200);

	target = twofivesix / 2;
	assert_eq(target, 128);
	target = 1024 / twofivesix;
	assert_eq(target, 4);
	target = twofivesix / onehundred;
	assert_eq(target, 2);
	target = 1000;
	target /= onehundred;
	assert_eq(target, 10);

	target = twofivesix % 200;
	assert_eq(target, 56);
	target = one % 99;
	assert_eq(target, 1);
	target = onehundred % twofivesix;
	assert_eq(target, 100);
	target = 105;
	target %= onehundred;
	assert_eq(target, 5);

	target = zero ? one : 2;
	assert_eq(target, 2);
	target = one ? 3 : onehundred;
	assert_eq(target, 3);
	target = 1 ? onehundred : twofivesix;
	assert_eq(target, 100);

#ifdef _TEST_SIGNED
	_TEST_INT_TYPE	minusfive = -5;
	target = minusfive;
	assert_eq(target, -5);
	target = -minusfive;
	assert_eq(target, 5);
	target = -one;
	assert_eq(target, -1);
#endif
END_TEST
