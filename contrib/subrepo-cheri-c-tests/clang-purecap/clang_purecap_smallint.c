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

/* This use of the offset field works fine -> silence warning */
#pragma clang diagnostic ignored "-Wcheri-bitwise-operations"

typedef union {
	void *ptr;
	__uintcap_t intptr;
} PtrIntPair;

__noinline static unsigned get_int(PtrIntPair p)
{
	return p.intptr & (__uintcap_t)7;
}

__noinline static PtrIntPair set_int(PtrIntPair p, int val)
{
	val &= 7;
	p.intptr &= (__uintcap_t)~7LL;
	p.intptr ^= (__uintcap_t)val;
	return p;
}

__noinline static void *get_pointer(PtrIntPair p)
{
	return (void*)(p.intptr & (__uintcap_t)~7LL);
}

BEGIN_TEST(clang_purecap_smallint)
	_Alignas(8) char str[] = "123456789";
	PtrIntPair p;
	p.ptr = str;
	assert_eq(__builtin_cheri_address_get(p.ptr) & 7, 0); // must be aligned
	p = set_int(p, 4);
	assert_eq(get_int(p), 4);
	char *ptr = get_pointer(p);
	assert_eq_cap(ptr, str);
	assert_eq(ptr[0], '1');
END_TEST
