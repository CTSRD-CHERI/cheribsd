/*-
 * Copyright (c) 2012-2015 David Chisnall
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

#ifndef NULL
#define NULL ((void*)0)
#endif

#pragma clang diagnostic ignored "-Wmissing-variable-declarations"

_Atomic(char) c;
_Atomic(short) h;
_Atomic(int) w;
_Atomic(long long) d;
_Atomic(int*) p = NULL;

_Atomic(char) *cp = &c;
_Atomic(short) *hp = &h;
_Atomic(int) *wp = &w;
_Atomic(long long) *dp = &d;
_Atomic(int*) *pp = &p;

BEGIN_TEST(clang_purecap_atomic)
	assert_eq(__builtin_cheri_length_get(cp), sizeof(c));
	assert_eq(__builtin_cheri_length_get(hp), sizeof(h));
	assert_eq(__builtin_cheri_length_get(wp), sizeof(w));
	assert_eq(__builtin_cheri_length_get(dp), sizeof(d));
	c++;
	h++;
	w++;
	d++;
	(*cp)++;
	(*hp)++;
	(*wp)++;
	(*dp)++;
	assert_eq(c, 2);
	assert_eq(h, 2);
	assert_eq(w, 2);
	assert_eq(d, 2);

	// Test operations on pointers:
	assert_eq(__builtin_cheri_length_get(pp), sizeof(p));
	int newval;
	assert_eq_cap(p, NULL);
#if 0
	void* old_value = __c11_atomic_fetch_add(&p, 1, __ATOMIC_SEQ_CST);
	assert_eq_cap(old_value, NULL);
#else
	p = (void*)(__uintcap_t)1;
#endif
	assert_eq_cap(p, (void*)(__uintcap_t)1);
	int* expected = (int*)(__uintcap_t)1;
	assert(__c11_atomic_compare_exchange_strong(&p, &expected, (void*)&newval, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
	assert_eq_cap(p, &newval);
	int* xchg_value = __c11_atomic_exchange(&p, (void*)(__uintcap_t)2, __ATOMIC_SEQ_CST);
	assert_eq_cap(xchg_value, (void*)&newval);
	assert_eq_cap(p, (void*)(__uintcap_t)2);
	__c11_atomic_store(&p, (void*)(__uintcap_t)3, __ATOMIC_SEQ_CST);
	assert_eq_cap(p, (void*)(__uintcap_t)3);


END_TEST

