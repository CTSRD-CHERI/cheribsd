/*-
 * Copyright (c) 2015 David Chisnall
 * Copyright (c) 2015 SRI International
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
#include <stdarg.h>
#include "cheri_c_test.h"

static char str[] = "012345678901234567890";
static volatile void *ptrs[] =
{
	&str[0],
	&str[1],
	&str[2],
	&str[3],
	&str[4],
	&str[5],
	&str[6],
	&str[7],
	&str[8],
	&str[9],
	&str[0],
	&str[11],
	&str[12],
	&str[13],
	&str[14],
	&str[15],
	&str[16],
	&str[17],
	&str[18],
	&str[19]
};
static int gint;

static void printstuff(int argpairs, ...)
{
	va_list ap;
	va_start(ap, argpairs);
	// Check that the length corresponds to the number of arguments, with
	// appropriate padding.
	assert_eq(__builtin_cheri_length_get(ap), argpairs * sizeof(void*) * 2);
	ASSERT_HAS_NOT_PERMISSION(ap, STORE);
	ASSERT_HAS_NOT_PERMISSION(ap, STORE_CAPABILITY);
	for (int i=0 ; i<argpairs ; i++)
	{
		int x = va_arg(ap, int);
		char *p = va_arg(ap, void*);
		assert_eq(x, i);
		assert(__builtin_cheri_tag_get(p));
		assert_eq_cap(p, __DEVOLATILE(const void*, ptrs[i]));
		assert_eq(*p, str[i]);
	}
	va_end(ap);
}

typedef void (*inc_t)(void);

static void inc(void)
{
	gint++;
}

static void check_fp(int intarg, ...)
{
	inc_t incfp;
	va_list ap;
	va_start(ap, intarg);
	// Check that we've been passed a single function pointer sized argument
#ifdef INCLUDE_XFAIL
	assert_eq(__builtin_cheri_length_get(ap), sizeof(void *));
	incfp = va_arg(ap, inc_t);
	for (int i = 0; i < intarg; i++)
		incfp();
	assert_eq(gint, intarg);
#else
	(void)incfp;
#endif
	va_end(ap);
}

BEGIN_TEST(clang_purecap_va_args)
	printstuff(8, 0,ptrs[0],1,ptrs[1],2,ptrs[2],3,ptrs[3],4,ptrs[4],5,ptrs[5],6,ptrs[6],7,ptrs[7]);
	check_fp(3, &inc);
	assert_eq(faults, 0);
END_TEST
