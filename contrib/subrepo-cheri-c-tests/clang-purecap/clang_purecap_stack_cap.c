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
extern const unsigned int sizes[];
const unsigned int sizes[] = {
	131072, 262144, 1048576
};
volatile void* ptrs[3];

__noinline static void check_overlap(void *a, void*b)
{
	unsigned long long basea = __builtin_cheri_base_get(a);
	unsigned long long baseb = __builtin_cheri_base_get(b);
	unsigned long long topa = basea + __builtin_cheri_length_get(a);
	unsigned long long topb = baseb + __builtin_cheri_length_get(b);
	assert((basea >= topb) || (baseb >= topa));
}

__noinline static void check_sizes(void)
{
	for (unsigned int i=0 ; i<sizeof(sizes)/sizeof(sizes[0]) ; i++)
	{
		assert(__builtin_cheri_length_get(__DEVOLATILE(void*, ptrs[i])) >= sizes[i]);
	}
}

BEGIN_TEST(clang_purecap_stack_cap)
	char foo[sizes[0]], bar[sizes[1]], baz[sizes[2]];
	ptrs[0] = foo;
	ptrs[1] = bar;
	ptrs[2] = baz;
	// Check that, even with alignment padding, none of the stack allocations overlap
	check_overlap(foo, bar);
	check_overlap(bar, baz);
	check_overlap(foo, baz);
	// Check that we have as much space as we asked for.
	check_sizes();
END_TEST

