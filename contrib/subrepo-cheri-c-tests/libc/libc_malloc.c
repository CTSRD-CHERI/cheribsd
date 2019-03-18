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
#include <stdlib.h>
#include "cheri_c_test.h"

#ifdef HAVE_MALLOC_USUABLE_SIZE
size_t malloc_usable_size(const void *ptr);
#endif

void check_allocation(void *a, unsigned long size)
{
	assert(__builtin_cheri_tag_get(a));
	assert(__builtin_cheri_length_get(a) - __builtin_cheri_offset_get(a) >= size);
#ifdef INCLUDE_XFAIL
	ASSERT_HAS_NOT_PERMISSION(a, EXECUTE);
#endif
	ASSERT_HAS_PERMISSION(a, STORE_CAPABILITY);
	ASSERT_HAS_PERMISSION(a, STORE);
	ASSERT_HAS_PERMISSION(a, LOAD_CAPABILITY);
	ASSERT_HAS_PERMISSION(a, LOAD);
	assert_eq(__builtin_cheri_offset_get(a), 0);
	// There must be enough for the object (more is permitted)
	assert(__builtin_cheri_length_get(a) >= size);
#ifdef HAVE_MALLOC_USUABLE_SIZE
	assert_eq(__builtin_cheri_length_get(a), malloc_usable_size(a));
#endif
	// If there is space for a pointer, the allocation must be aligned
	// sufficiently to hold one.
	if (size >= sizeof(void *))
		assert_eq((__builtin_cheri_base_get(a) & (sizeof(void*) - 1)), 0);
}

void check_size(long size)
{
	void *a = malloc(size);
	check_allocation(a, size);
	char *b = calloc(size, 1);
	check_allocation(b, size);
	for (int i = 0 ; i<size-1 ; i++)
	{
		assert_eq(b[i], 0);
	}
	free(a);
	free(b);
}

BEGIN_TEST(libc_malloc)
#ifdef SLOW_TESTS
	// Malloc and free are fast, but faulting in and checking that every page
	// really is zero is *very* slow.
	const int max = 27;
#else
	const int max = 20;
#endif
	for (int i=1; i <= max ; i++)
	{
		check_size(1<<i);
		check_size((1<<i) + 1);
	}
END_TEST
