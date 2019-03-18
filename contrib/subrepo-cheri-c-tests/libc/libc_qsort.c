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
#include <stdlib.h>
#include <string.h>

const char *array[] = { "c", "d", "b", "a", "f", "e", "g" };
struct dict_entry
{
	int key;
	const char *value;
};

struct dict_entry array1[] =
{
	{2, "c"},
	{3, "d"},
	{1, "b"},
	{0, "a"},
	{5, "f"},
	{4, "e"},
	{6, "g"},
};

static int compare(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int compare1(const void *a, const void *b)
{
	const struct dict_entry *k1 = a;
	const struct dict_entry *k2 = b;
	return strcmp(k1->value, k2->value);
}

BEGIN_TEST(libc_qsort)
	for (unsigned int i=0 ; i<(sizeof(array)/sizeof(array[0])) ; i++)
	{
		assert_eq(__builtin_cheri_tag_get(array[i]), 1);
		assert_eq(__builtin_cheri_tag_get(array1[i].value), 1);
	}
	// Check that sorting capabilities works
	qsort(array, 7, sizeof(void*), compare);
	// Check that sorting large(ish) structs containing capabilities works
	qsort(array1, 7, sizeof(struct dict_entry), compare1);
	for (unsigned int i=0 ; i<(sizeof(array)/sizeof(array[0])) ; i++)
	{
		assert_eq(__builtin_cheri_tag_get(array[i]), 1);
		assert_eq(__builtin_cheri_tag_get(array1[i].value), 1);
		assert_eq(array[i][0], (size_t)('a' + i));
		assert_eq(array1[i].value[0], (size_t)('a' + i));
	}
END_TEST

