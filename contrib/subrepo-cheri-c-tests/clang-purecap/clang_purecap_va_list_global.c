/*-
 * Copyright (c) 2018 Alex Richardson
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

// Should have one trap (dereferencing one arg too many)
#define TEST_EXPECTED_FAULTS 1
#include "cheri_c_test.h"
#include <stdarg.h>
#include <stddef.h>


/* Check that the crazy stuff libxo does (storing va_list and using later works) */
struct print_info {
    va_list vap;
    int num_args;
};

const char* arg1 = "arg1";

const char* arg2 = "arg2";

struct print_info global_info;

void print_impl(struct print_info* info)
{
	DEBUG_MSG("Called print_impl!");
	assert_eq(info->num_args, 3);
	// the va_list should contain two elements and have offset 0
	assert_eq(__builtin_cheri_length_get((void*)info->vap), sizeof(void*) * 2);
	assert_eq(__builtin_cheri_offset_get((void*)info->vap), 0);
	for (int i = 0; i < info->num_args; i++) {
		// before va_arg the va_list should point to the object we are about to load
		assert_eq(__builtin_cheri_offset_get((void*)info->vap), sizeof(void*) * i);
		char* cp = va_arg(info->vap, char *);
		// va_arg should advance the va_list forward
		assert_eq(__builtin_cheri_offset_get((void*)info->vap), sizeof(void*) * (i + 1));
		assert(cp != NULL);
		assert(*cp != '\0'); // this should trap on the third iteration
		if (i == 2) {
			assert_eq(faults, 1);
			// offset of the va_list should now be equal to the length (past end)
			assert_eq(__builtin_cheri_offset_get((void*)info->vap), __builtin_cheri_length_get((void*)info->vap) + sizeof(void*));
			break;
		}
		assert_eq(cp[0], 'a');
		assert_eq(cp[1], 'r');
		assert_eq(cp[2], 'g');
		assert_eq(cp[3], '1' + i);
		DEBUG_MSG(cp);
	}
	assert_eq(faults, 1);
}

static void printstuff(int num_args, ...)
{
	DEBUG_MSG("Called printstuff!");
	// Store in a global: see xo_emit
	struct print_info* pi = &global_info;
	pi->num_args = num_args;
	va_start(pi->vap, num_args);
	print_impl(pi);
	va_end(pi->vap);
	// va_list should be past the end now since we trapped:
	assert_eq(__builtin_cheri_offset_get((void*)pi->vap), __builtin_cheri_length_get((void*)pi->vap) + sizeof(void*));
	__builtin_memset(&pi->vap, 0, sizeof(pi->vap));
}

BEGIN_TEST(clang_purecap_va_list_global)
	// THere are only two args so it should die after the second one
	printstuff(3, "arg1", "arg2");
END_TEST
