/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include "plt_test.h"
#include <stdbool.h>

extern void* _get_library_cgp_with_null_caller_cgp(void);

static inline bool exactly_equal(void* cap1, void* cap2) {
	bool result = false;
	__asm__ volatile("cexeq %0, %1, %2": "=r"(result) : "C"(cap1), "C"(cap2));
	return result;
}

typedef int (*get_global_int_type)(void);

extern get_global_int_type load_int_fnptr __hidden;

static void test(void) {
	print("Starting test!\n");
	uintcap_t c1 = 1;
	uintcap_t c2 = 2;
	require(exactly_equal((void*)c1, (void*)c1));
	require(!exactly_equal((void*)c1, (void*)c2));

	get_global_int_type fnptr_from_lib = get_load_global_int_fnptr_from_library();
	print("Inside library: "); print_cap(fnptr_from_lib); print("\n");
	get_global_int_type fnptr_from_global = load_int_fnptr;
	print("global variable: "); print_cap(fnptr_from_global); print("\n");
	get_global_int_type fnptr_local = &load_global_int;
	print("local variable: "); print_cap(fnptr_local); print("\n");

	require(exactly_equal(fnptr_from_lib, fnptr_from_global));
	require(exactly_equal(fnptr_from_lib, fnptr_local));
	require(exactly_equal(fnptr_local, fnptr_from_lib));
	require(exactly_equal(fnptr_local, fnptr_from_global));
	require(exactly_equal(fnptr_from_global, fnptr_from_lib));
	require(exactly_equal(fnptr_from_global, fnptr_local));

	// Now try calling them all
	int call_local_fnptr = ((get_global_int_type)fnptr_local)();
	require_eq(call_local_fnptr, 42);
	int call_global_fnptr = ((get_global_int_type)fnptr_from_global)();
	require_eq(call_global_fnptr, 42);
	int call_library_fnptr = ((get_global_int_type)fnptr_from_lib)();
	require_eq(call_library_fnptr, 42);
}

TEST_MAIN()
