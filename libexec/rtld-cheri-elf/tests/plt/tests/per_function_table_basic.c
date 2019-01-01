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
extern int some_global_int;
void* no_globals_used(void) __noinline;
int test_global_function(void) __noinline;
static int test_local_function(void) __noinline;

int some_global_int = 11;

static void
print_cgp(const void* cgp, const char* func) {
	print("$cgp in ");
	print(func);
	print(" ");
	print_cap(cgp);
	print("\n");
}

// This function is noinline so that the functions using it don't pull in all
// the global string constants used by require_eq
// This makes it a lot easier to calculate the number of globals needed
static __noinline void
_check_cgp_size(const void* cgp, size_t num_globals, const char* func)
{
	print_cgp(cgp, func);
	require_eq(cheri_gettag(cgp), 1);
	require_eq(cheri_getlen(cgp), num_globals * sizeof(void*));
	// Check that we have permit_load and permit_load_capability on the library $cgp
	// And also verify that it is not writable and not executable
	require_eq((cheri_getperm(cgp) & CHERI_PERM_EXECUTE), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_STORE), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_STORE_CAP), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_EXECUTE), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_LOAD), CHERI_PERM_LOAD);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_LOAD_CAP), CHERI_PERM_LOAD_CAP);
}

#define CHECK_CGP_SIZE(cgp, num_globals) _check_cgp_size(cgp, num_globals, __func__)

__noinline void* no_globals_used(void) {
	void* cgp = cheri_getcgp();
	// No globals used in this function -> $cgp should be null
	return cgp;
}

__noinline int test_global_function(void) {
	// One global used in this function -> $cgp should be exactly
	// 3 caps: global_int and  _check_cgp_size()+__func__
	CHECK_CGP_SIZE(cheri_getcgp(), 3);
	return global_int + 10;
}

__noinline static int test_local_function(void) {
	// Two globals used in this function -> $cgp should be exactly
	// 3 caps: test_global_function, some_global_int and  _check_cgp_size()+__func__
	CHECK_CGP_SIZE(cheri_getcgp(), 4);
	return test_global_function() + some_global_int;
}

static void test(void) {
	const void* test_cgp = cheri_getcgp();
	print("Starting test!\n");
	print_cgp(test_cgp, __func__);
	// TODO: test $cgp for main test function
	require_eq(test_global_function(), 52);
	require_eq(test_local_function(), 63);
	// Also call a function in the external library and check the result:
	const void* library_cgp_plus_int = get_library_cgp_plus_global_int();
	print("Got library $cgp plus int:\n");
	print("Result: "); print_cap(library_cgp_plus_int); print("\n");
	// This should have offset 42:
	require_eq(cheri_getoffset(library_cgp_plus_int), 42);

	// Check the no globals cgp here because if we did it inside
	// no_globals_used() the check macros would cause use of global vars.
	const void* no_globals_cgp = no_globals_used();
	// no_globals_used $cgp should be a tagged value with length zero:
	_check_cgp_size(no_globals_cgp, 0, "no_globals_cgp");
}

TEST_MAIN()
