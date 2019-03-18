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

static void testfn(void);
static void __attribute__((noinline)) foo(void)
{
	void *ret = __builtin_return_address(0);
	// Check that the return capability is, indeed, a capability
	assert_eq(__builtin_cheri_tag_get(ret), 1);
	// Return capability should be executable
	assert_eq((__builtin_cheri_perms_get(ret) & __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__), __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__);
	// Return capability offset should be after the pcc-relative offset of main.
	assert(__builtin_cheri_offset_get(ret) > __builtin_cheri_offset_get(testfn));
	// Approximate, but main really shouldn't need to be more than 100
	// instruction in any vaguely sane implementation.
	assert(__builtin_cheri_offset_get(ret) - __builtin_cheri_offset_get(testfn) < 100 * 4);
	// We shouldn't be able to write through code capabilities
	XFAIL((__builtin_cheri_perms_get(ret) & __CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__) == 0);
	XFAIL((__builtin_cheri_perms_get(ret) & __CHERI_CAP_PERMISSION_PERMIT_STORE__) == 0);
}

static void __attribute__((noinline)) testfn(void)
{
	foo();
}

BEGIN_TEST(clang_purecap_capretaddr)
	testfn();
END_TEST
