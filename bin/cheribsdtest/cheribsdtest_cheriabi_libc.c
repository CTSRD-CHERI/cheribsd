/*-
 * Copyright (c) 2020 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/types.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <string.h>

#include "cheribsdtest.h"

CHERIBSDTEST(cheriabi_libc_memchr,
    "Check that memchr() works as required")
{
	_Alignas(16) char string[] = "0123456789abcde";

	/* Full length, aligned end */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)memchr(string, 'e', sizeof(string)),
	    'e');
	/* Length does not include char */
	CHERIBSDTEST_VERIFY(memchr(string, 'e', sizeof(string) - 2) == NULL);

	/*
	 * Length longer than cap, char in bounds
	 *
	 * From the standard: "The implementation shall behave as if it
	 * reads the characters sequentially and stops as soon as a
	 * matching character is found."
	 *
	 * This means the implementation needs to not trust the supplied
	 * length when doing optimized word-wise reads and compares.
	 */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)memchr(cheri_setbounds(string,
	    sizeof(string) - 1), 'e', sizeof(string)), 'e');

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_libc_strchr,
    "Check that strchr() works as required")
{
	_Alignas(16) char string[] = "0123456789abcdefghij";

	/* Full length, aligned end */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)strchr(string, 'e'), 'e');
	/* String that does not include char */
	CHERIBSDTEST_VERIFY(strchr(string, 'z') == NULL);

	/*
	 * char in bounds, but last word not fully in bounds
	 *
	 * As with memchr, the implementation must avoid raising a
	 * spurious exception if the character is in bounds even if
	 * the containing word is not in bounds.
	 */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)strchr(string, 'g'), 'g');

	cheribsdtest_success();
}


CHERIBSDTEST(cheriabi_libc_strchrnul,
    "Check that strchrnul() works as required")
{
	_Alignas(16) char string[] = "0123456789abcdefghij";

	/* Full length, aligned end */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)strchrnul(string, 'e'), 'e');
	/* String that does not include char */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)strchrnul(string, 'z'), '\0');

	/*
	 * char in bounds, but last word not fully in bounds
	 *
	 * As with memchr, the implementation must avoid raising a
	 * spurious exception if the character is in bounds even if
	 * the containing word is not in bounds.
	 */
	CHERIBSDTEST_CHECK_EQ_INT(*(char *)strchrnul(string, 'g'), 'g');

	cheribsdtest_success();
}
