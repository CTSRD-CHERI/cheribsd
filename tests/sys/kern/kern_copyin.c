/*-
 * Copyright (c) 2015 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>
 * under sponsorship from the FreeBSD Foundation.
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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <atf-c.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/vmparam.h>

static int scratch_file;

static int
copyin_checker(uintptr_t uaddr, size_t len)
{
	ssize_t ret;

	ret = write(scratch_file, (const void *)uaddr, len);
	return (ret == -1 ? errno : 0);
}

#define	FMAX	ULONG_MAX

ATF_TC_WITHOUT_HEAD(kern_copyin);
ATF_TC_BODY(kern_copyin, tc)
{
	char template[] = "copyin.XXXXXX";

#ifdef __mips__
	/*
	 * MIPS has different VM layout: the UVA map on mips ends the
	 * highest mapped entry at the VM_MAXUSER_ADDRESS - PAGE_SIZE,
	 * while all other arches map either stack or shared page up
	 * to the VM_MAXUSER_ADDRESS.
	 */
	atf_tc_skip("Platform is not supported.");
#endif

	scratch_file = mkstemp(template);
	ATF_REQUIRE(scratch_file != -1);
	unlink(template);

	ATF_CHECK(copyin_checker(0, 0) == 0);
#ifdef SHAREDPAGE
	/*
	 * XXX: The top of the address space only has a valid page if
	 * SHAREDPAGE support is enabled.  Otherwise, the stack ends one
	 * page before the last address.  Even this check is a bit bogus.
	 */
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS - 10, 9) == 0);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS - 10, 10) == 0);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS - 10, 11) == EFAULT);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS - 1, 1) == 0);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS, 0) == 0);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS, 1) == EFAULT);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS, 2) == EFAULT);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS + 1, 0) == 0);
	ATF_CHECK(copyin_checker(VM_MAXUSER_ADDRESS + 1, 2) == EFAULT);
#endif
	ATF_CHECK(copyin_checker(FMAX - 10, 9) == EFAULT);
	ATF_CHECK(copyin_checker(FMAX - 10, 10) == EFAULT);
	ATF_CHECK(copyin_checker(FMAX - 10, 11) == EFAULT);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, kern_copyin);
	return (atf_no_error());
}
