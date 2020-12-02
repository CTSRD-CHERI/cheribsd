/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
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

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <machine/cpuregs.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/libcheri_ccall.h>
#include <cheri/libcheri_enter.h>
#include <cheri/libcheri_fd.h>
#include <cheri/libcheri_stack.h>
#include <cheri/libcheri_sandbox.h>
#include <cheri/libcheri_sandbox_internal.h>

#include <cheribsdtest-helper.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

register_t
cheribsdtest_libcheri_userfn_getstack(void)
{
	struct libcheri_stack lcs;
	struct libcheri_stack_frame *lcsfp;
	u_int stack_depth;
	int retval;

	retval = libcheri_stack_get(&lcs);
	if (retval != 0)
		cheribsdtest_failure_err("libcheri_stack_get() failed");

	/* Does stack layout look sensible enough to continue? */
	if ((lcs.lcs_tsize % LIBCHERI_STACKFRAME_SIZE) != 0)
		cheribsdtest_failure_errx(
		    "stack size (%ld) not a multiple of frame size",
		    lcs.lcs_tsize);
	stack_depth = lcs.lcs_tsize / LIBCHERI_STACKFRAME_SIZE;

	if ((lcs.lcs_tsp % LIBCHERI_STACKFRAME_SIZE) != 0)
		cheribsdtest_failure_errx(
		    "stack pointer (%ld) not a multiple of frame size",
		    lcs.lcs_tsp);

	/* Validate that two stack frames are found. */
	if (lcs.lcs_tsp != lcs.lcs_tsize -
	    (register_t)(2 * LIBCHERI_STACKFRAME_SIZE))
		cheribsdtest_failure_errx("stack contains %ld frames; expected "
		    "2", (lcs.lcs_tsize - (2 * LIBCHERI_STACKFRAME_SIZE)) /
		    LIBCHERI_STACKFRAME_SIZE);

	/* Validate that the first is a saved ambient context. */
	lcsfp = &lcs.lcs_frames[stack_depth - 1];
	if (cheri_getbase(lcsfp->lcsf_caller_pcc) !=
	    cheri_getbase(cheri_getpcc()) ||
	    cheri_getlen(lcsfp->lcsf_caller_pcc) !=
	    cheri_getlen(cheri_getpcc()))
		cheribsdtest_failure_errx("frame 0: not global code cap");

#ifdef PLEASE_CRASH_THE_COMPILER
	/* ... and that the callee sandbox is right. */
	if (lcsfp->lcsf_callee_sbop != cheribsdtest_objectp)
		cheribsdtest_failure_errx("frame 1: incorrect callee sandbox");
#endif

	/* Validate that the second is cheribsdtest_objectp. */
	lcsfp = &lcs.lcs_frames[stack_depth - 2];
	if ((cheri_getbase(lcsfp->lcsf_caller_pcc) != cheri_getbase(
	    cheribsdtest_objectp->sbo_invoke_pcc)) ||
	    (cheri_getlen(lcsfp->lcsf_caller_pcc) != cheri_getlen(
	    cheribsdtest_objectp->sbo_invoke_pcc)))
		cheribsdtest_failure_errx("frame 1: not sandbox code cap");
	return (0);
}

void
test_sandbox_getstack(const struct cheri_test *ctp __unused)
{
	void * __capability cclear;
	register_t v;

	cclear = cheri_zerocap();
	v = invoke_libcheri_userfn(CHERIBSDTEST_USERFN_GETSTACK, 0);
	if (v != 0)
		cheribsdtest_failure_errx("Incorrect return value 0x%ld"
		    " (expected 0)\n", v);
	cheribsdtest_success();
}

#define	CHERIBSDTEST_SETSTACK_CONSTANT	37568

register_t
cheribsdtest_libcheri_userfn_setstack(register_t arg)
{
	struct libcheri_stack lcs;
	struct libcheri_stack_frame *lcsfp;
	u_int stack_depth;
	int retval;

	/* Validate stack as retrieved. */
	retval = libcheri_stack_get(&lcs);
	if (retval != 0)
		cheribsdtest_failure_err("libcheri_stack_get() failed");

	/* Does stack layout look sensible enough to continue? */
	if ((lcs.lcs_tsize % LIBCHERI_STACKFRAME_SIZE) != 0)
		cheribsdtest_failure_errx(
		    "stack size (%ld) not a multiple of frame size",
		    lcs.lcs_tsize);
	stack_depth = lcs.lcs_tsize / LIBCHERI_STACKFRAME_SIZE;

	if ((lcs.lcs_tsp % LIBCHERI_STACKFRAME_SIZE) != 0)
		cheribsdtest_failure_errx(
		    "stack pointer (%ld) not a multiple of frame size",
		    lcs.lcs_tsp);

	/* Validate that two stack frames are found. */
	if (lcs.lcs_tsp != lcs.lcs_tsize -
	    (register_t)(2 * LIBCHERI_STACKFRAME_SIZE))
		cheribsdtest_failure_errx("stack contains %ld frames; expected "
		    "2", (lcs.lcs_tsize - (2 * LIBCHERI_STACKFRAME_SIZE)) /
		    LIBCHERI_STACKFRAME_SIZE);

	/* Validate that the first is a saved ambient context. */
	lcsfp = &lcs.lcs_frames[stack_depth - 1];
	if (cheri_getbase(lcsfp->lcsf_caller_pcc) !=
	    cheri_getbase(cheri_getpcc()) ||
	    cheri_getlen(lcsfp->lcsf_caller_pcc) !=
	    cheri_getlen(cheri_getpcc()))
		cheribsdtest_failure_errx("frame 0: not global code cap");

#ifdef PLEASE_CRASH_THE_COMPILER
	/* ... and that the callee sandbox is right. */
	if (lcsfp->lcsf_callee_sbop != cheribsdtest_objectp)
		cheribsdtest_failure_errx("frame 1: incorrect callee sandbox");
#endif
	/* Validate that the second is cheribsdtest_objectp. */
	lcsfp = &lcs.lcs_frames[stack_depth - 2];
	if ((cheri_getbase(lcsfp->lcsf_caller_pcc) != cheri_getbase(
	    cheribsdtest_objectp->sbo_invoke_pcc)) ||
	    (cheri_getlen(lcsfp->lcsf_caller_pcc) != cheri_getlen(
	    cheribsdtest_objectp->sbo_invoke_pcc)))
		cheribsdtest_failure_errx("frame 1: not sandbox code cap");

	if (arg) {
		/* Rewrite to remove sandbox frame. */
		lcs.lcs_tsp += LIBCHERI_STACKFRAME_SIZE;
	}

	/* Update kernel view of trusted stack. */
	retval = libcheri_stack_set(&lcs);
	if (retval != 0)
		cheribsdtest_failure_err("libcheri_stack_set() failed");

	/* Leave behind a distinctive value we can test for. */
	return (CHERIBSDTEST_SETSTACK_CONSTANT);
}

void
test_sandbox_setstack(const struct cheri_test *ctp __unused)
{
	void * __capability cclear;
	register_t v;

	/*
	 * Note use of CHERIBSDTEST_HELPER_LIBCHERI_USERFN_SETSTACK here: this
	 * method adds 10 to the system-class return value.  We can detect
	 * whether stack rewrite worked to elide that return path by
	 * inspecting the return value.
	 *
	 * Request stack rewrite by using a non-zero argument value.
	 */
	cclear = cheri_zerocap();
	v = invoke_libcheri_userfn(CHERIBSDTEST_USERFN_SETSTACK, 1);
	if (v == CHERIBSDTEST_SETSTACK_CONSTANT + 10)
		cheribsdtest_failure_errx("sandbox return path improperly "
		    "executed");
	if (v != CHERIBSDTEST_SETSTACK_CONSTANT)
		cheribsdtest_failure_errx("unexpected return value (%ld)", v);
	cheribsdtest_success();
}

void
test_sandbox_setstack_nop(const struct cheri_test *ctp __unused)
{
	void * __capability cclear;
	register_t v;

	/* Request no stack rewrite by using an argument of 0. */
	cclear = cheri_zerocap();
	v = invoke_libcheri_userfn(CHERIBSDTEST_USERFN_SETSTACK, 0);
	if (v != CHERIBSDTEST_SETSTACK_CONSTANT)
		cheribsdtest_failure_errx("unexpected return value (%ld)", v);
	cheribsdtest_success();
}

/*
 * Perform a return without a corresponding invocation, to underflow the
 * trusted stack.
 */
void
test_sandbox_trustedstack_underflow(const struct cheri_test *ctp __unused)
{
	struct cheri_object returncap;
	void * __capability codecap /* currently ignored: asm ("$c1") */;
	void * __capability datacap /* currently ignored: asm ("$c2") */;

	returncap = libcheri_make_sealed_return_object();
	codecap = returncap.co_codecap;
	datacap = returncap.co_datacap;
	/*
	 * TODO: the branch delay slot has been removed. We can remove the nop
	 * once we no longer expect to run on older bitfiles
	 */
	__asm__ __volatile__ ("ccall %0, %1, 1\n\tnop" : : "C"(codecap),
	    "C"(datacap));
	cheribsdtest_failure_errx("continued after attempted CReturn");
}
