/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
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
#include <cheri/libcheri_fd.h>
#include <cheri/libcheri_invoke.h>
#include <cheri/libcheri_type.h>
#include <cheri/libcheri_sandbox.h>

#include <cheritest-helper.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheritest.h"
#include "cheritest_sandbox.h"

/*
 * Prepare a set of static sandboxes used (and reused) across various tests.
 * These are hand-crafted, minimalist affairs that don't even have stacks --
 * unlike libcheri tests that involve substantially more weight.  Those tests
 * are arguably tests for libcheri, while these are tests of the CCall (and
 * CReturn) mechanism itself.
 *
 * NB: Code and data capabilities have 100% overlapping address ranges;
 * base-relative $pc is always 0.  However, as they derive from $pcc vs. the
 * default data capability, they have non-identical permissions.
 */

static __capability void *sandbox_creturn_sealcap;
static __capability void *sandbox_creturn_codecap;
static __capability void *sandbox_creturn_datacap;

static __capability void *sandbox_nop_creturn_sealcap;
static __capability void *sandbox_nop_creturn_codecap;
static __capability void *sandbox_nop_creturn_datacap;

static __capability void *sandbox_dli_creturn_sealcap;
static __capability void *sandbox_dli_creturn_codecap;
static __capability void *sandbox_dli_creturn_datacap;

static __capability void *
codecap_create(void (*sandbox_base)(void), void *sandbox_end)
{
	__capability void *codecap;

#ifdef __CHERI_PURE_CAPABILITY__
	codecap = cheri_andperm(sandbox_base,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#else
	codecap = cheri_codeptrperm(sandbox_base,
	    (size_t)sandbox_end - (size_t)sandbox_base,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#endif
	return (codecap);
}

static __capability void *
datacap_create(void *sandbox_base, void *sandbox_end)
{
	__capability void *datacap;

#ifdef __CHERI_PURE_CAPABILITY__
	datacap = cheri_andperm(sandbox_base,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE |
	    CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP |
	    CHERI_PERM_STORE_LOCAL_CAP);
#else
	datacap = cheri_ptrperm(sandbox_base,
	    (size_t)sandbox_end - (size_t)sandbox_base,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE |
	    CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP |
	    CHERI_PERM_STORE_LOCAL_CAP);
#endif
	return (datacap);
}

/*
 * One-type setup for ccall-related tests.
 */
void
cheritest_ccall_setup(void)
{

	/*
	 * Create sealing, sealed code, and sealed data capabilities for each
	 * of the three classes used in these tests.
	 */
	sandbox_creturn_sealcap = libcheri_type_alloc();
	sandbox_creturn_codecap = cheri_seal(codecap_create(&sandbox_creturn,
	    &sandbox_creturn_end), sandbox_creturn_sealcap);
	sandbox_creturn_datacap = cheri_seal(datacap_create(&sandbox_creturn,
	    &sandbox_creturn_end), sandbox_creturn_sealcap);

	sandbox_nop_creturn_sealcap = libcheri_type_alloc();
	sandbox_nop_creturn_codecap =
	    cheri_seal(codecap_create(&sandbox_nop_creturn,
	    &sandbox_nop_creturn_end), sandbox_nop_creturn_sealcap);
	sandbox_nop_creturn_datacap =
	    cheri_seal(datacap_create(&sandbox_nop_creturn,
	    &sandbox_nop_creturn_end), sandbox_nop_creturn_sealcap);

	sandbox_dli_creturn_sealcap = libcheri_type_alloc();
	sandbox_dli_creturn_codecap =
	    cheri_seal(codecap_create(&sandbox_dli_creturn,
	    &sandbox_dli_creturn_end), sandbox_dli_creturn_sealcap);
	sandbox_dli_creturn_datacap =
	    cheri_seal(datacap_create(&sandbox_dli_creturn,
	    &sandbox_dli_creturn_end), sandbox_dli_creturn_sealcap);
}

/*
 * Trigger a CReturn underflow by trying to return from an unsandboxed
 * context.
 */
void
test_fault_creturn(const struct cheri_test *ctp __unused)
{

	CHERI_CRETURN();
}

/*
 * CCall code that will immediately CReturn.
 */
void
test_nofault_ccall_creturn(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = sandbox_creturn_codecap;
	co.co_datacap = sandbox_creturn_datacap;
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_success();
}

/*
 * CCall code that will execute a few NOPs, then CReturn.
 */
void
test_nofault_ccall_nop_creturn(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = sandbox_nop_creturn_codecap;
	co.co_datacap = sandbox_nop_creturn_datacap;
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_success();
}

/*
 * CCall code that will load a value (0x1234) into a return register,
 * which we can check for.  We install a quite different value (0x5678) in the
 * register prior to CCall to make sure that is overwritten.
 */
#define	PRIOR_RETVAL	0x5678
#define	DLI_RETVAL	0x1234
void
test_nofault_ccall_dli_creturn(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;
	register_t v0;

	v0 = PRIOR_RETVAL;
	co.co_codecap = sandbox_dli_creturn_codecap;
	co.co_datacap = sandbox_dli_creturn_datacap;
	v0 = libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (v0 != DLI_RETVAL)
		cheritest_failure_errx("Invalid return value (got: 0x%jx; "
		    "expected 0x%x)", v0, DLI_RETVAL);
	else
		cheritest_success();
}

/*
 * A series of tests exercising various potential failure modes for CCall.
 * These all work within the defined ABI of using $c1 and $c2.
 *
 * XXXRW: We should have some additional tests that attempt to use registers
 * other than $c1 and $c2 to see whether checks and implementation are done
 * properly if the caller doesn't quite follow the ABI.
 *
 * XXXRW: We should also have a test for trusted-stack overflow.
 *
 * XXXRW: There should also be a test for out-of-range $pc.
 */

/*
 * CCall with an untagged code capability.
 */
void
test_fault_ccall_code_untagged(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = sandbox_creturn_codecap;
	co.co_datacap = sandbox_creturn_datacap;

	co.co_codecap = cheri_cleartag(co.co_codecap);
	if (cheri_gettag(co.co_codecap) != 0)
		cheritest_failure_errx("cheri_cleartag failed");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfully");
}

/*
 * CCall with an untagged data capability.
 */
void
test_fault_ccall_data_untagged(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = sandbox_creturn_codecap;
	co.co_datacap = sandbox_creturn_datacap;

	co.co_datacap = cheri_cleartag(co.co_datacap);
	if (cheri_gettag(co.co_datacap) != 0)
		cheritest_failure_errx("cheri_cleartag failed");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfully");
}

/*
 * CCall with an unsealed code capability.
 */
void
test_fault_ccall_code_unsealed(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = codecap_create(&sandbox_creturn,
	    &sandbox_creturn_end);
	co.co_datacap = sandbox_creturn_datacap;

	if (cheri_getsealed(co.co_codecap) != 0)
		cheritest_failure_errx("code capability was sealed");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfully");
}

/*
 * CCall with an unsealed data capability.
 */
void
test_fault_ccall_data_unsealed(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = sandbox_creturn_codecap;
	co.co_datacap = datacap_create(&sandbox_creturn,
	    &sandbox_creturn_end);

	if (cheri_getsealed(co.co_datacap) != 0)
		cheritest_failure_errx("data capability was sealed");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfully");
}

/*
 * CCall with non-matching types for code and data.
 */
void
test_fault_ccall_typemismatch(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = sandbox_creturn_codecap;
	co.co_datacap = sandbox_dli_creturn_datacap;

	if (cheri_gettype(co.co_codecap) == cheri_gettype(co.co_datacap))
		cheritest_failure_errx("code and data types match");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfully");
}

/*
 * CCall without execute permission on the code capability.
 */
void
test_fault_ccall_code_noexecute(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = co.co_datacap = sandbox_creturn_datacap;

	if ((cheri_getperm(co.co_codecap) & CHERI_PERM_EXECUTE) != 0)
		cheritest_failure_errx("code capability has execute perm");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfully");
}

/*
 * CCall with execute permission on the data capability.
 */
void
test_fault_ccall_data_execute(const struct cheri_test *ctp __unused)
{
	struct cheri_object co;

	co.co_codecap = co.co_datacap = sandbox_creturn_codecap;

	if ((cheri_getperm(co.co_datacap) & CHERI_PERM_EXECUTE) == 0)
		cheritest_failure_errx("code capability does not have "
		    "execute perm");
	(void)libcheri_invoke(co, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	cheritest_failure_errx("ccall returned successfull");
}
