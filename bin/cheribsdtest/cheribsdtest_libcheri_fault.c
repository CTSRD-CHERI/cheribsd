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
#include <cheri/libcheri_sandbox.h>

#include <cheribsdtest-helper.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

/*
 * Exercises various faults inside of sandboxes, including VM faults,
 * arithmetic faults, etc.
 */
void
test_sandbox_cp2_bound_catch(const struct cheri_test *ctp __unused)
{

	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_BOUND);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_bound_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGPROT);
	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_BOUND);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_bound_nocatch_noaltstack(
    const struct cheri_test *ctp __unused)
{
	stack_t ss;

	bzero(&ss, sizeof(ss));
	ss.ss_flags = SS_DISABLE;
	if (sigaltstack(&ss, NULL) < 0)
		cheribsdtest_failure_err("sigaltstack");
	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_BOUND);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_perm_load_catch(const struct cheri_test *ctp __unused)
{

	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_PERM_LOAD);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_perm_load_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGPROT);
	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_PERM_LOAD);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_perm_store_catch(const struct cheri_test *ctp __unused)
{

	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_PERM_STORE);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_perm_store_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGPROT);
	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_PERM_STORE);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_tag_catch(const struct cheri_test *ctp __unused)
{

	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_TAG);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_tag_nocatch(const struct cheri_test *ctp __unused)
{
	register_t v;

	signal_handler_clear(SIGPROT);
	v = invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_TAG);
	if (v != -1)
		cheribsdtest_failure_errx("invoke returned %ld (expected %d)", v,
		    -1);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_seal_catch(const struct cheri_test *ctp __unused)
{

	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_SEAL);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_cp2_seal_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGPROT);
	invoke_cap_fault(CHERIBSDTEST_HELPER_CAP_FAULT_CP2_SEAL);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_divzero_catch(const struct cheri_test *ctp __unused)
{

	invoke_divzero();
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_divzero_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGEMT);
	invoke_divzero();
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_vm_rfault_catch(const struct cheri_test *ctp __unused)
{

	invoke_vm_fault(CHERIBSDTEST_HELPER_VM_FAULT_RFAULT);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_vm_rfault_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGSEGV);
	invoke_vm_fault(CHERIBSDTEST_HELPER_VM_FAULT_RFAULT);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_vm_wfault_catch(const struct cheri_test *ctp __unused)
{

	invoke_vm_fault(CHERIBSDTEST_HELPER_VM_FAULT_WFAULT);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_vm_wfault_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGSEGV);
	invoke_vm_fault(CHERIBSDTEST_HELPER_VM_FAULT_WFAULT);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_vm_xfault_catch(const struct cheri_test *ctp __unused)
{

	invoke_vm_fault(CHERIBSDTEST_HELPER_VM_FAULT_XFAULT);
	cheribsdtest_failure_errx("invoke returned");
}

void
test_sandbox_vm_xfault_nocatch(const struct cheri_test *ctp __unused)
{

	signal_handler_clear(SIGSEGV);
	invoke_vm_fault(CHERIBSDTEST_HELPER_VM_FAULT_XFAULT);
	cheribsdtest_failure_errx("invoke returned");
}
