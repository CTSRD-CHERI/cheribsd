/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Jessica Clarke
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Innovate
 * UK project 105694, "Digital Security by Design (DSbD) Technology Platform
 * Prototype".
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

#include <sys/mman.h>
#include <sys/signal.h>

#include <ucontext.h>

#include "cheribsdtest.h"

static void
ucontext_mmap_stack(ucontext_t *uctx)
{
	size_t len;
	void *p;

	len = SIGSTKSZ;
	p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY2(p != MAP_FAILED, "failed to map new stack");
	uctx->uc_stack.ss_sp = p;
	uctx->uc_stack.ss_size = len;
}

#define	SETCONTEXT_ARG1	0x43485249
#define	SETCONTEXT_ARG2	0x534554

static void
setcontext_func(int arg1, int arg2)
{
	CHERIBSDTEST_VERIFY(arg1 == SETCONTEXT_ARG1);
	CHERIBSDTEST_VERIFY(arg2 == SETCONTEXT_ARG2);
	cheribsdtest_success();
}

CHERIBSDTEST(setcontext_basic, "Check that setcontext works",
    /*
     * Currently happens to pass for c18n, possibly because makecontext and
     * setcontext calls are done in the same function?
     */
    .ct_flaky_reason = XFAIL_FLAKY_C18N_CONTEXT)
{
	ucontext_t uc;

	CHERIBSDTEST_CHECK_SYSCALL(getcontext(&uc));
	ucontext_mmap_stack(&uc);
	uc.uc_link = NULL;
	makecontext(&uc, (void (*)(void))&setcontext_func, 2, SETCONTEXT_ARG1,
	    SETCONTEXT_ARG2);
	CHERIBSDTEST_CHECK_SYSCALL(setcontext(&uc));
	cheribsdtest_failure_errx("returned from successful setcontext");
}

#define	SWAPCONTEXT_ARG1	0x53574150

static int swapcontext_arg1;

static void
swapcontext_func(int arg1)
{
	swapcontext_arg1 = arg1;
}

CHERIBSDTEST(swapcontext_basic, "Check that swapcontext works",
    .ct_flaky_reason = XFAIL_FLAKY_C18N_CONTEXT)
{
	ucontext_t uc, uc_link;
	int ret;

	CHERIBSDTEST_CHECK_SYSCALL(getcontext(&uc));
	ucontext_mmap_stack(&uc);
	uc.uc_link = &uc_link;
	makecontext(&uc, (void (*)(void))&swapcontext_func, 1,
	    SWAPCONTEXT_ARG1);
	ret = CHERIBSDTEST_CHECK_SYSCALL(swapcontext(&uc_link, &uc));
	CHERIBSDTEST_VERIFY2(ret == 0, "unknown return value from swapcontext");
	CHERIBSDTEST_VERIFY(swapcontext_arg1 == SWAPCONTEXT_ARG1);
	cheribsdtest_success();
}
