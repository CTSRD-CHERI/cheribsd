/*-
 * Copyright (c) 2011-2016 Robert N. M. Watson
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

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <cheri/cheri.h>

SYSCTL_NODE(_security, OID_AUTO, cheri, CTLFLAG_RD, 0,
    "CHERI settings and statistics");

static u_int cheri_capability_size = CHERICAP_SIZE;
SYSCTL_UINT(_security_cheri, OID_AUTO, capability_size, CTLFLAG_RD,
    &cheri_capability_size, 0, "Size of a CHERI capability");

u_int	cheri_cloadtags_stride;
SYSCTL_UINT(_security_cheri, OID_AUTO, cloadtags_stride, CTLFLAG_RD,
    &cheri_cloadtags_stride, 0,
    "Number of capabilities covered by a single CLoadTags");

SYSCTL_NODE(_security_cheri, OID_AUTO, stats, CTLFLAG_RD, 0,
    "CHERI statistics");

/* XXXRW: Should possibly be u_long. */
u_int	security_cheri_syscall_violations;
SYSCTL_UINT(_security_cheri, OID_AUTO, syscall_violations, CTLFLAG_RD,
    &security_cheri_syscall_violations, 0, "Number of system calls blocked");

u_int	security_cheri_sandboxed_signals;
SYSCTL_UINT(_security_cheri, OID_AUTO, sandboxed_signals, CTLFLAG_RD,
    &security_cheri_sandboxed_signals, 0, "Number of signals in sandboxes");

/*
 * A set of sysctls that cause the kernel debugger to enter following a policy
 * violation or signal delivery due to CHERI or while in a sandbox.
 */
u_int	security_cheri_debugger_on_sandbox_signal;
SYSCTL_UINT(_security_cheri, OID_AUTO, debugger_on_sandbox_signal, CTLFLAG_RW,
    &security_cheri_debugger_on_sandbox_signal, 0,
    "Enter KDB when a signal is delivered while in a sandbox");

u_int	security_cheri_debugger_on_sandbox_syscall;
SYSCTL_UINT(_security_cheri, OID_AUTO, debugger_on_sandbox_syscall, CTLFLAG_RW,
    &security_cheri_debugger_on_sandbox_syscall, 0,
    "Enter KDB when a syscall is rejected while in a sandbox");

u_int	security_cheri_debugger_on_sandbox_unwind;
SYSCTL_UINT(_security_cheri, OID_AUTO, debugger_on_sandbox_unwind, CTLFLAG_RW,
    &security_cheri_debugger_on_sandbox_unwind, 0,
    "Enter KDB when a sandbox is auto-unwound due to a signal");

u_int	security_cheri_abort_on_memcpy_tag_loss;
SYSCTL_UINT(_security_cheri, OID_AUTO, abort_on_memcpy_tag_loss,
    CTLFLAG_RW, &security_cheri_abort_on_memcpy_tag_loss, 0,
    "abort() when memcpy() detects a tag loss due to misaligned copies.");

u_int	security_cheri_bound_legacy_capabilities;
SYSCTL_INT(_security_cheri, OID_AUTO, bound_legacy_capabilities,
    CTLFLAG_RWTUN, &security_cheri_bound_legacy_capabilities, 0,
    "Set bounds on userspace capabilities created by legacy ABIs.");

static void
measure_cloadtags_stride(void *dummy __unused)
{
	void * __capability *buf;
	uint64_t tags;
	u_int i;

	/*
	 * Malloc a buffer as allocating an aligned page on the stack
	 * risks overflowing the stack.
	 *
	 * Note that the buffer must not be simply aligned on a
	 * capability boundary but aligned on a stride of
	 * capabilities.
	 */
	buf = malloc_aligned(sizeof(*buf) * 64, sizeof(*buf) * 64,
	    M_TEMP, M_WAITOK | M_ZERO);

#ifdef INVARIANTS
	tags = cheri_loadtags(buf);

	KASSERT(tags == 0, ("CLoadTags on a zeroed buffer returned %lu", tags));
#endif

	/* CLoadTags can't return more than 64 bits. */
	for (i = 0; i < 64; i++)
		buf[i] = userspace_root_cap;

	tags = cheri_loadtags(buf);

	KASSERT(tags != 0, ("CLoadTags returned 0"));
	KASSERT(powerof2(tags + 1),
	    ("CLoadTags didn't return a valid bit mask"));

	cheri_cloadtags_stride = fls(tags);
	KASSERT(powerof2(cheri_cloadtags_stride),
	    ("CLoadTags isn't a power of 2"));

	zfree(buf, M_TEMP);
}
SYSINIT(cloadtags_stride, SI_SUB_VM_CONF, SI_ORDER_ANY,
    measure_cloadtags_stride, NULL);
