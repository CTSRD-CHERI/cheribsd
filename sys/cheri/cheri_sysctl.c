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
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <cheri/cheri.h>

#ifdef __CHERI_PURE_CAPABILITY__
FEATURE(cheriabi_kernel, "CheriABI kernel");
#ifdef __CHERI_SUBOBJECT_BOUNDS__
FEATURE(subobject_bounds, "CheriABI kernel with sub-object bounds");
#endif
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
FEATURE(benchmark_abi_kernel, "Morello benchmark ABI kernel");
#endif
#endif /* __CHERI_PURE_CAPABILITY__ */

SYSCTL_NODE(_security, OID_AUTO, cheri, CTLFLAG_RD, 0,
    "CHERI settings and statistics");

static u_int cheri_capability_size = CHERICAP_SIZE;
SYSCTL_UINT(_security_cheri, OID_AUTO, capability_size, CTLFLAG_RD,
    &cheri_capability_size, 0, "Size of a CHERI capability");

SYSCTL_NODE(_security_cheri, OID_AUTO, stats, CTLFLAG_RD, 0,
    "CHERI statistics");

/* XXXRW: Should possibly be u_long. */
u_int	security_cheri_syscall_violations;
SYSCTL_UINT(_security_cheri_stats, OID_AUTO, syscall_violations, CTLFLAG_RD,
    &security_cheri_syscall_violations, 0, "Number of system calls blocked");

/*
 * A set of sysctls that cause the kernel debugger to enter following a policy
 * violation or signal delivery due to CHERI or while in a sandbox.
 */
u_int	security_cheri_debugger_on_sandbox_syscall;
SYSCTL_UINT(_security_cheri, OID_AUTO, debugger_on_sandbox_syscall, CTLFLAG_RW,
    &security_cheri_debugger_on_sandbox_syscall, 0,
    "Enter KDB when a syscall is rejected while in a sandbox");

u_int	security_cheri_abort_on_memcpy_tag_loss;
SYSCTL_UINT(_security_cheri, OID_AUTO, abort_on_memcpy_tag_loss,
    CTLFLAG_RW, &security_cheri_abort_on_memcpy_tag_loss, 0,
    "abort() when memcpy() detects a tag loss due to misaligned copies.");

u_int	security_cheri_bound_legacy_capabilities;
SYSCTL_INT(_security_cheri, OID_AUTO, bound_legacy_capabilities,
    CTLFLAG_RWTUN, &security_cheri_bound_legacy_capabilities, 0,
    "Set bounds on userspace capabilities created by legacy ABIs.");

/*
 * Set the default state of library-based compartmentalisation (c18n) in
 * userspace.
 */
bool security_cheri_lib_based_c18n_default = false;
SYSCTL_BOOL(_security_cheri, OID_AUTO, lib_based_c18n_default, CTLFLAG_RWTUN,
    &security_cheri_lib_based_c18n_default, 0,
    "Userspace library-based compartmentalisation default");

#ifdef CHERI_CAPREVOKE
/*
 * Set the default state of revocation in userspace.  This is used to
 * compute the revocation flags in AT_BSDFLAGS but can be overridden
 * by elfctl(1) flags and procctl(2).
 */
int security_cheri_runtime_revocation_default = 1;
SYSCTL_INT(_security_cheri, OID_AUTO, runtime_revocation_default, CTLFLAG_RWTUN,
    &security_cheri_runtime_revocation_default, 0,
    "Userspace runtime revocation default");

/*
 * Set the default policy for revocation in userspace.  This is used to
 * compute the revocation policy flag in AT_BSDFLAGS.
 */
int security_cheri_runtime_revocation_every_free_default = 0;
SYSCTL_INT(_security_cheri, OID_AUTO, runtime_revocation_every_free_default,
    CTLFLAG_RWTUN, &security_cheri_runtime_revocation_every_free_default, 0,
    "Userspace runtime revocation on every free for debugging default");

/*
 * Set the default policy for synchronous vs. asynchronous revocation.  This is
 * used to compute the revocation policy flag in AT_BSDFLAGS.
 */
int security_cheri_runtime_revocation_async = 1;
SYSCTL_INT(_security_cheri, OID_AUTO, runtime_revocation_async,
    CTLFLAG_RWTUN, &security_cheri_runtime_revocation_async, 0,
    "Userspace requests (a)synchronous revocation by default");
#endif  /* CHERI_CAPREVOKE */
