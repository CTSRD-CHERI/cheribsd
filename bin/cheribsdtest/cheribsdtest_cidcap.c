/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122S0003 ("MTSS").
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

#include <sys/sysctl.h>

#include "cheribsdtest.h"

#ifdef CHERI_PERM_COMPARTMENT_ID

static uintcap_t
get_cidcap(void)
{
	uintcap_t cidcap;
	size_t cidcap_size;

	cidcap_size = sizeof(cidcap);
	CHERIBSDTEST_CHECK_SYSCALL(sysctlbyname("security.cheri.cidcap",
	    &cidcap, &cidcap_size, NULL, 0));

	return (cidcap);
}

CHERIBSDTEST(cidcap_sysctl, "Retrieve cidcap using sysctl(3)")
{
	uintcap_t cidcap;
	uint64_t v;

	cidcap = get_cidcap();

	/* Base. */
	v = cheri_getbase(cidcap);
	if (v != CHERI_COMPARTMENT_ID_USERSPACE_BASE)
		cheribsdtest_failure_errx("base %jx (expected %jx)", v,
		    (uintmax_t)CHERI_COMPARTMENT_ID_USERSPACE_BASE);

	/* Length. */
	v = cheri_getlen(cidcap);
	if (v != CHERI_COMPARTMENT_ID_USERSPACE_LENGTH)
		cheribsdtest_failure_errx("length 0x%jx (expected 0x%jx)", v,
		    (uintmax_t)CHERI_COMPARTMENT_ID_USERSPACE_LENGTH);

	/* Offset. */
	v = cheri_getoffset(cidcap);
	if (v != CHERI_COMPARTMENT_ID_USERSPACE_OFFSET)
		cheribsdtest_failure_errx("offset %jx (expected %jx)", v,
		    (uintmax_t)CHERI_COMPARTMENT_ID_USERSPACE_OFFSET);

	/* Type -- should have unsealed type. */
	v = cheri_gettype(cidcap);
	if (v != (u_register_t)CHERI_OTYPE_UNSEALED)
		cheribsdtest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)CHERI_OTYPE_UNSEALED);

	/* Permissions. */
	v = cheri_getperm(cidcap);
	if (v != CHERI_COMPARTMENT_ID_USERSPACE_PERMS)
		cheribsdtest_failure_errx("perms %jx (expected %jx)", v,
		    (uintmax_t)CHERI_COMPARTMENT_ID_USERSPACE_PERMS);

	/* Sealed bit. */
	v = cheri_getsealed(cidcap);
	if (v != 0)
		cheribsdtest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_gettag(cidcap);
	if (v != 1)
		cheribsdtest_failure_errx("tag %jx (expected 1)", v);
	cheribsdtest_success();
}
#endif /* CHERI_PERM_COMPARTMENT_ID */
