/*-
 * Copyright (c) 2017 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/sysent.h>

#include <machine/cherireg.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include "cheriabi_util.h"

static otype_t systoken_type;
void * __capability foo;

static void
cheriabi_systoken_init(void *dummy __unused)
{

	systoken_type = cheri_otype_alloc();
}
SYSINIT(cheriabi_systokens, SI_SUB_EXEC, SI_ORDER_FIRST,
    cheriabi_systoken_init, NULL);

CTASSERT(CHERI_SEAL_ALIGN_SHIFT(1) == 12);

void * __capability
cheriabi_syscall2token(int num, struct proc *p)
{
	int nsyscalls;
	void * __capability token;

	nsyscalls = p->p_sysent->sv_size;
	if (num < 0 || num >= nsyscalls)
		return (NULL);

	cheri_capability_set(&token, 0, 0,
	    roundup2(nsyscalls,
		(size_t)(1ULL << CHERI_SEAL_ALIGN_SHIFT(nsyscalls))), num);
	KASSERT(cheri_getbase(token) == 0, ("base of token is not 0"));
	KASSERT(cheri_getoffset(token) == num,
	    ("offset of token is not %d", num));
	KASSERT(cheri_getlen(token) >= nsyscalls,
	    ("length is too short %zu < %d", cheri_getlen(token), nsyscalls));
	return (cheri_seal(token, systoken_type));
}

int
cheriabi_token2syscall(void * __capability token)
{

	if (cheri_gettype(token) !=
	    cheri_getbase(systoken_type) + cheri_getoffset(systoken_type))
		return (-1);

	return (cheri_getoffset(token));
}
