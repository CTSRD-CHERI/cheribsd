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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/cherireg.h>

static struct mtx cheri_otype_lock;
static struct unrhdr *cheri_otypes;
static void * __capability kernel_sealcap;

static void
cheri_otype_init(void *dummy __unused)
{

	mtx_init(&cheri_otype_lock, "CHERI object type lock", NULL, MTX_DEF);
	cheri_otypes = new_unrhdr(CHERI_OTYPE_KERN_MIN,
	    CHERI_OTYPE_KERN_MAX, &cheri_otype_lock);
	cheri_capability_set(&kernel_sealcap, CHERI_SEALCAP_KERNEL_PERMS,
	    CHERI_SEALCAP_KERNEL_BASE, CHERI_SEALCAP_KERNEL_LENGTH,
	    CHERI_SEALCAP_KERNEL_BASE);
}
SYSINIT(cheri_otype_init, SI_SUB_LOCK, SI_ORDER_FIRST, cheri_otype_init, NULL);

otype_t
cheri_otype_alloc(void)
{
	u_int type;

	type = alloc_unr(cheri_otypes);
	if (type == -1)
		return (NULL);
	return (cheri_maketype(kernel_sealcap,
	    type - CHERI_SEALCAP_KERNEL_BASE));
}

/*
 * Return a type to the pool.  Ideally we would ensure that no
 * capablities of this type remain in memory, but that would be VERY
 * expensive.  In practice, most consumers will never free a type.
 */
void
cheri_otype_free(otype_t cap)
{
	u_int type;

	type = cheri_getbase(cap);
	free_unr(cheri_otypes, type);
}
