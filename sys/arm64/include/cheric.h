/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
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

#ifndef _MACHINE_CHERIC_H_
#define	_MACHINE_CHERIC_H_

#include <machine/vmparam.h>

#if __has_feature(capabilities) && defined(_KERNEL)
/*
 * ERET in Morello does not use the LSB of the saved elr to set
 * PSR_C64, nor does it support unsealing sentry capabilities.
 *
 * This helper handles those cases by storing an unsealed return
 * address in elr and setting or clearing PSR_C64 in a trapframe.
 */
static __inline void
trapframe_set_elr(struct trapframe *tf, uintcap_t elr)
{
	extern void * __capability sentry_unsealcap;

	if (cheri_getsealed(elr))
		elr = cheri_unseal(elr, sentry_unsealcap);

	if (elr & 0x1) {
		tf->tf_spsr |= PSR_C64;
		--elr;
	} else {
		tf->tf_spsr &= ~PSR_C64;
	}
	tf->tf_elr = elr;
}
#endif

#if __has_feature(capabilities)
#define	cheri_capmode(cap)	(__typeof(cap))((uintcap_t)(cap) | 1)
#endif

#endif /* !_MACHINE_CHERIC_H_ */
