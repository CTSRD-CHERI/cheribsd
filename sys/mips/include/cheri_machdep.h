/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019 Alex Richardson <arichardson@FreeBSD.org>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
 *
 * $FreeBSD$
 */
#ifndef _MIPS_INCLUDE_CHERI_MACHDEP_H_
#define _MIPS_INCLUDE_CHERI_MACHDEP_H_

#ifndef _KERNEL
#error "Should only be used in the kernel"
#endif

#include <machine/frame.h>
#include <cheri/cheric.h>

static inline trapf_pc_t
_update_pcc_offset(trapf_pc_t pcc, register_t pc, const char *func)
{

	/*
	 * Be careful to not modify sealed values here since otherwise we get
	 * a CHERI trap in the kernel which results in a panic().
	 */
	if (cheri_gettype(pcc) == CHERI_OTYPE_UNSEALED) {
		return cheri_setoffset(pcc, pc);
	} else if (cheri_getoffset(pcc) == pc) {
		/* Don't warn if the values match (not modifying $pcc) */
		return pcc;
	} else {
		printf("%s: attempted to change sealed $pcc offset 0x%jx\n",
		    func, (intmax_t)pc);
		CHERI_PRINT_PTR(pcc);
		return cheri_fromint(pc);
	}
}
#define	update_pcc_offset(pcc, pc)	_update_pcc_offset(pcc, pc, __func__)

#endif /* _MIPS_INCLUDE_CHERI_MACHDEP_H_ */
