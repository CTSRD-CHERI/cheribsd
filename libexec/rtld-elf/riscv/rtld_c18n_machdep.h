/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
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

#ifndef RTLD_C18N_MACHDEP_H
#define RTLD_C18N_MACHDEP_H

#include <sys/cdefs.h>
#include <machine/riscvreg.h>

#define	TRUSTED_FRAME_SIZE		17
#define	TRUSTED_FRAME_SP_OSP		(16 * 13)
#define	TRUSTED_FRAME_PREV		(16 * 15)
#define	TRUSTED_FRAME_CALLER		(16 * 16)
#define	TRUSTED_FRAME_CALLEE		(16 * 16 + 4)
#define	TRUSTED_FRAME_LANDING		(16 * 16 + 8)

#define	SIG_FRAME_SIZE			1376

#define	UNTRUSTED_STACK		csp
#define	TIDC			3
#define	TRUSTED_STACK		0
#define	STACK_TABLE		CLEN_BYTES
#define	STACK_TABLE_N		6
#define	STACK_TABLE_C		__CONCAT(ct, STACK_TABLE_N)
#define	STACK_TABLE_RTLD	32

#ifdef IN_ASM

.macro	get_untrusted_stk	reg
	cmove		\reg, UNTRUSTED_STACK
.endmacro

.macro	set_untrusted_stk	reg
	cmove		UNTRUSTED_STACK, \reg
.endmacro

.macro	get_rtld_stk		reg
	clgc		\reg, sealer_tidc
	clc		\reg, 0(\reg)
	cspecialr	STACK_TABLE_C, TIDC
	cunseal		STACK_TABLE_C, STACK_TABLE_C, \reg
	clc		STACK_TABLE_C, STACK_TABLE(STACK_TABLE_C)
	clc		\reg, STACK_TABLE_RTLD(STACK_TABLE_C)
.endmacro

#else

static inline void *
get_trusted_tp(void)
{
	void *ptr;

	asm volatile ("cmove	%0, ctp" : "=C" (ptr));
	return (ptr);
}

struct tidc {
	struct trusted_frame *trusted_stk;
	struct stk_table *table;
};

static inline struct stk_table *
get_stk_table(void)
{
	struct tidc *tidc;

	asm volatile ("cspecialr	%0, " __XSTRING(TIDC) : "=C" (tidc));
	tidc = cheri_unseal(tidc, sealer_tidc);
	return (tidc->table);
}

static inline void
set_stk_table(struct stk_table *table)
{
	struct tidc *tidc;

	asm volatile ("cspecialr	%0, " __XSTRING(TIDC) : "=C" (tidc));
	tidc = cheri_unseal(tidc, sealer_tidc);
	tidc->table = table;
}

static inline struct trusted_frame *
get_trusted_stk(void)
{
	struct tidc *tidc;

	asm volatile ("cspecialr	%0, " __XSTRING(TIDC) : "=C" (tidc));
	tidc = cheri_unseal(tidc, sealer_tidc);
	return (tidc->trusted_stk);
}

static inline void
set_trusted_stk(struct trusted_frame *tf)
{
	struct tidc *tidc;

	asm volatile ("cspecialr	%0, " __XSTRING(TIDC) : "=C" (tidc));
	tidc = cheri_unseal(tidc, sealer_tidc);
	tidc->trusted_stk = tf;
}

struct dl_c18n_compart_state {
	void *fp;	/* s0 */
	void *pc;
	/*
	 * s1 to s11
	 */
	void *regs[11];
	/*
	 * INVARIANT: This field contains the top of the caller's stack when the
	 * caller made the call.
	 */
	void *sp;
};
#endif
#endif
