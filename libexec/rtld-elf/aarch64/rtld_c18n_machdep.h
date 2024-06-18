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

#define	TRUSTED_FRAME_SIZE		16
#define	TRUSTED_FRAME_SP_OSP		(16 * 12)
#define	TRUSTED_FRAME_PREV		(16 * 14)
#define	TRUSTED_FRAME_CALLER		(16 * 15)
#define	TRUSTED_FRAME_CALLEE		(16 * 15 + 4)
#define	TRUSTED_FRAME_LANDING		(16 * 15 + 8)

#define	SIG_FRAME_SIZE			1360

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
#define	TRUSTED_STACK		rddc_el0
#define	UNTRUSTED_STACK		csp
#define	STACK_TABLE		rctpidr_el0
#else
#define	TRUSTED_STACK		ddc
#define	UNTRUSTED_STACK		rcsp_el0
#define	STACK_TABLE		ctpidr_el0
#endif
#define	STACK_TABLE_N		17
#define	STACK_TABLE_C		__CONCAT(c, STACK_TABLE_N)
#define	STACK_TABLE_RTLD	32

#ifdef IN_ASM

.macro	get_untrusted_stk	reg
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	\reg, UNTRUSTED_STACK
#else
	mrs	\reg, UNTRUSTED_STACK
#endif
.endmacro

.macro	set_untrusted_stk	reg
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	UNTRUSTED_STACK, \reg
#else
	msr	UNTRUSTED_STACK, \reg
#endif
.endmacro

.macro	get_rtld_stk		reg
	mrs	STACK_TABLE_C, STACK_TABLE
	ldr	\reg, [STACK_TABLE_C, #STACK_TABLE_RTLD]
.endmacro

.macro	update_stk_table	osp, sp, index
	mrs	STACK_TABLE_C, TRUSTED_STACK
	ldrh	\index, [STACK_TABLE_C, #TRUSTED_FRAME_CALLEE]

	mrs	STACK_TABLE_C, STACK_TABLE
	ldr	\osp, [STACK_TABLE_C, \index, uxtw #0]
	str	\sp, [STACK_TABLE_C, \index, uxtw #0]
.endmacro

#else

static inline void *
get_trusted_tp(void)
{
	void *ptr;

	asm volatile ("mrs	%0, ctpidr_el0" : "=C" (ptr));
	return (ptr);
}

static inline struct stk_table *
get_stk_table(void)
{
	struct stk_table *table;

	asm volatile ("mrs	%0, " __XSTRING(STACK_TABLE) : "=C" (table));
	return (table);
}

static inline void
set_stk_table(const struct stk_table *table)
{
	asm ("msr	" __XSTRING(STACK_TABLE) ", %0" :: "C" (table));
}

static inline struct trusted_frame *
get_trusted_stk(void)
{
	struct trusted_frame *tf;

	asm volatile ("mrs	%0, " __XSTRING(TRUSTED_STACK) : "=C" (tf));
	return (tf);
}

static inline void
set_trusted_stk(const struct trusted_frame *tf)
{
	asm ("msr	" __XSTRING(TRUSTED_STACK) ", %0" :: "C" (tf));
}

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
static inline void
set_untrusted_stk(const void *sp)
{
	asm ("msr	" __XSTRING(UNTRUSTED_STACK) ", %0" :: "C" (sp));
}
#endif
#endif
#endif
