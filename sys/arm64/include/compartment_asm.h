/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#ifndef _MACHINE_COMPARTMENT_ASM_H_
#define	_MACHINE_COMPARTMENT_ASM_H_

#include <machine/_compartment.h>

/*
 * This header file includes compartmentalization-related macros for assembly
 * source code files.
 */

#ifdef CHERI_COMPARTMENTALIZE_KERNEL
#define	RELRO_ENTRY(label)					\
	.section .data.rel.ro, "aw", @progbits;			\
	.balign 16;						\
	.type label##_ptr, @object;				\
	label##_ptr:						\
	.chericap label;					\
	.size	label##_ptr, . - label##_ptr
#define	RELRO_BRANCH(scratchn, dstsym)				\
	adrp	c##scratchn, dstsym##_ptr;			\
	ldr	c##scratchn, [c##scratchn, :lo12:dstsym##_ptr];	\
	blr	c##scratchn

#define	EXECUTIVE_ENTRY(sym)	ENTRY(EXECUTIVE_ENTRY_NAME(sym))
#else
#define	EXECUTIVE_ENTRY(sym)	ENTRY(sym)
#endif

#endif	/* !_MACHINE_COMPARTMENT_ASM_H_ */
