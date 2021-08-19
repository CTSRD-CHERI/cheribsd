/*-
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
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

#ifndef _MACHINE_ASM_H_
#define	_MACHINE_ASM_H_

#undef __FBSDID
#if !defined(lint) && !defined(STRIP_FBSDID)
#define	__FBSDID(s)     .ident s
#else
#define	__FBSDID(s)     /* nothing */
#endif

#define	_C_LABEL(x)	x

#define	ENTRY(sym)						\
	.text; .globl sym; .align 2; .type sym,#function; sym:
#define	EENTRY(sym)						\
	.globl	sym; .type sym,#function; sym:
#define	END(sym) .size sym, . - sym
#define	EEND(sym) .size sym, . - sym

#define	WEAK_REFERENCE(sym, alias)				\
	.weak alias;						\
	.set alias,sym

#define	UINT64_C(x)	(x)

#if defined(PIC)
#define	PIC_SYM(x,y)	x ## @ ## y
#else
#define	PIC_SYM(x,y)	x
#endif

#define	INT_WIDTH	8
#define	INTN(n)		n
#define	INT(n)		x ## n

#if __has_feature(capabilities)
#define	CAP_WIDTH	16
#define	CAPN(n)		c ## n
#define	CAP(n)		c ## n
#else
#define	CAP_WIDTH	INT_WIDTH
#define	CAPN(n)		INTN(n)
#define	CAP(n)		INT(n)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#define	PTR_WIDTH	CAP_WIDTH
#define	PTRN(n)		CAPN(n)
#define	PTR(n)		CAP(n)
/* Alias for link register c30 */
#define	clr		c30
#else
#define	PTR_WIDTH	INT_WIDTH
#define	PTRN(n)		INTN(n)
#define	PTR(n)		INT(n)
/* Alias for link register x30 */
#define	lr		x30
#endif

/* TODO: Remove these confusing deprecated aliases. */
#define	REG_WIDTH	PTR_WIDTH
#define	REGN(n)		PTRN(n)
#define	REG(n)		PTR(n)

/*
 * Switch into C64 mode to use instructions only available in Morello.
 */
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
#define	ENTER_C64		\
	bx #4;			\
	.arch_extension	c64
#define	EXIT_C64		\
	bx #4;			\
	.arch_extension	noc64;	\
	.arch_extension	a64c
#else
#define	ENTER_C64
#define	EXIT_C64
#endif

/*
 * Helper to load addresses that can be in the literal pool in the hybrid
 * kernel but must be loaded from GOT in purecap.
 */
#ifdef __CHERI_PURE_CAPABILITY__
#define	LDR_LABEL(reg, tmpptr, label)			\
	adrp	tmpptr, :got:##label;			\
	ldr	tmpptr, [tmpptr, :got_lo12:##label];	\
	ldr	reg, [tmpptr]
#else
#define	LDR_LABEL(reg, tmpptr, label)			\
	ldr	tmpptr, =##label;			\
	ldr	reg, [tmpptr]
#endif

/*
 * Sets the trap fault handler. The exception handler will return to the
 * address in the handler register on a data abort or the xzr register to
 * clear the handler. The tmp parameter should be a register able to hold
 * the temporary data.
 */
#define	SET_FAULT_HANDLER(handler, ptmp)				\
	ldr	ptmp, [PTR(18), #PC_CURTHREAD];	/* Load curthread */	\
	ldr	ptmp, [ptmp, #TD_PCB];		/* Load the pcb */	\
	str	handler, [ptmp, #PCB_ONFAULT]	/* Set the handler */

#define	ENTER_USER_ACCESS(reg, ptmp)					\
	LDR_LABEL(reg, ptmp, has_pan);		/* Get has_pan */	\
	cbz	reg, 997f;			/* If no PAN skip */	\
	.inst	0xd500409f | (0 << 8);		/* Clear PAN */		\
	997:

#define	EXIT_USER_ACCESS(reg)						\
	cbz	reg, 998f;			/* If no PAN skip */	\
	.inst	0xd500409f | (1 << 8);		/* Set PAN */		\
	998:

#define	EXIT_USER_ACCESS_CHECK(reg, ptmp)				\
	LDR_LABEL(reg, ptmp, has_pan);		/* Get has_pan */	\
	cbz	reg, 999f;			/* If no PAN skip */	\
	.inst	0xd500409f | (1 << 8);		/* Set PAN */		\
	999:

/*
 * Some AArch64 CPUs speculate past an eret instruction. As the user may
 * control the registers at this point add a speculation barrier usable on
 * all AArch64 CPUs after the eret instruction.
 * TODO: ARMv8.5 adds a specific instruction for this, we could use that
 * if we know we are running on something that supports it.
 */
#define	ERET								\
	eret;								\
	dsb	sy;							\
	isb

#endif /* _MACHINE_ASM_H_ */
