/*-
 * Copyright (c) 2015-2020 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#include <machine/setjmp.h>
#include <machine/riscvreg.h>

#include "assym.inc"

/*
 * Convenience macros for CHERI.
 */
#if __has_feature(capabilities)
#if defined(FSU_CHERI_AS_USER)
// If so configured, use the as-user .u.cap loads and stores
#define	CLR_W		lr.w.u.cap
#define	CLR_D		lr.d.u.cap
#define	CLBU		lbu.u.cap
#define	CLHU		lhu.u.cap
#define	CLW		lw.u.cap
#define	CLD		ld.u.cap
#define	CLC		lc.u.cap
#define	CSB		sb.u.cap
#define	CSH		sh.u.cap
#define	CSW		sw.u.cap
#define	CSD		sd.u.cap
#define	CSC		sc.u.cap
#elif defined(__CHERI_PURE_CAPABILITY__)
// Otherwise, pure-cap kernels use capmode loads and stores
#define	CLR_W		clr.w
#define	CLR_D		clr.d
#define	CLBU		clbu
#define	CLHU		clhu
#define	CLW		clw
#define	CLD		cld
#define	CLC		clc
#define	CSB		csb
#define	CSH		csh
#define	CSW		csw
#define	CSD		csd
#define	CSC		csc
#else
// Otherwise, hybrid kernels use .cap loads and stores
#define	CLR_W		lr.w.cap
#define	CLR_D		lr.d.cap
#define	CLBU		lbu.cap
#define	CLHU		lhu.cap
#define	CLW		lw.cap
#define	CLD		ld.cap
#define	CLC		lc.cap
#define	CSB		sb.cap
#define	CSH		sh.cap
#define	CSW		sw.cap
#define	CSD		sd.cap
#define	CSC		sc.cap
#endif
#endif

/*
 * One of the fu* or su* functions failed, return -1.
 */
ENTRY(fsu_fault)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)	/* Reset the handler function */
#else
	SET_FAULT_HANDLER(x0, a1)	/* Reset the handler function */
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a1)
#endif
fsu_fault_nopcb:
	li	a0, -1
	RETURN
END(fsu_fault)

/*
 * as fsu_fault, but we're using the "magic" HINT instruction, so don't need to
 * clear out the fault handler
 *
 * This is also used by the inline forms in cpufunc.h; if, for some reason, it
 * changes to write to something other than a0, go update those as well.
 */
#ifdef FSU_MAGIC_HINT
ENTRY(fsu_fault_magic_hint)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a1)
#endif
	li	a0, -1
	RETURN
END(fsu_fault_fast_copy)
#endif

/*
 * int casueword32(volatile uint32_t * __capability, uint32_t, uint32_t *, uint32_t)
 */
ENTRY(casueword32)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a4, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a4, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca4)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a4)
#endif

#if __has_feature(capabilities)
	CLR_W	a4, 0(ca0)		/* Load-exclusive the data */
#else
	lr.w	a4, 0(a0)		/* Load-exclusive the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif

	bne	a4, a1, 1f		/* If not equal then exit */

#if __has_feature(capabilities)
#if defined(FSU_CHERI_AS_USER)
	// as-user cap-authorized form
	move	a5, a3
	sc.w.u.cap a5, 0(ca0)		/* Store the new data */
#elif defined(__CHERI_PURE_CAPABILITY__)
	// capmode
	csc.w	a5, a3, 0(ca0)		/* Store the new data */
#else
	// explicit cap form
	move	a5, a3
	sc.w.cap a5, 0(ca0)		/* Store the new data */
#endif
#else
	// no caps
	sc.w	a5, a3, 0(a0)		/* Store the new data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif

	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
2:	EXIT_USER_ACCESS(a6)
#else
2:
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(cnull, ca6)	/* Reset the fault handler */
#endif
	csw	a4, 0(ca2)		/* Store the read data */
#else
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(x0, a6)	/* Reset the fault handler */
#endif
	sw	a4, 0(a2)		/* Store the read data */
#endif
	mv	a0, a5			/* Success indicator */
	RETURN				/* Return */
END(casueword32)

/*
 * int casueword(volatile u_long * __capability, u_long, u_long *, u_long)
 */
ENTRY(casueword)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a4, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a4, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca4)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
#endif
#endif
	ENTER_USER_ACCESS(a4)

#if __has_feature(capabilities)
	CLR_D	a4, 0(ca0)		/* Load-exclusive the data */
#else
	lr.d	a4, 0(a0)		/* Load-exclusive the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif

	bne	a4, a1, 1f		/* If not equal then exit */

#if __has_feature(capabilities)
#if defined(FSU_CHERI_AS_USER)
	// as-user cap-authorized form
	move	a5, a3
	sc.d.u.cap a5, 0(ca0)		/* Store the new data */
#elif defined(__CHERI_PURE_CAPABILITY__)
	// capmode
	csc.d	a5, a3, 0(ca0)		/* Store the new data */
#else
	// explicit cap form
	move	a5, a3
	sc.d.cap a5, 0(ca0)		/* Store the new data */
#endif
#else
	// no caps
	sc.d	a5, a3, 0(a0)		/* Store the new data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif

	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
2:	EXIT_USER_ACCESS(a6)
#else
2:
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(cnull, ca6)	/* Reset the fault handler */
#endif
	csd	a4, 0(ca2)		/* Store the read data */
#else
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(x0, a6)	/* Reset the fault handler */
#endif
	sd	a4, 0(a2)		/* Store the read data */
#endif
	mv	a0, a5			/* Success indicator */
	RETURN				/* Return */
END(casueword)

/*
 * int fubyte(volatile const void * __capability)
 */
ENTRY(fubyte)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a1, VM_MAXUSER_ADDRESS
	bgt	a0, a1, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca1)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a1)
#endif

#if __has_feature(capabilities)
	CLBU	a0, 0(ca0)		/* Try loading the data */
#else
	lbu	a0, 0(a0)		/* Try loading the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a1)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a1)	/* Reset the fault handler */
#endif
#endif
	RETURN				/* Return */
END(fubyte)

/*
 * int fuword16(volatile const void * __capability)
 */
ENTRY(fuword16)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a1, (VM_MAXUSER_ADDRESS-1)
	bgt	a0, a1, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca1)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a1)
#endif

#if __has_feature(capabilities)
	CLHU	a0, 0(ca0)		/* Try loading the data */
#else
	lhu	a0, 0(a0)		/* Try loading the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a1)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a1)	/* Reset the fault handler */
#endif
#endif
	RETURN				/* Return */
END(fuword16)

/*
 * int32_t fueword32(volatile const void * __capability, int32_t *)
 */
ENTRY(fueword32)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

#if __has_feature(capabilities)
	CLW	a0, 0(ca0)		/* Try loading the data */
#else
	lw	a0, 0(a0)		/* Try loading the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#endif
	csw	a0, 0(ca1)		/* Save the data in kernel space */
#else
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	sw	a0, 0(a1)		/* Save the data in kernel space */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(fueword32)

/*
 * long fueword(volatile const void __capability *, int64_t *)
 * int64_t fueword64(volatile const void __capability *, int64_t *)
 */
ENTRY(fueword)
EENTRY(fueword64)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

#if __has_feature(capabilities)
	CLD	a0, 0(ca0)		/* Try loading the data */
#else
	ld	a0, 0(a0)		/* Try loading the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#endif
	csd	a0, 0(ca1)		/* Save the data in kernel space */
#else
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	sd	a0, 0(a1)		/* Save the data in kernel space */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
EEND(fueword64)
END(fueword)

#if __has_feature(capabilities)
/*
 * int fuecap(volatile const void __capability *, intcap_t *)
 */
ENTRY(fuecap)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

	CLC	ca0, 0(ca0)		/* Try loading the data */
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#endif
	csc	ca0, 0(ca1)		/* Save the data in kernel space */
#else
#ifndef FSU_MAGIC_HINT
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	sc.ddc	ca0, 0(a1)		/* Save the data in kernel space */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(fuecap)
#endif

/*
 * int subyte(volatile void * __capability, int)
 */
ENTRY(subyte)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, VM_MAXUSER_ADDRESS
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

#if __has_feature(capabilities)
	CSB	a1, 0(ca0)		/* Try storing the data */
#else
	sb	a1, 0(a0)		/* Try storing the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(subyte)

/*
 * int suword16(volatile void * __capability, int)
 */
ENTRY(suword16)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-1)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

#if __has_feature(capabilities)
	CSH	a1, 0(ca0)		/* Try storing the data */
#else
	sh	a1, 0(a0)		/* Try storing the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(suword16)

/*
 * int suword32(volatile void * __capability, int)
 */
ENTRY(suword32)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

#if __has_feature(capabilities)
	CSW	a1, 0(ca0)		/* Try storing the data */
#else
	sw	a1, 0(a0)		/* Try storing the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(suword32)

/*
 * int suword(volatile void * __capability, long)
 */
ENTRY(suword)
EENTRY(suword64)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

#if __has_feature(capabilities)
	CSD	a1, 0(ca0)		/* Try storing the data */
#else
	sd	a1, 0(a0)		/* Try storing the data */
#endif
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
EEND(suword64)
END(suword)

#if __has_feature(capabilities)
/*
 * int sucap(volatile void * __capability, intcap_t)
 */
ENTRY(sucap)
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a2, fsu_fault_nopcb
#endif
#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	ENTER_USER_ACCESS(a2)
#endif

	CSC	ca1, 0(ca0)		/* Try storing the data */
#ifdef FSU_MAGIC_HINT
	FSU_MAGIC_HINT_ASM
#endif
#if !__has_feature(capabilities) || !defined(FSU_CHERI_AS_USER)
	EXIT_USER_ACCESS(a2)
#endif

#ifndef FSU_MAGIC_HINT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(sucap)
#endif

ENTRY(setjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Store the stack pointer */
	csc	csp, 0(ca0)
	cincoffset ca0, ca0, 16

	/* Store the general purpose registers and ra */
	csc	cs0, (0 * 16)(ca0)
	csc	cs1, (1 * 16)(ca0)
	csc	cs2, (2 * 16)(ca0)
	csc	cs3, (3 * 16)(ca0)
	csc	cs4, (4 * 16)(ca0)
	csc	cs5, (5 * 16)(ca0)
	csc	cs6, (6 * 16)(ca0)
	csc	cs7, (7 * 16)(ca0)
	csc	cs8, (8 * 16)(ca0)
	csc	cs9, (9 * 16)(ca0)
	csc	cs10, (10 * 16)(ca0)
	csc	cs11, (11 * 16)(ca0)
	csc	cra, (12 * 16)(ca0)
#else
	/* Store the stack pointer */
	sd	sp, 0(a0)
	addi	a0, a0, 8

	/* Store the general purpose registers and ra */
	sd	s0, (0 * 8)(a0)
	sd	s1, (1 * 8)(a0)
	sd	s2, (2 * 8)(a0)
	sd	s3, (3 * 8)(a0)
	sd	s4, (4 * 8)(a0)
	sd	s5, (5 * 8)(a0)
	sd	s6, (6 * 8)(a0)
	sd	s7, (7 * 8)(a0)
	sd	s8, (8 * 8)(a0)
	sd	s9, (9 * 8)(a0)
	sd	s10, (10 * 8)(a0)
	sd	s11, (11 * 8)(a0)
	sd	ra, (12 * 8)(a0)
#endif

	/* Return value */
	li	a0, 0
	RETURN
END(setjmp)

ENTRY(longjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Restore the stack pointer */
	clc	csp, 0(ca0)
	cincoffset ca0, ca0, 16

	/* Restore the general purpose registers and ra */
	clc	cs0, (0 * 16)(ca0)
	clc	cs1, (1 * 16)(ca0)
	clc	cs2, (2 * 16)(ca0)
	clc	cs3, (3 * 16)(ca0)
	clc	cs4, (4 * 16)(ca0)
	clc	cs5, (5 * 16)(ca0)
	clc	cs6, (6 * 16)(ca0)
	clc	cs7, (7 * 16)(ca0)
	clc	cs8, (8 * 16)(ca0)
	clc	cs9, (9 * 16)(ca0)
	clc	cs10, (10 * 16)(ca0)
	clc	cs11, (11 * 16)(ca0)
	clc	cra, (12 * 16)(ca0)
#else
	/* Restore the stack pointer */
	ld	sp, 0(a0)
	addi	a0, a0, 8

	/* Restore the general purpose registers and ra */
	ld	s0, (0 * 8)(a0)
	ld	s1, (1 * 8)(a0)
	ld	s2, (2 * 8)(a0)
	ld	s3, (3 * 8)(a0)
	ld	s4, (4 * 8)(a0)
	ld	s5, (5 * 8)(a0)
	ld	s6, (6 * 8)(a0)
	ld	s7, (7 * 8)(a0)
	ld	s8, (8 * 8)(a0)
	ld	s9, (9 * 8)(a0)
	ld	s10, (10 * 8)(a0)
	ld	s11, (11 * 8)(a0)
	ld	ra, (12 * 8)(a0)
#endif

	/* Load the return value */
	mv	a0, a1
	RETURN
END(longjmp)

/*
 * CHERI CHANGES START
 * {
 *   "updated": 20200804,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
