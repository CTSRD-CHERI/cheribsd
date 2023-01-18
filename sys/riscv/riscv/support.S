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
 * Hybrid kernels use .cap loads and stores whereas purecap kernels use
 * capmode loads and stores.
 */
#ifdef __CHERI_PURE_CAPABILITY__
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

/*
 * One of the fu* or su* functions failed, return -1.
 */
ENTRY(fsu_fault)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)	/* Reset the handler function */
#else
	SET_FAULT_HANDLER(x0, a1)	/* Reset the handler function */
#endif
	EXIT_USER_ACCESS(a1)
fsu_fault_nopcb:
	li	a0, -1
	RETURN
END(fsu_fault)

/*
 * int casueword32(volatile uint32_t * __capability, uint32_t, uint32_t *, uint32_t)
 */
ENTRY(casueword32)
	li	a4, (VM_MAXUSER_ADDRESS-3)
	bgeu	a0, a4, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca4)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
#endif
	ENTER_USER_ACCESS(a4)
#if __has_feature(capabilities)
	CLR_W	a4, 0(ca0)		/* Load-exclusive the data */
#else
	lr.w	a4, 0(a0)		/* Load-exclusive the data */
#endif
	bne	a4, a1, 1f		/* If not equal then exit */
#ifdef __CHERI_PURE_CAPABILITY__
	csc.w	a5, a3, 0(ca0)		/* Store the new data */
#elif __has_feature(capabilities)
	move	a5, a3
	sc.w.cap a5, 0(ca0)		/* Store the new data */
#else
	sc.w	a5, a3, 0(a0)		/* Store the new data */
#endif
	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
2:	EXIT_USER_ACCESS(a6)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca6)	/* Reset the fault handler */
	csw	a4, 0(ca2)		/* Store the read data */
#else
	SET_FAULT_HANDLER(x0, a6)	/* Reset the fault handler */
	sw	a4, 0(a2)		/* Store the read data */
#endif
	mv	a0, a5			/* Success indicator */
	RETURN				/* Return */
END(casueword32)

/*
 * int casueword(volatile u_long * __capability, u_long, u_long *, u_long)
 */
ENTRY(casueword)
	li	a4, (VM_MAXUSER_ADDRESS-7)
	bgeu	a0, a4, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca4)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
#endif
	ENTER_USER_ACCESS(a4)
#if __has_feature(capabilities)
	CLR_D	a4, 0(ca0)		/* Load-exclusive the data */
#else
	lr.d	a4, 0(a0)		/* Load-exclusive the data */
#endif
	bne	a4, a1, 1f		/* If not equal then exit */
#ifdef __CHERI_PURE_CAPABILITY__
	csc.d	a5, a3, 0(ca0)		/* Store the new data */
#elif __has_feature(capabilities)
	move	a5, a3
	sc.d.cap a5, 0(ca0)		/* Store the new data */
#else
	sc.d	a5, a3, 0(a0)		/* Store the new data */
#endif
	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
2:	EXIT_USER_ACCESS(a6)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca6)	/* Reset the fault handler */
	csd	a4, 0(ca2)		/* Store the read data */
#else
	SET_FAULT_HANDLER(x0, a6)	/* Reset the fault handler */
	sd	a4, 0(a2)		/* Store the read data */
#endif
	mv	a0, a5			/* Success indicator */
	RETURN				/* Return */
END(casueword)

/*
 * int fubyte(volatile const void * __capability)
 */
ENTRY(fubyte)
	li	a1, VM_MAXUSER_ADDRESS
	bgeu	a0, a1, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca1)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
#endif
	ENTER_USER_ACCESS(a1)
#if __has_feature(capabilities)
	CLBU	a0, 0(ca0)		/* Try loading the data */
#else
	lbu	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a1)	/* Reset the fault handler */
#endif
	RETURN				/* Return */
END(fubyte)

/*
 * int fuword16(volatile const void * __capability)
 */
ENTRY(fuword16)
	li	a1, (VM_MAXUSER_ADDRESS-1)
	bgeu	a0, a1, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca1)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
#endif
	ENTER_USER_ACCESS(a1)
#if __has_feature(capabilities)
	CLHU	a0, 0(ca0)		/* Try loading the data */
#else
	lhu	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a1)	/* Reset the fault handler */
#endif
	RETURN				/* Return */
END(fuword16)

/*
 * int32_t fueword32(volatile const void * __capability, int32_t *)
 */
ENTRY(fueword32)
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	CLW	a0, 0(ca0)		/* Try loading the data */
#else
	lw	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
	csw	a0, 0(ca1)		/* Save the data in kernel space */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
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
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	CLD	a0, 0(ca0)		/* Try loading the data */
#else
	ld	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
	csd	a0, 0(ca1)		/* Save the data in kernel space */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
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
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	CLC	ca0, 0(ca0)		/* Try loading the data */
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
	csc	ca0, 0(ca1)		/* Save the data in kernel space */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
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
	li	a2, VM_MAXUSER_ADDRESS
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	CSB	a1, 0(ca0)		/* Try storing the data */
#else
	sb	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(subyte)

/*
 * int suword16(volatile void * __capability, int)
 */
ENTRY(suword16)
	li	a2, (VM_MAXUSER_ADDRESS-1)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	CSH	a1, 0(ca0)		/* Try storing the data */
#else
	sh	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(suword16)

/*
 * int suword32(volatile void * __capability, int)
 */
ENTRY(suword32)
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	CSW	a1, 0(ca0)		/* Try storing the data */
#else
	sw	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(suword32)

/*
 * int suword(volatile void * __capability, long)
 */
ENTRY(suword)
EENTRY(suword64)
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	CSD	a1, 0(ca0)		/* Try storing the data */
#else
	sd	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
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
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgeu	a0, a2, fsu_fault_nopcb
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(ca6, ca2)	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	CSC	ca1, 0(ca0)		/* Try storing the data */
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca2)	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
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
 *   "updated": 20221205,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
