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
#include <machine/setjmp.h>
#include <machine/riscvreg.h>

#include "assym.inc"

/*
 * One of the fu* or su* functions failed, return -1.
 */
ENTRY(fsu_fault)
	MODESW_INT
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a1))	/* Reset the handler function */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a4))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
#endif
	ENTER_USER_ACCESS(a4)
	MODESW_CAP
#if __has_feature(capabilities)
	LR_W_CAP	a4, 0(CAP(a0))	/* Load-exclusive the data */
#else
	lr.w	a4, 0(a0)		/* Load-exclusive the data */
#endif
	bne	a4, a1, 1f		/* If not equal then exit */
#ifdef __riscv_xcheri
#ifdef __CHERI_PURE_CAPABILITY__
	csc.w	a5, a3, 0(PTR(a0))	/* Store the new data */
#else
	move	a5, a3
	sc.w.cap a5, 0(CAP(a0))		/* Store the new data */
#endif
#else
	sc.w	a5, a3, 0(CAP(a0))	/* Store the new data */
#endif
	beqz	a5, 2f			/* Success */

1:	li	a5, 1			/* Normalize failure result */
2:	MODESW_INT
	EXIT_USER_ACCESS(a6)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a6))	/* Reset the fault handler */
	_SW	a4, 0(PTR(a2))		/* Store the read data */
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
	_LGC	PTR(a6), fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a4))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
#endif
	ENTER_USER_ACCESS(a4)
	MODESW_CAP
#if __has_feature(capabilities)
	LR_D_CAP	a4, 0(CAP(a0))	/* Load-exclusive the data */
#else
	lr.d	a4, 0(a0)		/* Load-exclusive the data */
#endif
	bne	a4, a1, 1f		/* If not equal then exit */
#ifdef __riscv_xcheri
#ifdef __CHERI_PURE_CAPABILITY__
	csc.d	a5, a3, 0(PTR(a0))	/* Store the new data */
#else
	move	a5, a3
	sc.d.cap a5, 0(CAP(a0))		/* Store the new data */
#endif
#else
	sc.d	a5, a3, 0(CAP(a0))	/* Store the new data */
#endif
	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
2:	MODESW_INT
	EXIT_USER_ACCESS(a6)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a6))	/* Reset the fault handler */
	_SD	a4, 0(PTR(a2))		/* Store the read data */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a1))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
#endif
	ENTER_USER_ACCESS(a1)
	MODESW_CAP
#if __has_feature(capabilities)
	LBU_CAP	a0, 0(CAP(a0))		/* Try loading the data */
#else
	lbu	a0, 0(a0)		/* Try loading the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a1))	/* Reset the fault handler */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a1))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
#endif
	ENTER_USER_ACCESS(a1)
	MODESW_CAP
#if __has_feature(capabilities)
	LHU_CAP	a0, 0(CAP(a0))		/* Try loading the data */
#else
	lhu	a0, 0(a0)		/* Try loading the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a1))	/* Reset the fault handler */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
#if __has_feature(capabilities)
	LW_CAP	a0, 0(CAP(a0))		/* Try loading the data */
#else
	lw	a0, 0(a0)		/* Try loading the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
	_SW	a0, 0(PTR(a1))		/* Save the data in kernel space */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
#if __has_feature(capabilities)
	LD_CAP	a0, 0(CAP(a0))		/* Try loading the data */
#else
	ld	a0, 0(a0)		/* Try loading the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
	_SD	a0, 0(PTR(a1))		/* Save the data in kernel space */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
	LC_CAP	CAP(a0), 0(CAP(a0))	/* Try loading the data */
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
	S_PTR	PTR(a0), 0(PTR(a1))		/* Save the data in kernel space */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	_SC	CAP(a0), 0(a1)		/* Save the data in kernel space */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
#if __has_feature(capabilities)
	SB_CAP	a1, 0(CAP(a0))		/* Try storing the data */
#else
	sb	a1, 0(a0)		/* Try storing the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
#if __has_feature(capabilities)
	SH_CAP	a1, 0(CAP(a0))		/* Try storing the data */
#else
	sh	a1, 0(a0)		/* Try storing the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
#if __has_feature(capabilities)
	SW_CAP	a1, 0(CAP(a0))		/* Try storing the data */
#else
	sw	a1, 0(a0)		/* Try storing the data */
#endif
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
#if __has_feature(capabilities)
	SD_CAP	a1, 0(CAP(a0))		/* Try storing the data */
#else
	sd	a1, 0(a0)		/* Try storing the data */
#endif
    	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
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
	_LGC	PTR(a6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	ENTER_USER_ACCESS(a2)
	MODESW_CAP
	SC_CAP	CAP(a1), 0(CAP(a0))	/* Try storing the data */
	MODESW_INT
	EXIT_USER_ACCESS(a2)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	li	a0, 0			/* Success */
	RETURN				/* Return */
END(sucap)
#endif

#if __has_feature(capabilities)
/*
 * cheri_buildcap_safe failed, return untagged input
 */
ENTRY(cbuildcap_fault)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the handler function */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the handler function */
#endif
#ifdef __riscv_xcheri
	ccleartag CAP(a0), CAP(a1)
#else
	gchi	a0, CAP(a1)
	schi	CAP(a0), CAP(a1), a0
#endif
	RETURN
END(cbuildcap_fault)

/*
 * void * __capability cheri_buildcap_safe(volatile void * __capability,
 *	intcap_t)
 */
ENTRY(cheri_buildcap_safe)
#ifdef __CHERI_PURE_CAPABILITY__
	_LGC	PTR(a6), cbuildcap_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(a6), PTR(a2))	/* And set it */
#else
	la	a6, cbuildcap_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
#endif
	_CBLD	CAP(a0), CAP(a0), CAP(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(PTR(null), PTR(a2))	/* Reset the fault handler */
#else
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
#endif
	RETURN
END(cheri_buildcap_safe)
#endif

ENTRY(setjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Store the stack pointer */
	S_PTR	PTR(sp), 0(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), 16

	/* Store the general purpose registers and ra */
	S_PTR	PTR(s0), (0 * 16)(PTR(a0))
	S_PTR	PTR(s1), (1 * 16)(PTR(a0))
	S_PTR	PTR(s2), (2 * 16)(PTR(a0))
	S_PTR	PTR(s3), (3 * 16)(PTR(a0))
	S_PTR	PTR(s4), (4 * 16)(PTR(a0))
	S_PTR	PTR(s5), (5 * 16)(PTR(a0))
	S_PTR	PTR(s6), (6 * 16)(PTR(a0))
	S_PTR	PTR(s7), (7 * 16)(PTR(a0))
	S_PTR	PTR(s8), (8 * 16)(PTR(a0))
	S_PTR	PTR(s9), (9 * 16)(PTR(a0))
	S_PTR	PTR(s10), (10 * 16)(PTR(a0))
	S_PTR	PTR(s11), (11 * 16)(PTR(a0))
	S_PTR	PTR(ra), (12 * 16)(PTR(a0))
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
	L_PTR	PTR(sp), 0(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), 16

	/* Restore the general purpose registers and ra */
	L_PTR	PTR(s0), (0 * 16)(PTR(a0))
	L_PTR	PTR(s1), (1 * 16)(PTR(a0))
	L_PTR	PTR(s2), (2 * 16)(PTR(a0))
	L_PTR	PTR(s3), (3 * 16)(PTR(a0))
	L_PTR	PTR(s4), (4 * 16)(PTR(a0))
	L_PTR	PTR(s5), (5 * 16)(PTR(a0))
	L_PTR	PTR(s6), (6 * 16)(PTR(a0))
	L_PTR	PTR(s7), (7 * 16)(PTR(a0))
	L_PTR	PTR(s8), (8 * 16)(PTR(a0))
	L_PTR	PTR(s9), (9 * 16)(PTR(a0))
	L_PTR	PTR(s10), (10 * 16)(PTR(a0))
	L_PTR	PTR(s11), (11 * 16)(PTR(a0))
	L_PTR	PTR(ra), (12 * 16)(PTR(a0))
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
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
