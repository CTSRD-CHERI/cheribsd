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
 * One of the fu* or su* functions failed, return -1.
 */
ENTRY(fsu_fault)
	SET_FAULT_HANDLER(x0, a1)	/* Reset the handler function */
	EXIT_USER_ACCESS(a1)
fsu_fault_nopcb:
	li	a0, -1
	ret
END(fsu_fault)

/*
 * int casueword32_c(volatile uint32_t * __capability, uint32_t, uint32_t *, uint32_t)
 */
#if __has_feature(capabilities)
ENTRY(casueword32_c)
#else
ENTRY(casueword32)
#endif
	li	a4, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a4, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
	ENTER_USER_ACCESS(a4)
#if __has_feature(capabilities)
	lr.w.cap a4, 0(ca0)		/* Load-exclusive the data */
#else
	lr.w	a4, 0(a0)		/* Load-exclusive the data */
#endif
	bne	a4, a1, 1f		/* If not equal then exit */
#if __has_feature(capabilities)
	move	a5, a3
	sc.w.cap a5, 0(ca0)		/* Store the new data */
#else
	sc.w	a5, a3, 0(a0)		/* Store the new data */
#endif
	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
2:	EXIT_USER_ACCESS(a6)
	SET_FAULT_HANDLER(x0, a6)	/* Reset the fault handler */
	sw	a4, 0(a2)		/* Store the read data */
	mv	a0, a5			/* Success indicator */
	ret				/* Return */
#if __has_feature(capabilities)
END(casueword32_c)
#else
END(casueword32)
#endif

/*
 * int casueword_c(volatile u_long * __capability, u_long, u_long *, u_long)
 */
#if __has_feature(capabilities)
ENTRY(casueword_c)
#else
ENTRY(casueword)
#endif
	li	a4, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a4, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a4)	/* And set it */
	ENTER_USER_ACCESS(a4)
#if __has_feature(capabilities)
	lr.d.cap a4, 0(ca0)		/* Load-exclusive the data */
#else
	lr.d	a4, 0(a0)		/* Load-exclusive the data */
#endif
	bne	a4, a1, 1f		/* If not equal then exit */
#if __has_feature(capabilities)
	move	a5, a3
	sc.d.cap a5, 0(ca0)		/* Store the new data */
#else
	sc.d	a5, a3, 0(a0)		/* Store the new data */
#endif
	beqz	a5, 2f			/* Success */
1:	li	a5, 1			/* Normalize failure result */
2:	EXIT_USER_ACCESS(a6)
	SET_FAULT_HANDLER(x0, a6)	/* Reset the fault handler */
	sd	a4, 0(a2)		/* Store the read data */
	mv	a0, a5			/* Success indicator */
	ret				/* Return */
#if __has_feature(capabilities)
END(casueword_c)
#else
END(casueword)
#endif

/*
 * int fubyte_c(volatile const void * __capability)
 */
#if __has_feature(capabilities)
ENTRY(fubyte_c)
#else
ENTRY(fubyte)
#endif
	li	a1, VM_MAXUSER_ADDRESS
	bgt	a0, a1, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
	ENTER_USER_ACCESS(a1)
#if __has_feature(capabilities)
	lbu.cap	a0, 0(ca0)		/* Try loading the data */
#else
	lbu	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a1)
	SET_FAULT_HANDLER(x0, a1)	/* Reset the fault handler */
	ret				/* Return */
#if __has_feature(capabilities)
END(fubyte_c)
#else
END(fubyte)
#endif

/*
 * int fuword16_c(volatile const void * __capability)
 */
#if __has_feature(capabilities)
ENTRY(fuword16_c)
#else
ENTRY(fuword16)
#endif
	li	a1, (VM_MAXUSER_ADDRESS-1)
	bgt	a0, a1, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a1)	/* And set it */
	ENTER_USER_ACCESS(a1)
#if __has_feature(capabilities)
	lhu.cap	a0, 0(ca0)		/* Try loading the data */
#else
	lhu	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a1)
	SET_FAULT_HANDLER(x0, a1)	/* Reset the fault handler */
	ret				/* Return */
#if __has_feature(capabilities)
END(fuword16_c)
#else
END(fuword16)
#endif

/*
 * int32_t fueword32_c(volatile const void * __capability, int32_t *)
 */
#if __has_feature(capabilities)
ENTRY(fueword32_c)
#else
ENTRY(fueword32)
#endif
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	lw.cap	a0, 0(ca0)		/* Try loading the data */
#else
	lw	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	sw	a0, 0(a1)		/* Save the data in kernel space */
	li	a0, 0			/* Success */
	ret				/* Return */
#if __has_feature(capabilities)
END(fueword32_c)
#else
END(fueword32)
#endif

/*
 * long fueword_c(volatile const void __capability *, int64_t *)
 * int64_t fueword64_c(volatile const void __capability *, int64_t *)
 */
#if __has_feature(capabilities)
ENTRY(fueword_c)
EENTRY(fueword64_c)
#else
ENTRY(fueword)
EENTRY(fueword64)
#endif
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	ld.cap	a0, 0(ca0)		/* Try loading the data */
#else
	ld	a0, 0(a0)		/* Try loading the data */
#endif
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	sd	a0, 0(a1)		/* Save the data in kernel space */
	li	a0, 0			/* Success */
	ret				/* Return */
#if __has_feature(capabilities)
EEND(fueword64_c)
END(fueword_c)
#else
EEND(fueword64)
END(fueword)
#endif

#if __has_feature(capabilities)
/*
 * int fuecap(volatile const void __capability *, intcap_t *)
 */
ENTRY(fuecap)
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
	lc.cap	ca0, 0(ca0)		/* Try loading the data */
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	sc.ddc	ca0, 0(a1)		/* Save the data in kernel space */
	li	a0, 0			/* Success */
	ret				/* Return */
END(fuecap)
#endif

/*
 * int subyte_c(volatile void * __capability, int)
 */
#if __has_feature(capabilities)
ENTRY(subyte_c)
#else
ENTRY(subyte)
#endif
	li	a2, VM_MAXUSER_ADDRESS
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	sb.cap	a1, 0(ca0)		/* Try storing the data */
#else
	sb	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	li	a0, 0			/* Success */
	ret				/* Return */
#if __has_feature(capabilities)
END(subyte_c)
#else
END(subyte)
#endif

/*
 * int suword16_c(volatile void * __capability, int)
 */
#if __has_feature(capabilities)
ENTRY(suword16_c)
#else
ENTRY(suword16)
#endif
	li	a2, (VM_MAXUSER_ADDRESS-1)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	sh.cap	a1, 0(ca0)		/* Try storing the data */
#else
	sh	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	li	a0, 0			/* Success */
	ret				/* Return */
#if __has_feature(capabilities)
END(suword16_c)
#else
END(suword16)
#endif

/*
 * int suword32_c(volatile void * __capability, int)
 */
#if __has_feature(capabilities)
ENTRY(suword32_c)
#else
ENTRY(suword32)
#endif
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	sw.cap	a1, 0(ca0)		/* Try storing the data */
#else
	sw	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	li	a0, 0			/* Success */
	ret				/* Return */
#if __has_feature(capabilities)
END(suword32_c)
#else
END(suword32)
#endif

/*
 * int suword_c(volatile void * __capability, long)
 */
#if __has_feature(capabilities)
ENTRY(suword_c)
EENTRY(suword64_c)
#else
ENTRY(suword)
EENTRY(suword64)
#endif
	li	a2, (VM_MAXUSER_ADDRESS-7)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
#if __has_feature(capabilities)
	sd.cap	a1, 0(ca0)		/* Try storing the data */
#else
	sd	a1, 0(a0)		/* Try storing the data */
#endif
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	li	a0, 0			/* Success */
	ret				/* Return */
#if __has_feature(capabilities)
EEND(suword64_c)
END(suword_c)
#else
EEND(suword64)
END(suword)
#endif

#if __has_feature(capabilities)
/*
 * int sucap(volatile void * __capability, intcap_t)
 */
ENTRY(sucap)
	li	a2, (VM_MAXUSER_ADDRESS-3)
	bgt	a0, a2, fsu_fault_nopcb
	la	a6, fsu_fault		/* Load the fault handler */
	SET_FAULT_HANDLER(a6, a2)	/* And set it */
	ENTER_USER_ACCESS(a2)
	sc.cap	ca1, 0(ca0)		/* Try storing the data */
	EXIT_USER_ACCESS(a2)
	SET_FAULT_HANDLER(x0, a2)	/* Reset the fault handler */
	li	a0, 0			/* Success */
	ret				/* Return */
END(sucap)
#endif

/* XXX: CHERI TODO: Save/restore cap registers. */
ENTRY(setjmp)
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

	/* Return value */
	li	a0, 0
	ret
END(setjmp)

ENTRY(longjmp)
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

	/* Load the return value */
	mv	a0, a1
	ret
END(longjmp)
