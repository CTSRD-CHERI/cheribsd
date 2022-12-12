/*-
 * Copyright (c) 2014 Andrew Turner
 * Copyright (c) 2014-2015 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation
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
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#include <machine/setjmp.h>
#include <machine/param.h>
#include <machine/vmparam.h>

#include "assym.inc"

.macro check_user_access user_arg, limit, bad_addr_func
	ldr	x7, =(\limit)
#if __has_feature(capabilities)
	gcvalue	x6, c\user_arg
	cmp	x6, x7
#else
	cmp	x\user_arg, x7
#endif
	b.cs	\bad_addr_func
.endm

/*
 * One of the fu* or su* functions failed, return -1.
 */
ENTRY(fsu_fault)
	SET_FAULT_HANDLER(xzr, PTR(1))	/* Reset the handler function */
	EXIT_USER_ACCESS_CHECK(w0, PTR(1))
fsu_fault_nopcb:
	mov	x0, #-1
	ret
END(fsu_fault)

/*
 * int casueword32_llsc(volatile uint32_t * __capability, uint32_t, uint32_t *,
 *         uint32_t)
 */
ENTRY(casueword32_llsc)
	check_user_access 0, (VM_MAXUSER_ADDRESS-3), fsu_fault_nopcb
	adr	PTR(6), fsu_fault	/* Load the fault handler */
	mov	w5, #1
	SET_FAULT_HANDLER(PTR(6), PTR(4))	/* And set it */
	ENTER_USER_ACCESS(w6, PTR(4))
	ENTER_C64
#if __has_feature(capabilities)
	ldxr	w4, [c0]		/* Load-exclusive the data */
#else
	ldxr	w4, [x0]		/* Load-exclusive the data */
#endif
	cmp	w4, w1			/* Compare */
	b.ne	1f			/* Not equal, exit */
#if __has_feature(capabilities)
	stxr	w5, w3, [c0]		/* Store the new data */
#else
	stxr	w5, w3, [x0]		/* Store the new data */
#endif
1:	EXIT_C64
	EXIT_USER_ACCESS(w6)
	SET_FAULT_HANDLER(xzr, PTR(6))	/* Reset the fault handler */
	str	w4, [PTR(2)]		/* Store the read data */
	mov	w0, w5			/* Result same as store status */
	ret				/* Return */
END(casueword32_llsc)

/*
 * int casueword32_lse(volatile u_long * __capability, u_long, u_long *, u_long)
 */
ENTRY(casueword32_lse)
	check_user_access 0, (VM_MAXUSER_ADDRESS-3), fsu_fault_nopcb
	adr	PTR(6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(6), PTR(4))	/* And set it */
	ENTER_USER_ACCESS(w6, PTR(4))
	mov	w7, w1			/* Back up the compare value */
	.arch_extension lse
	ENTER_C64
#if __has_feature(capabilities)
	cas	w1, w3, [c0]		/* Compare and Swap */
#else
	cas	w1, w3, [x0]		/* Compare and Swap */
#endif
	EXIT_C64
	.arch_extension nolse
	cmp	w1, w7			/* Check if successful */
	cset	w0, ne			/* Return 0 on success, 1 on failure */
	EXIT_USER_ACCESS(w6)
	SET_FAULT_HANDLER(xzr, PTR(6))	/* Reset the fault handler */
	str	w1, [PTR(2)]		/* Store the read data */
	ret				/* Return */
END(casueword32_lse)

/*
 * int casueword_llsc(volatile u_long * __capability, u_long, u_long *, u_long)
 */
ENTRY(casueword_llsc)
	check_user_access 0, (VM_MAXUSER_ADDRESS-7), fsu_fault_nopcb
	adr	PTR(6), fsu_fault	/* Load the fault handler */
	mov	w5, #1
	SET_FAULT_HANDLER(PTR(6), PTR(4))	/* And set it */
	ENTER_USER_ACCESS(w6, PTR(4))
	ENTER_C64
#if __has_feature(capabilities)
	ldxr	x4, [c0]		/* Load-exclusive the data */
#else
	ldxr	x4, [x0]		/* Load-exclusive the data */
#endif
	cmp	x4, x1			/* Compare */
	b.ne	1f			/* Not equal, exit */
#if __has_feature(capabilities)
	stxr	w5, x3, [c0]		/* Store the new data */
#else
	stxr	w5, x3, [x0]		/* Store the new data */
#endif
1:	EXIT_C64
	EXIT_USER_ACCESS(w6)
	SET_FAULT_HANDLER(xzr, PTR(6))	/* Reset the fault handler */
	str	x4, [PTR(2)]		/* Store the read data */
	mov	w0, w5			/* Result same as store status */
	ret				/* Return */
END(casueword_llsc)

/*
 * int casueword_lse(volatile u_long * __capability, u_long, u_long *, u_long)
 */
ENTRY(casueword_lse)
	check_user_access 0, (VM_MAXUSER_ADDRESS-3), fsu_fault_nopcb
	adr	PTR(6), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(6), PTR(4))	/* And set it */
	ENTER_USER_ACCESS(w6, PTR(4))
	mov	x7, x1			/* Back up the compare value */
	.arch_extension lse
	ENTER_C64
#if __has_feature(capabilities)
	cas	x1, x3, [c0]		/* Compare and Swap */
#else
	cas	x1, x3, [x0]		/* Compare and Swap */
#endif
	EXIT_C64
	.arch_extension nolse
	cmp	x1, x7			/* Check if successful */
	cset	w0, ne			/* Return 0 on success, 1 on failure */
	EXIT_USER_ACCESS(w6)
	SET_FAULT_HANDLER(xzr, PTR(6))	/* Reset the fault handler */
	str	x1, [PTR(2)]		/* Store the read data */
	ret				/* Return */
END(casueword_lse)

.macro fsudata insn, ret_reg, user_arg
	adr	PTR(7), fsu_fault	/* Load the fault handler */
	SET_FAULT_HANDLER(PTR(7), PTR(6))	/* And set it */
	ENTER_C64
#if __has_feature(capabilities)
	\insn	\ret_reg, [c\user_arg]	/* Try accessing the data */
#else
	\insn	\ret_reg, [x\user_arg]	/* Try accessing the data */
#endif
	EXIT_C64
	SET_FAULT_HANDLER(xzr, PTR(6))	/* Reset the fault handler */
.endm

/*
 * int fubyte(volatile const void * __capability)
 */
ENTRY(fubyte)
	check_user_access 0, (VM_MAXUSER_ADDRESS), fsu_fault_nopcb
	fsudata	ldtrb, w0, 0
	ret				/* Return */
END(fubyte)

/*
 * int fuword(volatile const void * __capability)
 */
ENTRY(fuword16)
	check_user_access 0, (VM_MAXUSER_ADDRESS-1), fsu_fault_nopcb
	fsudata	ldtrh, w0, 0
	ret				/* Return */
END(fuword16)

/*
 * int32_t fueword32(volatile const void *, int32_t * __capability)
 */
ENTRY(fueword32)
	check_user_access 0, (VM_MAXUSER_ADDRESS-3), fsu_fault_nopcb
	fsudata	ldtr, w0, 0
	str	w0, [PTR(1)]		/* Save the data in kernel space */
	mov	w0, #0			/* Success */
	ret				/* Return */
END(fueword32)

/*
 * long fueword(volatile const void * __capability, int64_t *)
 * int64_t fueword64(volatile const void * __capability, int64_t *)
 */
ENTRY(fueword)
EENTRY(fueword64)
	check_user_access 0, (VM_MAXUSER_ADDRESS-7), fsu_fault_nopcb
	fsudata	ldtr, x0, 0
	str	x0, [PTR(1)]		/* Save the data in kernel space */
	mov	x0, #0			/* Success */
	ret				/* Return */
EEND(fueword64)
END(fueword)

#if __has_feature(capabilities)
/*
 * int fuecap(volatile const void * __capability, intcap_t *)
 */
ENTRY(fuecap)
	check_user_access 0, (VM_MAXUSER_ADDRESS-15), fsu_fault_nopcb
	fsudata	ldtr, c0, 0
	str	c0, [PTR(1)]		/* Save the data in kernel space */
	mov	x0, #0			/* Success */
	ret				/* Return */
END(fuecap)
#endif

/*
 * int subyte(volatile void * __capability, int)
 */
ENTRY(subyte)
	check_user_access 0, (VM_MAXUSER_ADDRESS), fsu_fault_nopcb
	fsudata	sttrb, w1, 0
	mov	x0, #0			/* Success */
	ret				/* Return */
END(subyte)

/*
 * int suword16(volatile void * __capability, int)
 */
ENTRY(suword16)
	check_user_access 0, (VM_MAXUSER_ADDRESS-1), fsu_fault_nopcb
	fsudata	sttrh, w1, 0
	mov	x0, #0			/* Success */
	ret				/* Return */
END(suword16)

/*
 * int suword32(volatile void * __capability, int)
 */
ENTRY(suword32)
	check_user_access 0, (VM_MAXUSER_ADDRESS-3), fsu_fault_nopcb
	fsudata	sttr, w1, 0
	mov	x0, #0			/* Success */
	ret				/* Return */
END(suword32)

/*
 * int suword(volatile void * __capability, long)
 */
ENTRY(suword)
EENTRY(suword64)
	check_user_access 0, (VM_MAXUSER_ADDRESS-7), fsu_fault_nopcb
	fsudata	sttr, x1, 0
	mov	x0, #0			/* Success */
	ret				/* Return */
EEND(suword64)
END(suword)

#if __has_feature(capabilities)
/*
 * int sucap(volatile void * __capability, intcap_t)
 */
ENTRY(sucap)
	check_user_access 0, (VM_MAXUSER_ADDRESS-15), fsu_fault_nopcb
	fsudata	sttr, c1, 0
	mov	x0, #0			/* Success */
	ret				/* Return */
END(sucap)
#endif

ENTRY(setjmp)
	/* Store the stack pointer */
	mov	PTR(8), PTRN(sp)
	str	PTR(8), [PTR(0)], #PTR_WIDTH

	/* Store the general purpose registers and lr */
	stp	PTR(19), PTR(20), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(21), PTR(22), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(23), PTR(24), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(25), PTR(26), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(27), PTR(28), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(29), PTRN(lr), [PTR(0)], #(2 * PTR_WIDTH)

	/* Return value */
	mov	x0, #0
	ret
END(setjmp)

ENTRY(longjmp)
	/* Restore the stack pointer */
	ldr	PTR(8), [PTR(0)], #PTR_WIDTH
	mov	PTRN(sp), PTR(8)

	/* Restore the general purpose registers and lr */
	ldp	PTR(19), PTR(20), [PTR(0)], #(2 * PTR_WIDTH)
	ldp	PTR(21), PTR(22), [PTR(0)], #(2 * PTR_WIDTH)
	ldp	PTR(23), PTR(24), [PTR(0)], #(2 * PTR_WIDTH)
	ldp	PTR(25), PTR(26), [PTR(0)], #(2 * PTR_WIDTH)
	ldp	PTR(27), PTR(28), [PTR(0)], #(2 * PTR_WIDTH)
	ldp	PTR(29), PTRN(lr), [PTR(0)], #(2 * PTR_WIDTH)

	/* Load the return value */
	mov	x0, x1
	ret
END(longjmp)

/*
 * pagezero, simple implementation
 */
ENTRY(pagezero_simple)
	add	PTR(1), PTR(0), #PAGE_SIZE

1:
	stp	PTR(zr), PTR(zr), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(zr), PTR(zr), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(zr), PTR(zr), [PTR(0)], #(2 * PTR_WIDTH)
	stp	PTR(zr), PTR(zr), [PTR(0)], #(2 * PTR_WIDTH)
	cmp	PTR(0), PTR(1)
	b.ne	1b
	ret

END(pagezero_simple)

/*
 * pagezero, cache assisted
 */
ENTRY(pagezero_cache)
	add	PTR(1), PTR(0), #PAGE_SIZE

	LDR_LABEL(x2, PTR(2), dczva_line_size)

1:
	dc	zva, PTR(0)
	add	PTR(0), PTR(0), x2
	cmp	PTR(0), PTR(1)
	b.ne	1b
	ret

END(pagezero_cache)
// CHERI CHANGES START
// {
//   "updated": 20221129,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
