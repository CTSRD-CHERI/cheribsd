/*-
 * Copyright (c) 2014 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Andrew Turner under
 * sponsorship from the FreeBSD Foundation.
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

/*
 * Pure-capability:
 *
 * void
 * _rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Auxinfo *aux)
 *
 * func_ptr_type
 * _rtld(Elf_Auxinfo *aux, func_ptr_type *exit_proc, Obj_Entry **objp)
 */

/*
 * Plain:
 *
 * func_ptr_type
 * _rtld(Elf_Addr *sp, func_ptr_type *exit_proc, Obj_Entry **objp)
 */

ENTRY(.rtld_start)
#ifdef __CHERI_PURE_CAPABILITY__
	.cfi_undefined	c30
	mov	c19, c0				/* Put aux in a callee-saved register */
	mov	c20, csp			/* And the stack pointer */

	sub	csp, csp, #32			/* Make room for obj_main & exit proc */

	adrp	c0, _DYNAMIC
	add	c0, c0, :lo12:_DYNAMIC		/* dynp */
	mov	c1, c19				/* aux */
	bl	_rtld_relocate_nonplt_self	/* Relocate ourselves early */

#if __CHERI_CAPABILITY_TABLE__ != 3
#error "Only the PC-relative ABI is currently supported"
#endif

	mov	c0, c19				/* Restore aux */
	scbnds	c1, csp, #16			/* exit_proc */
	add	c2, csp, #16
	scbnds	c2, c2, #16			/* obj_main */
	bl	_rtld				/* Call the loader */
	mov	c8, c0				/* Backup the entry point*/

	ldr	c1, [csp, #0]			/* Load cleanup */
	ldr	c2, [csp, #16]			/* Load obj_main */
	mov	c0, c19				/* Restore aux */
	mov	csp, c20			/* Restore the stack pointer */
#ifdef RTLD_SANDBOX
	mov	x9, xzr				/* Clear c9 for transitionary ABI */
	blr	c8				/* Jump to the entry point */
#else
	br	c8				/* Jump to the entry point */
#endif
#else /* defined(__CHERI_PURE_CAPABILITY__) */
	.cfi_undefined	x30
	mov	x19, x0		/* Put ps_strings in a callee-saved register */

	sub	sp, sp, #16	/* Make room for obj_main & exit proc */
	.cfi_adjust_cfa_offset	16

	mov	x1, sp		/* exit_proc */
	add	x2, x1, #8	/* obj_main */
	bl	_rtld		/* Call the loader */
	mov	x8, x0		/* Backup the entry point */
	ldp	x2, x1, [sp], #16 /* Load cleanup, obj_main */
	.cfi_adjust_cfa_offset	0

	mov	x0, x19		/* Restore ps_strings */
	br	x8		/* Jump to the entry point */
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
END(.rtld_start)

/*
 * sp + 0 = &GOT[x + 3]
 * sp + 8 = RA
 * x16 = &GOT[2]
 * x17 = &_rtld_bind_start
 */
ENTRY(_rtld_bind_start)
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	/*
	 * Calls to _rtld_bind_start do not go through the trampoline because
	 * _rtld_bind_start never returns, which would break the trampoline's
	 * invariant. But we still need to manually perform some of the
	 * trampoline's work, i.e., saving the caller's stack pointer at its
	 * bottom.
	 */
	mrs	c17, rcsp_el0
	.cfi_def_cfa_register c17
	.cfi_offset c30, (PTR_WIDTH)
	gclim	x10, c17
	scvalue c10, c17, x10
	str	c17, [c10, #-PTR_WIDTH]
#else
	mov	PTR(17), PTRN(sp)
#endif

	/* Save frame pointer and SP */
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	stp	PTR(29), PTR(17), [PTRN(sp), #-(PTR_WIDTH * 2)]!
	mov	PTR(29), PTRN(sp)
	.cfi_def_cfa PTR(29), (PTR_WIDTH * 2)
	.cfi_offset PTR(17), -(PTR_WIDTH * 1)
#else
	stp	PTR(29), PTR(30), [PTRN(sp), #-(PTR_WIDTH * 2)]!
	mov	PTR(29), PTRN(sp)
	.cfi_def_cfa PTR(29), (PTR_WIDTH * 2)
	.cfi_offset PTR(30), -(PTR_WIDTH * 1)
#endif
	.cfi_offset PTR(29), -(PTR_WIDTH * 2)

	/* Save the arguments */
	stp	CAP(0), CAP(1), [PTRN(sp), #-(CAP_WIDTH * 2)]!
	stp	CAP(2), CAP(3), [PTRN(sp), #-(CAP_WIDTH * 2)]!
	stp	CAP(4), CAP(5), [PTRN(sp), #-(CAP_WIDTH * 2)]!
	stp	CAP(6), CAP(7), [PTRN(sp), #-(CAP_WIDTH * 2)]!
	stp	CAP(8), CAP(9), [PTRN(sp), #-(CAP_WIDTH * 2)]!

	/* Save any floating-point arguments */
	stp	q0, q1, [PTRN(sp), #-32]!
	stp	q2, q3, [PTRN(sp), #-32]!
	stp	q4, q5, [PTRN(sp), #-32]!
	stp	q6, q7, [PTRN(sp), #-32]!

	/*
	 * Calculate gotoff and reloff. We have &GOT[x + 3] on the stack and
	 * &GOT[2], which gives x = &GOT[x + 3] - &GOT[2] - 1. We do our
	 * calculations still scaled by PTR_WIDTH and then re-scale to be
	 * reloff. Each Elf64_Rela is 24 bytes and each .plt.got entry is a
	 * single pointer, so we need to multiply by either 3 or 1.5 depending
	 * on whether this is a pure-capability ABI in order to turn it into
	 * reloff.
	 */
	ldr	PTR(2), [PTR(17), #0]	/* Get the address of the entry */
	sub	x1, x2, x16		/* Find its offset from &GOT[2] */
	sub	x1, x1, #PTR_WIDTH	/* Turn into an offset from &GOT[3] */
#ifdef __CHERI_PURE_CAPABILITY__
	lsr	x3, x1, #1		/* x3 = offset / 2 */
#else
	lsl	x3, x1, #1		/* x3 = 2 * offset */
#endif
	add	x1, x1, x3		/* reloff = x3 + offset = (3 or 1.5) * offset */

	/* Load obj */
	ldr	PTR(0), [PTR(16), #-PTR_WIDTH]

	/* Call into rtld */
	bl	_rtld_bind

	/* Backup the address to branch to */
	mov	PTR(16), PTR(0)

	/* restore the arguments */
	ldp	q6, q7, [PTRN(sp)], #32
	ldp	q4, q5, [PTRN(sp)], #32
	ldp	q2, q3, [PTRN(sp)], #32
	ldp	q0, q1, [PTRN(sp)], #32
	ldp	CAP(8), CAP(9), [PTRN(sp)], #(CAP_WIDTH * 2)
	ldp	CAP(6), CAP(7), [PTRN(sp)], #(CAP_WIDTH * 2)
	ldp	CAP(4), CAP(5), [PTRN(sp)], #(CAP_WIDTH * 2)
	ldp	CAP(2), CAP(3), [PTRN(sp)], #(CAP_WIDTH * 2)
	ldp	CAP(0), CAP(1), [PTRN(sp)], #(CAP_WIDTH * 2)

	/* Restore frame pointer */
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	ldp	PTR(29), PTR(17), [PTRN(sp)], #(PTR_WIDTH * 2)
#else
	ldp	PTR(29), PTR(zr), [PTRN(sp)], #(PTR_WIDTH * 2)
#endif

	 /* Restore link register saved by the plt code */
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	ldp	czr, c30, [c17], #(PTR_WIDTH * 2)
	msr	rcsp_el0, c17
#else
	ldp	PTR(zr), PTR(30), [PTRN(sp)], #(PTR_WIDTH * 2)
#endif

	/* Call into the correct function */
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	brr	PTR(16)
#else
	br	PTR(16)
#endif
END(_rtld_bind_start)

/*
 * struct rel_tlsdesc {
 *  uint64_t resolver_fnc;
 *  uint64_t resolver_arg;
 *
 *
 * uint64_t _rtld_tlsdesc_static(struct rel_tlsdesc *);
 *
 * Resolver function for TLS symbols resolved at load time
 */
ENTRY(_rtld_tlsdesc_static)
#ifdef __CHERI_PURE_CAPABILITY__
	ldp	x0, x1, [c0, #16]
	add	c0, c2, x0
	scbnds	c0, c0, x1
#ifdef RTLD_SANDBOX
	retr	c30
#else
	ret
#endif
#else /* defined(__CHERI_PURE_CAPABILITY__) */
	ldr	x0, [x0, #8]
	ret
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
END(_rtld_tlsdesc_static)

/*
 * uint64_t _rtld_tlsdesc_undef(void);
 *
 * Resolver function for weak and undefined TLS symbols
 */
ENTRY(_rtld_tlsdesc_undef)
#ifdef __CHERI_PURE_CAPABILITY__
	ldr	x0, [c0, #16]
#ifdef RTLD_SANDBOX
	retr	c30
#else
	ret
#endif
#else /* defined(__CHERI_PURE_CAPABILITY__) */
	str	x1, [sp, #-16]!
	.cfi_adjust_cfa_offset	16

	mrs	x1, tpidr_el0
	ldr	x0, [x0, #8]
	sub	x0, x0, x1

	ldr	x1, [sp], #16
	.cfi_adjust_cfa_offset 	-16
	ret
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
END(_rtld_tlsdesc_undef)

/*
 * uint64_t _rtld_tlsdesc_dynamic(struct rel_tlsdesc *);
 *
 * Resolver function for TLS symbols from dlopen()
 */
ENTRY(_rtld_tlsdesc_dynamic)
#ifdef __CHERI_PURE_CAPABILITY__
	stp	c3, c4, [csp, #-32]!
	.cfi_adjust_cfa_offset	2 * 16
	.cfi_rel_offset		c3, 0
	.cfi_rel_offset		c4, 16

	/* Test fastpath - inlined version of tls_get_addr_common(). */
	ldr	c1, [c0, #16]
	ldr	c0, [c2]		/* DTV pointer */
	ldr	x3, [c0]		/* dtv[0] (generation count) */
	ldr	x4, [c1]		/* tlsdesc->dtv_gen */
	cmp	x3, x4
	b.ne	1f			/* dtv[0] != tlsdec->dtv_gen */

	ldr	w3, [c1, #16]		/* tlsdesc->tls_index */
	add	w3, w3, #1
	ldr     c3, [c0, w3, sxtw #4]	/* dtv[tlsdesc->tls_index + 1] */
	cbz	x3, 1f

	/* Return (dtv[tlsdesc->tls_index + 1] + tlsdesc->tls_offs) */
	ldr	x4, [c1, #24]		/* tlsdesc->tls_offs */
	add 	c3, c3, x4
	ldr	x4, [c1, #32]		/* tlsdesc->tls_size */
	scbnds	c0, c3, x4

	/* Restore registers and return */
	ldp	 c3,  c4, [csp], #32
	.cfi_adjust_cfa_offset 	-2 * 16
#ifdef RTLD_SANDBOX
	retr	c30
#else
	ret
#endif

	/*
	 * Slow path
	 * return(
	 *    tls_get_addr_common(tp, tlsdesc->tls_index, tlsdesc->tls_offs));
	 *
	 */
1:
#ifdef RTLD_SANDBOX
	/*
	 * Caller must be Restricted, so save its rcsp at the bottom of its own
	 * stack. This step is only needed for _rtld_tlsdesc_dynamic because it
	 * might call external functions.
	 *
	 * For the same reason, the Restricted stack needs to be saved and
	 * restored upon return.
	 */
	mrs	c3, rcsp_el0
	gclim	x4, c3
	scvalue	c4, c3, x4
	str	c3, [c4, #-CAP_WIDTH]
#endif

	/* Save non-callee-saved capability registers as well as c19 */
	stp	c29, c30, [csp, #-(10 * 32)]!
	.cfi_adjust_cfa_offset	10 * 32
	.cfi_rel_offset		c29, 0
	.cfi_rel_offset		c30, 16

	mov	c29, csp
	stp	c1,   c2, [csp, #(1 * 32)]
	stp	c5,   c6, [csp, #(2 * 32)]
	stp	c7,   c8, [csp, #(3 * 32)]
	stp	c9,  c10, [csp, #(4 * 32)]
	stp	c11, c12, [csp, #(5 * 32)]
	stp	c13, c14, [csp, #(6 * 32)]
	stp	c15, c16, [csp, #(7 * 32)]
	stp	c17, c18, [csp, #(8 * 32)]
#ifdef RTLD_SANDBOX
	stp	c19,  c3, [csp, #(9 * 32)]
	.cfi_rel_offset		 c3, 304
#else
	str	c19,	  [csp, #(9 * 32)]
#endif
	.cfi_rel_offset		 c1, 32
	.cfi_rel_offset		 c2, 48
	.cfi_rel_offset		 c5, 64
	.cfi_rel_offset		 c6, 80
	.cfi_rel_offset		 c7, 96
	.cfi_rel_offset		 c8, 112
	.cfi_rel_offset		 c9, 128
	.cfi_rel_offset		c10, 144
	.cfi_rel_offset		c11, 160
	.cfi_rel_offset		c12, 176
	.cfi_rel_offset		c13, 192
	.cfi_rel_offset		c14, 208
	.cfi_rel_offset		c15, 224
	.cfi_rel_offset		c16, 240
	.cfi_rel_offset		c17, 256
	.cfi_rel_offset		c18, 272
	.cfi_rel_offset		c19, 288

	/* Find the tls offset */
	mov	c0, c2			/* tp */
	mov	c3, c1			/* tlsdesc ptr */
	ldr	w1, [c3, #16]		/* tlsdesc->tls_index */
	ldr	x2, [c3, #24]		/* tlsdesc->tls_offs */
	ldr	x19, [c3, #32]		/* tlsdesc->tls_size */
	bl	tls_get_addr_common
	scbnds	c0, c0, x19

	/* Restore slow path registers */
#ifdef RTLD_SANDBOX
	ldp	c19,  c3, [csp, #(9 * 32)]
	msr	rcsp_el0, c3
#else
	ldr	c19,	  [csp, #(9 * 32)]
#endif
	ldp	c17, c18, [csp, #(8 * 32)]
	ldp	c15, c16, [csp, #(7 * 32)]
	ldp	c13, c14, [csp, #(6 * 32)]
	ldp	c11, c12, [csp, #(5 * 32)]
	ldp	c9, c10,  [csp, #(4 * 32)]
	ldp	c7, c8,   [csp, #(3 * 32)]
	ldp	c5, c6,   [csp, #(2 * 32)]
	ldp	c1, c2,   [csp, #(1 * 32)]
	ldp	c29, c30, [csp], #(10 * 32)
	.cfi_adjust_cfa_offset 	-10 * 32
	.cfi_restore		c29
	.cfi_restore		c30

	/* Restore fast path registers and return */
	ldp	 c3,  c4, [csp], #32
	.cfi_adjust_cfa_offset 	-2 * 16
#ifdef RTLD_SANDBOX
	retr	c30
#else
	ret
#endif
#else /* defined(__CHERI_PURE_CAPABILITY__) */
	/* Save registers used in fast path */
	stp	x1,  x2, [sp, #(-2 * 16)]!
	stp	x3,  x4, [sp, #(1 * 16)]
	.cfi_adjust_cfa_offset	2 * 16
	.cfi_rel_offset		x1, 0
	.cfi_rel_offset		x2, 8
	.cfi_rel_offset		x3, 16
	.cfi_rel_offset		x4, 24

	/* Test fastpath - inlined version of tls_get_addr_common(). */
	ldr	x1, [x0, #8]		/* tlsdesc ptr */
	mrs	x4, tpidr_el0
	ldr	x0, [x4]		/* DTV pointer */
	ldr	x2, [x0]		/* dtv[0] (generation count) */
	ldr	x3, [x1]		/* tlsdec->dtv_gen */
	cmp	x2, x3
	b.ne	1f			/* dtv[0] != tlsdec->dtv_gen */

	ldr	w2, [x1, #8]		/* tlsdec->tls_index */
	add	w2, w2, #1
	ldr     x3, [x0, w2, sxtw #3]	/* dtv[tlsdesc->tls_index + 1] */
	cbz	x3, 1f

	/* Return (dtv[tlsdesc->tls_index + 1] + tlsdesc->tls_offs - tp) */
	ldr	x2, [x1, #16]		/* tlsdec->tls_offs */
	add 	x2, x2, x3
	sub	x0, x2, x4
	/* Restore registers and return */
	ldp	 x3,  x4, [sp, #(1 * 16)]
	ldp	 x1,  x2, [sp], #(2 * 16)
	.cfi_adjust_cfa_offset 	-2 * 16
	ret

	/*
	 * Slow path
	  * return(
	 *    tls_get_addr_common(tp, tlsdesc->tls_index, tlsdesc->tls_offs));
	 *
	 */
1:
	/* Save all integer registers */
	stp	x29, x30, [sp, #-(8 * 16)]!
	.cfi_adjust_cfa_offset	8 * 16
	.cfi_rel_offset		x29, 0
	.cfi_rel_offset		x30, 8

	mov	x29, sp
	stp	x5,   x6, [sp, #(1 * 16)]
	stp	x7,   x8, [sp, #(2 * 16)]
	stp	x9,  x10, [sp, #(3 * 16)]
	stp	x11, x12, [sp, #(4 * 16)]
	stp	x13, x14, [sp, #(5 * 16)]
	stp	x15, x16, [sp, #(6 * 16)]
	stp	x17, x18, [sp, #(7 * 16)]
	.cfi_rel_offset		 x5, 16
	.cfi_rel_offset		 x6, 24
	.cfi_rel_offset		 x7, 32
	.cfi_rel_offset		 x8, 40
	.cfi_rel_offset		 x9, 48
	.cfi_rel_offset		x10, 56
	.cfi_rel_offset		x11, 64
	.cfi_rel_offset		x12, 72
	.cfi_rel_offset		x13, 80
	.cfi_rel_offset		x14, 88
	.cfi_rel_offset		x15, 96
	.cfi_rel_offset		x16, 104
	.cfi_rel_offset		x17, 112
	.cfi_rel_offset		x18, 120

	/* Find the tls offset */
	mov	x0, x4			/* tp */
	mov	x3, x1			/* tlsdesc ptr */
	ldr	w1, [x3, #8]		/* tlsdec->tls_index */
	ldr	x2, [x3, #16]		/* tlsdec->tls_offs */
	bl	tls_get_addr_common
	mrs	x1, tpidr_el0
	sub	x0, x0, x1

	/* Restore slow patch registers */
	ldp	x17, x18, [sp, #(7 * 16)]
	ldp	x15, x16, [sp, #(6 * 16)]
	ldp	x13, x14, [sp, #(5 * 16)]
	ldp	x11, x12, [sp, #(4 * 16)]
	ldp	x9, x10,  [sp, #(3 * 16)]
	ldp	x7, x8,   [sp, #(2 * 16)]
	ldp	x5, x6,   [sp, #(1 * 16)]
	ldp	x29, x30, [sp], #(8 * 16)
	.cfi_adjust_cfa_offset 	-8 * 16
	.cfi_restore		x29
	.cfi_restore		x30

	/* Restore fast path registers and return */
	ldp	 x3,  x4, [sp, #16]
	ldp	 x1,  x2, [sp], #(2 * 16)
	.cfi_adjust_cfa_offset	-2 * 16
	ret
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
END(_rtld_tlsdesc_dynamic)

#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
ENTRY(_rtld_setjmp)
	/*
	 * This function MUST save the callee-saved registers in the c0 buffer.
	 *
	 * Before setjmp is called, the top of the Executive stack contains:
	 * 	-3.	Caller's data
	 * 	-2.	Caller's stack
	 * 	-1.	Return address
	 * 	0.	Link to previous frame
	 * When setjmp is called, the following is pushed to the Executive
	 * stack:
	 * 	1.	Caller's data
	 * 	2.	Caller's stack
	 * 	3.	Return address
	 * 	4.	Link to 0
	 * setjmp then calls _rtld_setjmp, which pushes the following:
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * In _rtld_setjmp, we manipulate the stack content to the following:
	 * 	-6.	Copy of 2
	 * 	-5.	Copy of 3
	 * 	-4.	Link to 0
	 * 	-3.	Caller's data
	 * 	-2.	Caller's stack
	 * 	-1.	Return address
	 * 	0.	Link to previous frame
	 * 	------------------------------
	 * 	1.	Caller's data
	 * 	2.	Caller's stack
	 * 	3.	Return address
	 * 	4.	Link to 0
	 * 	------------------------------
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * To do this, we shift everything from -3 to 8 by 3 positions.
	 */

#define	SETJMP_SHIFT	3
	/*
	 * Move 8 and adjust it's cursor.
	 * Also adjust csp.
	 */
	ldr	c2, [csp], #-(SETJMP_SHIFT * CAP_WIDTH)
	sub	c2, c2, #(SETJMP_SHIFT * CAP_WIDTH)
	str	c2, [csp]

	add	c1, csp, #CAP_WIDTH

	/* Shift 5, 6, and 7 */
1:	ldr	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	str	c3, [c1], #CAP_WIDTH
	cmp	x1, x2
	b.ne	1b

	/* Save link to 4 for buffer */
	mov	c4, c1

	ldp	c19, c20, [c1, #((SETJMP_SHIFT + 3) * CAP_WIDTH)]
	ldp	c21, c22, [c1, #((SETJMP_SHIFT + 5) * CAP_WIDTH)]
	ldp	c23, c24, [c1, #((SETJMP_SHIFT + 7) * CAP_WIDTH)]
	ldp	c25, c26, [c1, #((SETJMP_SHIFT + 9) * CAP_WIDTH)]
	ldp	c27, c28, [c1, #((SETJMP_SHIFT + 11) * CAP_WIDTH)]
	ldr	c29, [c1, #((SETJMP_SHIFT + 13) * CAP_WIDTH)]

	stp	c19, c20, [c0, #(CAP_WIDTH * 1)]
	stp	c21, c22, [c0, #(CAP_WIDTH * 3)]
	stp	c23, c24, [c0, #(CAP_WIDTH * 5)]
	stp	c25, c26, [c0, #(CAP_WIDTH * 7)]
	stp	c27, c28, [c0, #(CAP_WIDTH * 9)]
	str	c29, [c0, #(CAP_WIDTH * 11)]

	/* Shift 4 and adjust it's cursor */
	ldr	c2, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	sub	c2, c2, #(SETJMP_SHIFT * CAP_WIDTH)
	str	c2, [c1], #CAP_WIDTH

	/* Shift 1, 2, and 3 */
2:	ldr	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	str	c3, [c1], #CAP_WIDTH
	cmp	x1, x2
	b.ne	2b

	/* Shift 0 */
	ldr	c2, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	str	c2, [c1], #CAP_WIDTH
	sub	c2, c2, #(SETJMP_SHIFT * CAP_WIDTH)

	/* Load RTLD sealer to detect other jump buffers */
	ldr	c5, sealer_jmpbuf

	/* Shift -3, -2, and -1 */
3:	ldr	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	unseal	c6, c3, c5
	gctag	x6, c6
	cbnz	x6, 4f
	str	c3, [c1], #CAP_WIDTH
	cmp	x1, x2
	b.ne	3b
	b	5f

4:	seal	c3, c1, c5
	str	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]

	/* Store -4, -5, and -6 */
5:	ldr	c2, [c4]
	ldp	c3, c4, [c4, #CAP_WIDTH]
	seal	c2, c2, c5
	str	c2, [c1]
	stp	c3, c4, [c1, #CAP_WIDTH]

	scbnds	c1, c1, #(SETJMP_SHIFT * CAP_WIDTH)
	seal	c1, c1, c5
	str	c1, [c0], #(CAP_WIDTH * 12)

	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	mov	x1, xzr
	ret
END(_rtld_setjmp)

ENTRY(_rtld_longjmp)
	/*
	 * This function MUST preserve the value of x1 and update c0 to point at
	 * the value of lr to be restored.
	 *
	 * Before longjmp is called, the top of the Executive stack contains:
	 * 	0.	Link to previous frame
	 * When longjmp is called, the following is pushed to the Executive
	 * stack:
	 * 	1.	Caller's data
	 * 	2.	Caller's stack
	 * 	3.	Return address
	 * 	4.	Link to 0
	 * longjmp then calls _rtld_longjmp, which pushes the following:
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * In _rtld_longjmp, we manipulate the stack content to the following:
	 * 	-n.	Link to previous frame
	 * 	------------------------------
	 * 	...
	 * 	0.	Link to previous frame
	 * 	------------------------------
	 * 	1.	Supplied caller's data
	 * 	2.	Supplied caller's stack
	 * 	3.	Supplied return address
	 * 	4.	Link to supplied Executive stack pointer (-n)
	 * 	------------------------------
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * When longjmp makes its final branch, it will go to the returning
	 * phase of setjmp's trampoline, which unwinds to the frame and PC
	 * supplied by 3.
	 */

	/*
	 * Load link to the supplied buffer
	 * c2: Link to the supplied buffer
	 */
	ldr	c2, [c0], #CAP_WIDTH

	/* Check that the supplied buffer is on the current Executive stack */
	chkssu	c2, c2, csp
	b.pl	1f

	/* Check that the supplied buffer is below the top of the stack */
	cmp	sp, x2
	b.hs	1f

	/*
	 * All sanity checks have passed
	 * Locate the frame of the supplied buffer
	 * c2: Frame of the supplied buffer
	 */
	ldr	c4, [c2]
	ldr	c5, sealer_jmpbuf
2:	unseal	c3, c4, c5
	ldr	c4, [c3]
	gcseal	x6, c4
	cbnz	x6, 2b

	/*
	 * Get the previous frame.
	 * c4: Previous frame
	 */
	ldr	c4, [csp]

	/* Unwind the frames */
	mov	c5, c4
4:	ldr	c5, [c5]
	cmp	c5, c3
	b.eq	3f

	/* Enforce security policy here for each frame being unwound */
	b	4b

3:	ldp	c2, c5, [c2, #CAP_WIDTH]

	/* Restore general purpose registers */
	ldp	c19, c20, [c0], #(CAP_WIDTH * 2)
	ldp	c21, c22, [c0], #(CAP_WIDTH * 2)
	ldp	c23, c24, [c0], #(CAP_WIDTH * 2)
	ldp	c25, c26, [c0], #(CAP_WIDTH * 2)
	ldp	c27, c28, [c0], #(CAP_WIDTH * 2)
	ldr	c29, [c0], #CAP_WIDTH

	/* Update frame and save callee-saved registers */
	stp	c3, c2, [c4]
	stp	c5, c19, [c4, #(CAP_WIDTH * 2)]
	stp	c20, c21, [c4, #(CAP_WIDTH * 4)]
	stp	c22, c23, [c4, #(CAP_WIDTH * 6)]
	stp	c24, c25, [c4, #(CAP_WIDTH * 8)]
	stp	c26, c27, [c4, #(CAP_WIDTH * 10)]
	stp	c28, c29, [c4, #(CAP_WIDTH * 12)]

	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	ret

	/* TODO: Abort */
1:	ret
END(_rtld_longjmp)

ENTRY(_rtld_get_rstk)
	/*
	 * This function MUST preserve all caller-saved registers and return the
	 * requested stack except:
	 * - c11: Target restricted stack
	 * - c18: Code capability to this function
	 */
	stp	c17, c30, [csp, #-(CAP_WIDTH * 2)]
	stp	c15, c16, [csp, #-(CAP_WIDTH * 4)]
	stp	c13, c14, [csp, #-(CAP_WIDTH * 6)]
	stp	c10, c12, [csp, #-(CAP_WIDTH * 8)]
	stp	c8, c9, [csp, #-(CAP_WIDTH * 10)]
	stp	c6, c7, [csp, #-(CAP_WIDTH * 12)]
	stp	c4, c5, [csp, #-(CAP_WIDTH * 14)]
	stp	c2, c3, [csp, #-(CAP_WIDTH * 16)]
	stp	c0, c1, [csp, #-(CAP_WIDTH * 18)]!
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	mov	c0, c10					/* c0 = data */
	mov	w1, w12					/* w1 = index */
	mrs	c2, ctpidr_el0				/* c2 = table */

	bl	get_rstk
	mov	c11, c0

	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)
	ldp	c17, c30, [csp, #(CAP_WIDTH * 16)]
	ldp	c15, c16, [csp, #(CAP_WIDTH * 14)]
	ldp	c13, c14, [csp, #(CAP_WIDTH * 12)]
	ldp	c10, c12, [csp, #(CAP_WIDTH * 10)]
	ldp	c8, c9, [csp, #(CAP_WIDTH * 8)]
	ldp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	ldp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	ldp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	ldp	c0, c1, [csp], #(CAP_WIDTH * 18)

	ret
END(_rtld_get_rstk)

/*
 * Trampoline templates are code but reside in rodata. Hence a new macro is
 * defined to describe them.
 */
#define TRAMP(sym) \
	.section .rodata; .globl sym; .type sym,#object; sym:

#define TRAMPEND(sym) \
	end_##sym: \
	EEND(sym); \
	.section .rodata; .globl size_##sym; .align 3; .type size_##sym,#object; \
	.size size_##sym, 8; size_##sym: \
	.quad	end_##sym - sym

TRAMP(tramp_header)
tramp_header_target:
	.chericap	0
	ldr	c10, tramp_header_target
	mrs	c17, rcsp_el0
	mov	c18, csp

	/* Push frame */
	stp	c28, c29, [csp, #-(CAP_WIDTH * 2)]
	stp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	stp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	stp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	stp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	stp	c17, c19, [csp, #-(CAP_WIDTH * 12)]
	stp	c18, c30, [csp, #-(CAP_WIDTH * 14)]!
TRAMPEND(tramp_header)

TRAMP(tramp_header_hook)
tramp_header_hook_obj:
	.chericap	0
tramp_header_hook_def:
	.chericap	0
tramp_header_hook_function:
	.chericap	0
tramp_header_hook_target:
	.chericap	0
	ldr	c10, tramp_header_hook_obj
	ldr	c11, tramp_header_hook_def
	ldr	c12, tramp_header_hook_function
	mrs	c17, rcsp_el0
	mov	c18, csp

	str	c12, [csp, #-CAP_WIDTH]
	stp	c10, c11, [csp, #-(CAP_WIDTH * 3)]!

	/* Push frame */
	stp	c28, c29, [csp, #-(CAP_WIDTH * 2)]
	stp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	stp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	stp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	stp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	stp	c17, c19, [csp, #-(CAP_WIDTH * 12)]
	stp	c18, c30, [csp, #-(CAP_WIDTH * 14)]!

	/* Save argument registers */
	stp	c8, c9, [csp, #-(CAP_WIDTH * 2)]
	stp	c6, c7, [csp, #-(CAP_WIDTH * 4)]
	stp	c4, c5, [csp, #-(CAP_WIDTH * 6)]
	stp	c2, c3, [csp, #-(CAP_WIDTH * 8)]
	stp	c0, c1, [csp, #-(CAP_WIDTH * 10)]!
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	mov	w0, #0
	ldr	c1, tramp_header_hook_target
	mov	c2, c10
	mov	c3, c11
	blr	c12

	/* Restore argument registers */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)
	ldp	c8, c9, [csp, #(CAP_WIDTH * 8)]
	ldp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	ldp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	ldp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	ldp	c0, c1, [csp], #(CAP_WIDTH * 10)
	ldp	c30, c17, [csp, #CAP_WIDTH]
	ldr	c10, tramp_header_hook_target
TRAMPEND(tramp_header_hook)

TRAMP(tramp_header_res)
	mrs	c18, ctpidr_el0	/* c18 = table */
	movz	w12, #0		/* w12 = index, to be patched at runtime */
	gclen	x13, c18	/* x13 = len(table) */
TRAMPEND(tramp_header_res)

TRAMP(tramp_save_caller)
	/*
	 * If caller is Restricted, save its rcsp at the bottom of its own stack.
	 * Otherwise, the caller is RTLD or Restricted code performing a
	 * tail-call. In either case, there is no need to save the rcsp of the
	 * caller. This step must be done before the table lookup so that
	 * same-compartment switches get the correct stack.
	 */
	gcperm	x14, c30
	tbnz	x14, #1, 1f
	gclim	x15, c17
	scvalue	c16, c17, x15
	str	c17, [c16, #-CAP_WIDTH]

	/*
	 * Save the number of unused return value registers in the flags of csp.
	 */
1:	movz	x16, #0
	scflgs	csp, csp, x16
TRAMPEND(tramp_save_caller)

TRAMP(tramp_switch_stack)
	/*
	 * Callee is Restricted, so switch to its saved rcsp at the bottom of
	 * itself.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	x17, x13, x12, lsl #4		/* if (len(table) <= index) */
	b.ls	2f				/* goto 2f */
	ldr	c11, [c18, w12, uxtw #4]	/* c11 = table[index] */
	cbnz	x11, 3f
	/*
	 * Call get_rstk(), which may invoke Restricted code (e.g. locking
	 * procedures in libthr), causing another trampoline to run. The
	 * implications of re-entrancy must be carefully addressed.
	 */
2:	blr	[c18, #0]			/* get_rstk() */
3:	ldr	c11, [c11, #-CAP_WIDTH]

	/* Move the c9 buffer to the target stack */
	cbz	x9, 6f
	gclen	x16, c9
	add	c17, c9, x16
	lsr	x16, x16, #4
	tst	x17, #0xf
	b.eq	5f

	orr	x18, x17, #0xfffffffffffffff0
	add	c11, c11, x18
7:	ldrb	w18, [c17, #-1]!
	strb	w18, [c11, #-1]!
	tst	x17, #0xf
	b.ne	7b

4:	cbz	x16, 6f
5:	ldr	c18, [c17, #-CAP_WIDTH]!
	str	c18, [c11, #-CAP_WIDTH]!
	sub	x16, x16, #1
	b	4b
6:
TRAMPEND(tramp_switch_stack)

TRAMP(tramp_invoke_exe)
	blr	c10

	/* Restore callee-saved registers */
	ldp	c18, c30, [csp], #(CAP_WIDTH * 14)
	ldp	c10, c19, [csp, #-(CAP_WIDTH * 12)]
	ldp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	ldp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	ldp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	ldp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	ldp	c28, c29, [csp, #-(CAP_WIDTH * 2)]

	/* Clear c11 */
	mov	x11, xzr
TRAMPEND(tramp_invoke_exe)

TRAMP(tramp_clear_regs)
	mov	x9, xzr
	mov	x8, xzr
	mov	x7, xzr
	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	mov	x1, xzr
	mov	x0, xzr
TRAMPEND(tramp_clear_regs)

TRAMP(tramp_invoke_res)
	/* Clear callee-saved registers */
	mov	x29, xzr
	mov	x28, xzr
	mov	x27, xzr
	mov	x26, xzr
	mov	x25, xzr
	mov	x24, xzr
	mov	x23, xzr
	mov	x22, xzr
	mov	x21, xzr
	mov	x20, xzr
	mov	x19, xzr

	/*
	 * Clear temporary registers, except
	 * - c10: Callee's code
	 * - c11: Callee's stack
	 * - c12: Callee's compartment ID (scalar)
	 * - c13: Length of stack table (scalar)
	 * - c14: Permissions of c30 (scalar)
	 * - c15: Limit of caller's stack (scalar)
	 * - c16: Flags of csp (scalar)
	 * - c17: Comparison result (scalar)
	 */
	mov	x18, xzr

	msr	rcsp_el0, c11
	blrr	c10

	/* Restore callee-saved registers */
	ldp	c18, c30, [csp], #(CAP_WIDTH * 14)
	ldp	c10, c19, [csp, #-(CAP_WIDTH * 12)]
	ldp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	ldp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	ldp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	ldp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	ldp	c28, c29, [csp, #-(CAP_WIDTH * 2)]

	/*
	 * Callee's saved rcsp may have changed during the call (e.g. because it
	 * called into another compartment). Restore it to the correct value
	 * here.
	 */
	mrs	c12, rcsp_el0
	gclim	x11, c12
	scvalue	c13, c12, x11
	str	c12, [c13, #-CAP_WIDTH]
TRAMPEND(tramp_invoke_res)

TRAMP(tramp_return_hook)
	/* Save return value registers */
	swp	c0, c2, [csp]
	add	csp, csp, #CAP_WIDTH
	swp	c1, c3, [csp]

	/* Save temporary registers and return address */
	add	csp, csp, #CAP_WIDTH
	swp	c10, c4, [csp]
	stp	c18, c30, [csp, #-(CAP_WIDTH * 4)]!

	/* Save floating point registers */
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	mov	w0, #1
	mov	x1, xzr
	blr	c4

	/* Restore floating point registers */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)

	/* Restore temporary registers and return address */
	ldp	c18, c30, [csp], #(CAP_WIDTH * 2)
	ldp	c0, c1, [csp], #(CAP_WIDTH * 2)
	ldr	c10, [csp], #CAP_WIDTH
	mov	x11, xzr
TRAMPEND(tramp_return_hook)

TRAMP(tramp_return)
	/*
	 * Clear unused return value registers. The registers to clear is
	 * encoded as follows and stored in the flags of csp:
	 * - None:	0b00
	 * - c1 only:	0b01
	 * - c0 and c1:	0b1x
	 * Use comparison and csel to avoid branching.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	gcflgs	x12, csp
	subs	x13, x12, #0b01
	csel	c1, czr, c1, hs
	csel	c0, czr, c0, hi

	mov	x9, xzr
	mov	x8, xzr
	mov	x7, xzr
	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr

	/*
	 * Clear temporary registers, except
	 * - c10: Caller's stack
	 * - c11: Limit of callee's stack (scalar) or zero
	 * - c12: Flags of csp (scalar)
	 * - c13: Comparison result (scalar)
	 */
	mov	x17, xzr
	mov	x16, xzr
	mov	x15, xzr
	mov	x14, xzr

	mov	csp, c18
	mov	x18, xzr

	/*
	 * Restore caller's saved rcsp (has no effect if the caller is
	 * Executive).
	 */
	msr	rcsp_el0, c10
	retr	c30
TRAMPEND(tramp_return)
#endif
