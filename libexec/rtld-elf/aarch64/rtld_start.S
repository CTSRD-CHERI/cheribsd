/*-
 * Copyright (c) 2014 The FreeBSD Foundation
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
#include <sys/cdefs.h>
#include <sys/elf_common.h>

#define	IN_ASM
#include "rtld_c18n_machdep.h"
#undef IN_ASM

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

	adrp	c0, _DYNAMIC
	add	c0, c0, :lo12:_DYNAMIC		/* dynp */
	mov	c1, c19				/* aux */
	bl	_rtld_relocate_nonplt_self	/* Relocate ourselves early */

#if __CHERI_CAPABILITY_TABLE__ != 3
#error "Only the PC-relative ABI is currently supported"
#endif

	mov	c20, csp			/* Save the stack pointer */
	sub	csp, csp, #32			/* Make room for obj_main & exit proc */

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
#if defined(__ARM_MORELLO_PURECAP_BENCHMARK_ABI)
	br	x8				/* Jump to the entry point */
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
	mov	PTR(17), PTRN(sp)

	/* Save frame pointer and SP */
	stp	PTR(29), PTR(30), [PTRN(sp), #-(PTR_WIDTH * 2)]!
	mov	PTR(29), PTRN(sp)
	.cfi_def_cfa PTR(29), (PTR_WIDTH * 2)
	.cfi_offset PTR(30), -(PTR_WIDTH * 1)
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

	/* Load plt */
	ldr	PTR(0), [PTR(16), #-PTR_WIDTH]

	/* Call into rtld */
	adrp	PTR(10), :got:rtld_bind_fptr
	ldr	PTR(10), [PTR(10), :got_lo12:rtld_bind_fptr]
	ldr	PTR(10), [PTR(10)]
	/* Under c18n, the trampoline always clear c10, a scratch register. */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x10
#else
	blr	PTR(10)
#endif

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
	ldp	PTR(29), PTR(zr), [PTRN(sp)], #(PTR_WIDTH * 2)

	/* Restore link register saved by the plt code */
	ldp	PTR(zr), PTR(30), [PTRN(sp)], #(PTR_WIDTH * 2)

	/* Call into the correct function */
#if defined(__ARM_MORELLO_PURECAP_BENCHMARK_ABI)
	br	x16
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
	RETURN
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
	RETURN
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
	RETURN

	/*
	 * Slow path
	 * return(
	 *    tls_get_addr_common(tcb, tlsdesc->tls_index, tlsdesc->tls_offs));
	 *
	 */
1:
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
	str	c19,	  [csp, #(9 * 32)]
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
	mov	c0, c2			/* tcb */
	mov	c3, c1			/* tlsdesc ptr */
	ldr	w1, [c3, #16]		/* tlsdesc->tls_index */
	ldr	x2, [c3, #24]		/* tlsdesc->tls_offs */
	ldr	x19, [c3, #32]		/* tlsdesc->tls_size */
	adrp	PTR(10), :got:tls_get_addr_common_fptr
	ldr	PTR(10), [PTR(10), :got_lo12:tls_get_addr_common_fptr]
	ldr	PTR(10), [PTR(10)]
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x10
#else
	blr	PTR(10)
#endif
	scbnds	c0, c0, x19

	/* Restore slow path registers */
	ldr	c19,	  [csp, #(9 * 32)]
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
	RETURN
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
	 *    tls_get_addr_common(tcb, tlsdesc->tls_index, tlsdesc->tls_offs));
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
	mov	x0, x4			/* tcb */
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

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
