/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Jessica Clarke
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
#include <machine/armreg.h>

#include "assym.inc"

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * int efi_rt_arch_call_nofault(struct efirt_callinfo *ec)
 *
 * Wrap EFI calls to save caller-saved capability registers until we have a
 * pure-capability interface.
 *
 * NB: This temporarily installs an almighty DDC.
 */
ENTRY(efi_rt_arch_call_nofault)
	sub	csp, csp, #(17 * PTR_WIDTH)

	/*
	 * Save all capability registers that should be callee-saved, plus save
	 * the efirt_callinfo pointer so we can set ec_efi_status on return.
	 */
	stp	c16, c17, [csp]
	stp	c18, c19, [csp, #(2 * PTR_WIDTH)]
	stp	c20, c21, [csp, #(4 * PTR_WIDTH)]
	stp	c22, c23, [csp, #(6 * PTR_WIDTH)]
	stp	c24, c25, [csp, #(8 * PTR_WIDTH)]
	stp	c26, c27, [csp, #(10 * PTR_WIDTH)]
	stp	c28, c29, [csp, #(12 * PTR_WIDTH)]
	stp	c30,  c0, [csp, #(14 * PTR_WIDTH)]

	/* Save CSP as the metadata will be clobbered by the EFI call */
	mov	c8, csp
	str	c8, [csp, #(16 * PTR_WIDTH)]

	/* Get the number of arguments for the EFI call */
	ldr	x8, [c0, #EC_ARGCNT]

	/* Check we have no more than 5 arguments */
	cmp	x8, #5
	b.hi	1f

	/* Get target function pointer */
	ldr	c6, [c0, #EC_FPTR]

	/* Jump to 0f + 4 * (5 - ec_argcnt) + 1 */
	adr	c9, 0f + 1
	mov	x10, #20
	sub	x8, x10, x8, lsl #2
	add	c9, c9, x8, uxtx
	br	c9

	/* Load the arguments into registers */
0:	ldr	x4, [c0, #EC_ARG5]
	ldr	x3, [c0, #EC_ARG4]
	ldr	x2, [c0, #EC_ARG3]
	ldr	x1, [c0, #EC_ARG2]
	ldr	x0, [c0, #EC_ARG1]

	/* Install almighty DDC just for EFI (and our CSP restore) */
	adrp	c7, :got:kernel_root_cap
	ldr	c7, [c7, :got_lo12:kernel_root_cap]
	ldr	c7, [c7]
	msr	ddc, c7

	/*
	 * Temporarily disable all interrupts as we can't handle them whilst
	 * CSP is clobbered during the EFI call.
	 */
	mrs	x16, daif
	msr	daifset, #(DAIF_ALL)

	/*
	 * Need to be in A64 so LR has the LSB clear, since the callee's
	 * RET X30 won't honour or clear the LSB.
	 */
	bx	#4
	.arch_extension	noc64
	.arch_extension	a64c
	blr	c6
	bx	#4
	.arch_extension	c64

	/* EFI calls run in the same EL so trash SP metadata */
	ldr	c8, [sp, #(16 * PTR_WIDTH)]
	mov	csp, c8

	/* Restore interrupt mask */
	msr	daif, x16

	/* Done with the almighty DDC */
	msr	ddc, czr

	/*
	 * Restore capability registers that should be callee-saved, plus the
	 * saved efirt_callinfo pointer (but into a different register so as to
	 * not clobber x0 since that has the return value from the call).
	 */
	ldp	c30,  c8, [csp, #(14 * PTR_WIDTH)]
	ldp	c28, c29, [csp, #(12 * PTR_WIDTH)]
	ldp	c26, c27, [csp, #(10 * PTR_WIDTH)]
	ldp	c24, c25, [csp, #(8 * PTR_WIDTH)]
	ldp	c22, c23, [csp, #(6 * PTR_WIDTH)]
	ldp	c20, c21, [csp, #(4 * PTR_WIDTH)]
	ldp	c18, c19, [csp, #(2 * PTR_WIDTH)]
	ldp	c16, c17, [csp]

	/* Save the return code for the caller */
	str	x0, [c8, #EC_EFI_STATUS]

	add	csp, csp, #(17 * PTR_WIDTH)
	ret

	/* Panic if passed more than 5 arguments */
1:	add	csp, csp, #(17 * PTR_WIDTH)
	adrp	c0, efi_rt_panic_str_ptr
	ldr	c0, [c0, :lo12:efi_rt_panic_str_ptr]
	b	panic
END(efi_rt_arch_call_nofault)

	.rodata
	.type	efi_rt_panic_str, @object
efi_rt_panic_str:
	.asciz	"efi_rt_arch_call: too many args"
	.size	efi_rt_panic_str, . - efi_rt_panic_str

	.section .data.rel.ro, "aw", @progbits
	.balign	16
	.type	efi_rt_panic_str_ptr, @object
efi_rt_panic_str_ptr:
	.chericap	efi_rt_panic_str
	.size	efi_rt_panic_str_ptr, . - efi_rt_panic_str_ptr
#endif
