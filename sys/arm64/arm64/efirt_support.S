/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Jessica Clarke
 * Copyright (c) 2024 Arm Ltd
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

#include <sys/elf_common.h>
#include <sys/errno.h>

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
	adr	c9, 0f
	mov	x10, #20
	sub	x8, x10, x8, lsl #2
	add	c9, c9, x8, uxtx
	br	x9

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
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x6
#else
	blr	c6
#endif
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
	RETURN

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
#else
/*
 * int efi_rt_arch_call(struct efirt_callinfo *);
 */
ENTRY(efi_rt_arch_call)
	sub	sp, sp, #(14 * 8)
	stp	x19, x20, [sp, #(2  * 8)]
	stp	x21, x22, [sp, #(4  * 8)]
	stp	x23, x24, [sp, #(6  * 8)]
	stp	x25, x26, [sp, #(8  * 8)]
	stp	x27, x28, [sp, #(10 * 8)]
	stp	x29, x30, [sp, #(12 * 8)]
	add	x29, sp, #(12 * 8)

	/* Save the stack pointer so we can find it later */
	ldr	x23, [x18, #PC_CURTHREAD]
	mov	x24, sp
	str	x24, [x23, #TD_MD_EFIRT_TMP]

	mov	x22, x0

	/* Load the function to branch to */
	ldr	x9, [x22, #(EC_FPTR)]

	/* Load the arguments */
	ldr	x4, [x22, #(EC_ARG1 + (4 * 8))]
	ldr	x3, [x22, #(EC_ARG1 + (3 * 8))]
	ldr	x2, [x22, #(EC_ARG1 + (2 * 8))]
	ldr	x1, [x22, #(EC_ARG1 + (1 * 8))]
	ldr	x0, [x22, #(EC_ARG1 + (0 * 8))]

	/* Set the fault handler */
	adr	x10, efi_rt_fault
	SET_FAULT_HANDLER(x10, x11)

	blr	x9

	/* Clear the fault handler */
	SET_FAULT_HANDLER(xzr, x11)

	/* Store the result */
	str	x0, [x22, #(EC_EFI_STATUS)]
	mov	x0, #0

.Lefi_rt_arch_call_exit:
	ldp	x19, x20, [sp, #(2  * 8)]
	ldp	x21, x22, [sp, #(4  * 8)]
	ldp	x23, x24, [sp, #(6  * 8)]
	ldp	x25, x26, [sp, #(8  * 8)]
	ldp	x27, x28, [sp, #(10 * 8)]
	ldp	x29, x30, [sp, #(12 * 8)]
	add	sp, sp, #(14 * 8)

	ret
END(efi_rt_arch_call)

LENTRY(efi_rt_fault)
	/* Clear pcb_onfault */
	SET_FAULT_HANDLER(xzr, x11)
	/* Load curthread */
	ldr	x1, [x18, #PC_CURTHREAD]
	/* Restore the stack pointer */
	ldr	x2, [x1, #TD_MD_EFIRT_TMP]
	mov	sp, x2
	/* Normal exit returning an error */
	ldr	x0, =EFAULT
	b	.Lefi_rt_arch_call_exit
END(efi_rt_fault)
#endif

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
