/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
__FBSDID("$FreeBSD$");

/*
 * XXX-AM: Wrap HVC and SMC calls to save caller-save capability registers.
 * This is needed until we have purecap support in TF-A, BHYVE (or other
 * hypervisors) and QEMU.
 */
#ifdef __CHERI_PURE_CAPABILITY__
.macro save_registers
	sub	csp, csp, #(15 * PTR_WIDTH)
	stp	c16, c17, [csp]
	stp	c18, c19, [csp, #(2 * PTR_WIDTH)]
	stp	c20, c21, [csp, #(4 * PTR_WIDTH)]
	stp	c22, c23, [csp, #(6 * PTR_WIDTH)]
	stp	c24, c25, [csp, #(8 * PTR_WIDTH)]
	stp	c26, c27, [csp, #(10 * PTR_WIDTH)]
	stp	c28, c29, [csp, #(12 * PTR_WIDTH)]
	str	c30, [csp, #(14 * PTR_WIDTH)]
.endmacro

.macro restore_registers
	ldp	c16, c17, [csp]
	ldp	c18, c19, [csp, #(2 * PTR_WIDTH)]
	ldp	c20, c21, [csp, #(4 * PTR_WIDTH)]
	ldp	c22, c23, [csp, #(6 * PTR_WIDTH)]
	ldp	c24, c25, [csp, #(8 * PTR_WIDTH)]
	ldp	c26, c27, [csp, #(10 * PTR_WIDTH)]
	ldp	c28, c29, [csp, #(12 * PTR_WIDTH)]
	ldr	c30, [csp, #(14 * PTR_WIDTH)]
	add	csp, csp, #(15 * PTR_WIDTH)
.endmacro
#endif

/*
 * XXX: TF-A in Morello firmware versions up to at least 1.4 do not
 * initialize DDC_EL0 and depend on the caller setting it to almighty
 * capability.
 */
#if __has_feature(capabilities)
.macro	reset_ddc_el0
	sub	PTRN(sp), PTRN(sp), #16 * 2
	mrs	c9, ddc_el0
	mrs	x10, daif
	stp	c9, c10, [PTRN(sp)]
	adrp	PTR(9), smccc_ddc_el0
	ldr	c9, [PTR(9), :lo12:smccc_ddc_el0]

	/* Mask interrupts while DDC_EL0 is set. */
	msr	daifset, #(DAIF_INTR)
	msr	ddc_el0, c9
.endmacro

.macro restore_ddc_el0
	ldp	c9, c10, [PTRN(sp)]
	msr	ddc_el0, c9
	msr	daif, x10
	add	PTRN(sp), PTRN(sp), #16 * 2
.endmacro
#endif

.macro arm_smccc_1_0	insn
ENTRY(arm_smccc_\insn)
#ifdef __CHERI_PURE_CAPABILITY__
	save_registers
#endif
#if __has_feature(capabilities)
	reset_ddc_el0
#endif
	\insn	#0
#if __has_feature(capabilities)
	restore_ddc_el0
#endif
#ifdef __CHERI_PURE_CAPABILITY__
	restore_registers
#endif
	ldr	x4, [PTRN(sp)]
	cbz	x4, 1f
	stp	x0, x1, [PTR(4), #16 * 0]
	stp	x2, x3, [PTR(4), #16 * 1]
1:	ret
END(arm_smccc_\insn)
.endm

/*
 * int arm_smccc_*(register_t, register_t, register_t, register_t,
 *     register_t, register_t, register_t, register_t,
 *     struct arm_smccc_res *res)
 */
arm_smccc_1_0	hvc
arm_smccc_1_0	smc

.macro arm_smccc_1_2	insn
ENTRY(arm_smccc_1_2_\insn)
#ifdef __CHERI_PURE_CAPABILITY__
	save_registers
#endif
	stp	PTR(1), PTR(19), [PTRN(sp), #-(2 * PTR_WIDTH)]!
	mov	PTR(19), PTR(0)
	ldp	x0, x1, [PTR(19), #16 * 0]
	ldp	x2, x3, [PTR(19), #16 * 1]
	ldp	x4, x5, [PTR(19), #16 * 2]
	ldp	x6, x7, [PTR(19), #16 * 3]
	ldp	x8, x9, [PTR(19), #16 * 4]
	ldp	x10, x11, [PTR(19), #16 * 5]
	ldp	x12, x13, [PTR(19), #16 * 6]
	ldp	x14, x15, [PTR(19), #16 * 7]
	ldp	x16, x17, [PTR(19), #16 * 8]
	\insn	#0
	ldr	PTR(19), [PTRN(sp)]
	cbz	x19, 1f
	stp	x0, x1, [PTR(19), #16 * 0]
	stp	x2, x3, [PTR(19), #16 * 1]
	stp	x4, x5, [PTR(19), #16 * 2]
	stp	x6, x7, [PTR(19), #16 * 3]
	stp	x8, x9, [PTR(19), #16 * 4]
	stp	x10, x11, [PTR(19), #16 * 5]
	stp	x12, x13, [PTR(19), #16 * 6]
	stp	x14, x15, [PTR(19), #16 * 7]
	stp	x16, x17, [PTR(19), #16 * 8]
1:	ldp	PTR(zr), PTR(19), [PTRN(sp)], #(2 * PTR_WIDTH)
#ifdef __CHERI_PURE_CAPABILITY__
	restore_registers
#endif
	ret
END(arm_smccc_1_2\insn)
.endm
/* int arm_smccc_1_2_*(const struct arm_smccc_1_2_regs *args,
 *     struct arm_smccc_1_2_regs *res)
 */
arm_smccc_1_2	hvc
arm_smccc_1_2	smc
// CHERI CHANGES START
// {
//   "updated": 20210407,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
