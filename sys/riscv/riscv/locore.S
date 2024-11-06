/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 * Copyright (c) 2019-2021 Mitchell Horne <mhorne@FreeBSD.org>
 * Copyright (c) 2022-2024 The FreeBSD Foundation
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
 *
 * Portions of this software were developed by Mitchell Horne
 * <mhorne@FreeBSD.org> under sponsorship from the FreeBSD Foundation.
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

#include "assym.inc"

#include <machine/asm.h>
#ifdef __CHERI_PURE_CAPABILITY__
#include <machine/cherireg.h>
#endif
#include <machine/param.h>
#include <machine/riscvreg.h>
#include <machine/pte.h>

	.globl	kernbase
	.set	kernbase, KERNBASE

	.text
/*
 * Alternate entry point. Used when booting via SBI firmware. It must be placed
 * at the beginning of the .text section. Arguments are as follows:
 *  - a0 = hart ID
 *  - a1 = dtbp
 *
 * Multiple CPUs might enter from this point, so we perform a hart lottery and
 * send the losers to mpentry.
 */
	.globl _alt_start
_alt_start:
	/* Set the global pointer */
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	cgp, cnull
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
.option push
.option nocapmode

	/*
	 * The boot loader may enter in non-capmode even though
	 * our ELF header requests capmode.  The instructions below
	 * should work in both modes.
	 */
	lla	t0, 1f
	cspecialr ct1, pcc
	csetaddr ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
#ifdef __riscv_xcheri_mode_dependent_jumps
	jr.cap	ct1
#else
	cjr	ct1
#endif
1:
.option pop
#endif

	/* Pick a hart to run the boot process. */
	li	t1, 1
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, hart_lottery
	camoadd.w t0, t1, 0(ct0)
#else
	lla	t0, hart_lottery
	amoadd.w t0, t1, 0(t0)
#endif

	/*
	 * We must jump to mpentry in the non-BSP case because the offset is
	 * too large to fit in a 12-bit branch immediate.
	 */
	beqz	t0, 1f
	j	mpentry
1:
	/* Store the boot hart */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, boot_hart
	csw	a0, 0(ct0)
#else
	lla	t0, boot_hart
	sw	a0, 0(t0)
#endif

	/* Load zero as modulep */
	mv	a0, zero
	j	pagetables

/*
 * Main entry point. This routine is marked as the ELF entry, and is where
 * loader(8) will enter the kernel. Arguments are as follows:
 *  - a0 = modulep
 *  - a1 = ???
 *
 * It is expected that only a single CPU will enter here.
 */
	.globl _start
_start:
	/* Set the global pointer */
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	cgp, cnull
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

	/*
	 * Zero a1 to indicate that we have no DTB pointer. It is already
	 * included in the loader(8) metadata.
	 */
	mv	a1, zero

	/*
	 * Set up page tables: Our goal is to enable virtual memory, doing the
	 * minimum amount of work in assembly; just what is required to
	 * bootstrap. We will construct the real page tables in C code, in
	 * pmap_bootstrap().
	 *
	 * Here we map a 1GB region starting at KERNBASE using 2MB superpages,
	 * starting from the first 2MB physical page into which the kernel was
	 * loaded.
	 *
	 * We also use an L1 entry to create a 1GB identity map (1:1 PA->VA).
	 * This is useful for two reasons:
	 *  - handling the DTB pointer passed from SBI firmware (physical addr)
	 *  - simpler construction of pagetables in pmap_bootstrap()
	 *
	 * Implementations are required to provide Sv39 mode, so we use that
	 * here and will conditionally enable Sv48 (or higher) later.
	 *
	 * We arrive here with:
	 *  a0 - modulep or zero
	 *  a1 - zero or dtbp
	 */
pagetables:
	/* Get the kernel's load address (kernstart) in s9 */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	cra, get_physmem
	cjalr	cra
#else
	jal	get_physmem
#endif

	/* Construct 1GB Identity Map (1:1 PA->VA) */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	cs1, bootstrap_pt_l1
#else
	lla	s1, bootstrap_pt_l1
#endif

	srli	s2, s9, L1_SHIFT	/* kernstart >> L1_SHIFT */
	andi	a5, s2, Ln_ADDR_MASK	/* & Ln_ADDR_MASK */
	li	t4, (PTE_KERN)
	slli	s2, s2, PTE_PPN2_S	/* (s2 << PTE_PPN2_S) */
	or	t6, t4, s2

	/* Store L1 PTE entry to position */
	li	a6, PTE_SIZE
	mulw	a5, a5, a6		/* calculate L1 slot */
#ifdef __CHERI_PURE_CAPABILITY__
	cincoffset ct0, cs1, a5
	csd	t6, (ct0)		/* Store new PTE */
#else
	add	t0, s1, a5
	sd	t6, (t0)		/* Store new PTE */
#endif

	/* Construct the virtual address space at KERNBASE */

	/* Add L1 entry for kernel */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	cs1, bootstrap_pt_l1
	cllc	cs2, bootstrap_pt_l2	/* Link to next level PN */
#else
	lla	s1, bootstrap_pt_l1
	lla	s2, bootstrap_pt_l2	/* Link to next level PN */
#endif
	srli	s2, s2, PAGE_SHIFT

	li	a5, KERNBASE
	srli	a5, a5, L1_SHIFT	/* >> L1_SHIFT */
	andi	a5, a5, Ln_ADDR_MASK	/* & Ln_ADDR_MASK */
	li	t4, PTE_V
	slli	t5, s2, PTE_PPN0_S	/* (s2 << PTE_PPN0_S) */
	or	t6, t4, t5

	/* Store L1 PTE entry to position */
	li	a6, PTE_SIZE
	mulw	a5, a5, a6
#ifdef __CHERI_PURE_CAPABILITY__
	cincoffset ct0, cs1, a5
	csd	t6, (ct0)
#else
	add	t0, s1, a5
	sd	t6, (t0)
#endif

	/* Level 2 superpages (512 x 2MiB) */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	cs1, bootstrap_pt_l2
#else
	lla	s1, bootstrap_pt_l2
#endif
	srli	t4, s9, L2_SHIFT	/* Div physmem base by 2 MiB */
	li	t2, Ln_ENTRIES		/* Build 512 entries */
	add	t3, t4, t2
	li	t0, (PTE_KERN_CAP | PTE_X)
1:
	slli	t2, t4, PTE_PPN1_S	/* << PTE_PPN1_S */
	or	t5, t0, t2
#ifdef __CHERI_PURE_CAPABILITY__
	csd	t5, (cs1)		/* Store PTE entry to position */
	cincoffset cs1, cs1, PTE_SIZE
#else
	sd	t5, (s1)		/* Store PTE entry to position */
	addi	s1, s1, PTE_SIZE
#endif

	addi	t4, t4, 1
	bltu	t4, t3, 1b

	/* Page tables END */

	/*
	 * Set the supervisor trap vector temporarily. Enabling virtual memory
	 * may generate a page fault. We simply wish to continue onwards, so
	 * have the trap deliver us to 'va'.
	 */
	li	t1, KERNBASE
	sub	t1, t1, s9
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, va
	cincoffset ct0, ct0, t1
	cspecialw stcc, ct0
#else
	lla	t0, va
	add	t0, t0, t1
	csrw	stvec, t0
#endif

	/* Set page tables base register */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	cs2, bootstrap_pt_l1
#else
	lla	s2, bootstrap_pt_l1
#endif
	srli	s2, s2, PAGE_SHIFT
	li	t0, SATP_MODE_SV39
	or	s2, s2, t0
	sfence.vma
	csrw	satp, s2

	.align 2
va:
	/* Set the global pointer again, this time with the virtual address. */
#ifdef __CHERI_PURE_CAPABILITY__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Create a reduced PCC. */
	li	t0, KERNBASE
	cllc	ct1, _C_LABEL(_end)
	sub	t2, t1, t0
	csetaddr ct1, ct1, t0
	csetbounds ct1, ct1, t2
	cllc	ct0, 1f
	csetaddr ct1, ct1, t0
	cjr	ct1
1:
#endif

	/* Set the trap vector to the real handler. */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, cpu_exception_handler
	cspecialw stcc, ct0
	cmove	ct1, cnull
	cspecialw stdc, ct1
#else
	la	t0, cpu_exception_handler
#if __has_feature(capabilities)
	cspecialr ct1, pcc
	csetaddr ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
	cspecialw stcc, ct1
	cspecialr ct1, ddc
	cspecialw stdc, ct1
#else
	csrw	stvec, t0
#endif
#endif

	/* Ensure sscratch is zero */
#if __has_feature(capabilities)
	cmove	ct0, cnull
	cspecialw sscratchc, ct0
#else
	li	t0, 0
	csrw	sscratch, t0
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Initialize stack pointer */
	cllc	cs3, initstack
	cllc	ct0, initstack_end
	sub	t0, t0, s3
	csetbounds cs3, cs3, t0
	li	t1, CHERI_PERMS_KERNEL_DATA
	candperm cs3, cs3, t1
	cincoffset csp, cs3, t0

	/* Allocate space for thread0 PCB and riscv_bootparams */
	cincoffset csp, csp, -(PCB_SIZE + RISCV_BOOTPARAMS_SIZE) & ~STACKALIGNBYTES

	/* Clear BSS */
	cllc	cs0, _C_LABEL(__bss_start)
	cllc	cs1, _C_LABEL(_end)
1:
	csd	zero, 0(cs0)
	cincoffset cs0, cs0, 8
	bltu	s0, s1, 1b

	/* Save omnipotent DDC and clear kernel's DDC. */
	cspecialr cs0, ddc
	cmove	ct0, cnull
	cspecialw ddc, ct0

	/* Save modulep in cs2. */
	cmove	cs2, ca0

	/* Save DTB physical pointer in s1. */
	mv	s1, a1

	/* Initialize cap relocs. */
	li	t0, CHERI_PERMS_KERNEL_DATA
	candperm ca0, cs0, t0
	cllc	ca1, _C_LABEL(init_cap_relocs)
	li	t0, CHERI_PERMS_KERNEL_CODE
	candperm ca2, cs0, t0
	cjalr	ca1

	/* Initialize capabilities. */
	cmove	ca0, cs0
	clgc	cra, _C_LABEL(cheri_init_capabilities)
	cjalr	cra

	/* Fill riscv_bootparams */
	csd	s9, RISCV_BOOTPARAMS_KERN_PHYS(csp)

	csc	cs3, RISCV_BOOTPARAMS_KERN_STACK(csp)
	csd	s1, RISCV_BOOTPARAMS_DTBP_PHYS(csp)
	csc	cs2, RISCV_BOOTPARAMS_MODULEP(csp)

	/* Discard omnipotent cs0. */
	cmove	cs0, cnull

	/* Clear other capabilities no longer needed. */
	cmove	cs1, cnull
	cmove	cs2, cnull
	cmove	cs3, cnull

	csetbounds ca0, csp, RISCV_BOOTPARAMS_SIZE
	clgc	cra, _C_LABEL(initriscv)
	cjalr	cra			/* Off we go */
	clgc	cra, _C_LABEL(mi_startup)
	cjalr	cra
#else
	/* Initialize stack pointer */
	la	sp, initstack_end

	/* Clear frame pointer */
	mv	s0, zero

	/* Allocate space for thread0 PCB and riscv_bootparams */
	addi	sp, sp, -(PCB_SIZE + RISCV_BOOTPARAMS_SIZE) & ~STACKALIGNBYTES

	/* Clear BSS */
	la	t0, _C_LABEL(__bss_start)
	la	t1, _C_LABEL(_end)
1:
	sd	zero, 0(t0)
	addi	t0, t0, 8
	bltu	t0, t1, 1b

	/* Save modulep in s2. */
	mv	s2, a0

	/* Save DTB physical pointer in s1. */
	mv	s1, a1

#if __has_feature(capabilities)
	/* Initialize capabilities. */
	cspecialr ca0, ddc
	call	_C_LABEL(cheri_init_capabilities)
#endif

	/* Fill riscv_bootparams */
	sd	s9, RISCV_BOOTPARAMS_KERN_PHYS(sp)

	la	t0, initstack
	sd	t0, RISCV_BOOTPARAMS_KERN_STACK(sp)
	sd	s1, RISCV_BOOTPARAMS_DTBP_PHYS(sp)
	sd	s2, RISCV_BOOTPARAMS_MODULEP(sp)

	mv	a0, sp
	call	_C_LABEL(initriscv)	/* Off we go */
	call	_C_LABEL(mi_startup)
#endif

	/* We should never reach here, but if so just hang. */
2:
	wfi
	j	2b

/*
 * Get the physical address the kernel is loaded to. Returned in s9.
 */
get_physmem:
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, virt_map	/* physical address of virt_map */
	cld	t1, 0(ct0)	/* virtual address of virt_map */
#else
	lla	t0, virt_map	/* physical address of virt_map */
	ld	t1, 0(t0)	/* virtual address of virt_map */
#endif
	sub	t1, t1, t0	/* calculate phys->virt delta */
	li	t2, KERNBASE
	sub	s9, t2, t1	/* s9 = physmem base */
	RETURN

	.align  4
initstack:
	.space  (PAGE_SIZE * KSTACK_PAGES)
initstack_end:

/*
 * Static space for the bootstrap page tables. Unused after pmap_bootstrap().
 */
	.data
	.balign	PAGE_SIZE
	.type	bootstrap_pt_l1, @object
bootstrap_pt_l1:
	.space	PAGE_SIZE
	.size	bootstrap_pt_l1, . - bootstrap_pt_l1
	.type	bootstrap_pt_l2, @object
bootstrap_pt_l2:
	.space	PAGE_SIZE
	.size	bootstrap_pt_l2, . - bootstrap_pt_l2

	.align 3
virt_map:
	.quad   virt_map
hart_lottery:
	.space	4

#ifndef SMP
ENTRY(mpentry)
1:
	wfi
	j	1b
END(mpentry)
#else
/*
 * mpentry(unsigned long)
 *
 * Called by a core when it is being brought online.
 */
ENTRY(mpentry)
	/*
	 * Calculate the offset to __riscv_boot_ap
	 * for the current core, cpuid is in a0.
	 */
	li	t1, 4
	mulw	t1, t1, a0
	/* Get the pointer */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, __riscv_boot_ap
	cincoffset ct0, ct0, t1

1:
	/* Wait the kernel to be ready */
	clw	t1, 0(ct0)
	beqz	t1, 1b

	/* Setup stack pointer */
	cllc	ct0, bootstack
	clc	csp, 0(ct0)

	/* Get the kernel's load address */
	cllc	cra, get_physmem
	cjalr	cra

	/* Setup supervisor trap vector */
	cllc	ct0, mpva
	li	t1, KERNBASE
	sub	t1, t1, s9
	cincoffset ct0, ct0, t1
	cspecialw stcc, ct0
#else
	lla	t0, __riscv_boot_ap
	add	t0, t0, t1

1:
	/* Wait the kernel to be ready */
	lw	t1, 0(t0)
	beqz	t1, 1b

	/* Setup stack pointer */
	lla	t0, bootstack
	ld	sp, 0(t0)

	/* Get the kernel's load address */
	jal	get_physmem

	/*
	 * Set the supervisor trap vector temporarily. Enabling virtual memory
	 * may generate a page fault. We simply wish to continue onwards, so
	 * have the trap deliver us to 'mpva'.
	 */
	lla	t0, mpva
	sub	t0, t0, s9
	li	t1, KERNBASE
	add	t0, t0, t1
	csrw	stvec, t0
#endif

	/* Set page tables base register */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct2, kernel_pmap_store
	cld	s2, PM_SATP(ct2)
#else
	lla	t2, kernel_pmap_store
	ld	s2, PM_SATP(t2)
#endif
	sfence.vma
	csrw	satp, s2

	.align 2
mpva:
	/* Set the global pointer again, this time with the virtual address. */
#ifdef __CHERI_PURE_CAPABILITY__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
	cmove	cgp, cnull
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Create a reduced PCC. */
	li	t0, KERNBASE
	cllc	ct1, _C_LABEL(_end)
	sub	t2, t1, t0
	csetaddr ct1, ct1, t0
	csetbounds ct1, ct1, t2
	cllc	ct0, 1f
	csetaddr ct1, ct1, t0
	cjr	ct1
1:
#endif

	/* Set the trap vector to the real handler. */
#ifdef __CHERI_PURE_CAPABILITY__
	cllc	ct0, cpu_exception_handler
	cspecialw stcc, ct0
	cmove	ct1, cnull
	cspecialw stdc, ct1
#else
	la	t0, cpu_exception_handler
#if __has_feature(capabilities)
	cspecialr ct1, pcc
	csetaddr ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
	cspecialw stcc, ct1
	cspecialr ct1, ddc
	cspecialw stdc, ct1
#else
	csrw	stvec, t0
#endif
#endif

	/* Ensure sscratch is zero */
#if __has_feature(capabilities)
	cmove	ct0, cnull
	cspecialw sscratchc, ct0
#else
	li	t0, 0
	csrw	sscratch, t0
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	clgc	cra, init_secondary
	cjalr	cra
#else
	call	init_secondary
#endif
END(mpentry)
#endif

/*-
 * CHERI CHANGES START
 * {
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support",
 *     "pointer_as_integer"
 *   ]
 * }
 * CHERI CHANGES END
 */
