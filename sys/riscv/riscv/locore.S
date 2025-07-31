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

#ifdef __riscv_xcheri
#ifdef __CHERI_PURE_CAPABILITY__
#define	CSR_STVEC	stcc
#else
#define	CSR_STVEC	stvec
#endif
#else /* __riscv_zcheripurecap */
#define	CSR_STVEC	PTR_CSR(stvec)
#endif

/*
 * Set the CPU exception vector register.
 * Ensure that the installed exception handler is in cap-mode.
 * Trashes t0, t1.
 */
.macro set_exception_handler
	_LLC	PTR(t0), cpu_exception_handler
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
#ifdef __riscv_xcheri
	cspecialr	CAP(t1), pcc
	csetaddr	CAP(t1), CAP(t1), t0
	li	t0, 1
	csetflags	CAP(t1), CAP(t1), t0
	cspecialw	stcc, ct1
#else
	modesw.cap
.option push
.option capmode
	auipc	CAP(t1), 0
	scaddr	CAP(t1), CAP(t1), t0
	csrw	stvecc, CAP(t1)
	modesw.int
.option pop
#endif
#else
	_CSRW	CSR_STVEC, PTR(t0)
#endif
.endmacro


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
	_CMV	PTR(gp), PTR(null)
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
#ifdef __riscv_zcheripurecap
	modesw.cap
#else
	lla	t0, 1f
	cspecialr	PTR(t1), pcc
	csetaddr	PTR(t1), PTR(t1), t0
	li	t0, 1
	csetflags	PTR(t1), PTR(t1), t0
	jr.cap	PTR(t1)
#endif
1:
.option pop
#endif

	/* Pick a hart to run the boot process. */
	li	t1, 1
	_LLC	PTR(t0), hart_lottery
	AMOADD_W t0, t1, 0(PTR(t0))

	/*
	 * We must jump to mpentry in the non-BSP case because the offset is
	 * too large to fit in a 12-bit branch immediate.
	 */
	beqz	t0, 1f
	j	mpentry
1:
	/* Store the boot hart */
	_LLC	PTR(t0), boot_hart
	_SW	a0, 0(PTR(t0))

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
	_CMV	PTR(gp), PTR(null)
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
	_LLC	PTR(ra), get_physmem
	_JALR	PTR(ra)
#else
	jal	get_physmem
#endif

	/* Construct 1GB Identity Map (1:1 PA->VA) */
	_LLC	PTR(s1), bootstrap_pt_l1

	srli	s2, s9, L1_SHIFT	/* kernstart >> L1_SHIFT */
	andi	a5, s2, Ln_ADDR_MASK	/* & Ln_ADDR_MASK */
	li	t4, (PTE_KERN)
	slli	s2, s2, PTE_PPN2_S	/* (s2 << PTE_PPN2_S) */
	or	t6, t4, s2

	/* Store L1 PTE entry to position */
	li	a6, PTE_SIZE
	mulw	a5, a5, a6		/* calculate L1 slot */
	_CADD	PTR(t0), PTR(s1), a5
	_SD	t6, (PTR(t0))		/* Store new PTE */

	/* Construct the virtual address space at KERNBASE */

	/* Add L1 entry for kernel */
	_LLC	PTR(s1), bootstrap_pt_l1
	_LLC	PTR(s2), bootstrap_pt_l2	/* Link to next level PN */
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
	_CADD	PTR(t0), PTR(s1), a5
	_SD	t6, (PTR(t0))

	/* Level 2 superpages (512 x 2MiB) */
	_LLC	PTR(s1), bootstrap_pt_l2
	srli	t4, s9, L2_SHIFT	/* Div physmem base by 2 MiB */
	li	t2, Ln_ENTRIES		/* Build 512 entries */
	add	t3, t4, t2
	li	t0, (PTE_KERN_CAP | PTE_X)
1:
	slli	t2, t4, PTE_PPN1_S	/* << PTE_PPN1_S */
	or	t5, t0, t2
	sd	t5, (PTR(s1))		/* Store PTE entry to position */
	_CADDI	PTR(s1), PTR(s1), PTE_SIZE

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
	_LLC	PTR(t0), va
	_CADD	PTR(t0), PTR(t0), t1
	_CSRW	CSR_STVEC, PTR(t0)

	/* Set page tables base register */
	_LLC	PTR(s2), bootstrap_pt_l1
	srli	s2, s2, PAGE_SHIFT
	li	t0, SATP_MODE_SV39
	or	s2, s2, t0
	sfence.vma
	csrw	satp, s2

	/* Enter the kernel VA space */
	_LLC	PTR(t0), va
	li	t1, KERNBASE
	sub	t1, t1, s9
	_CADD	PTR(t0), PTR(t0), t1
	_JR	PTR(t0)

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
	_LLC	PTR(t1), _C_LABEL(_end)
	sub	t2, t1, t0
	_SCADDR	PTR(t1), PTR(t1), t0
	_SCBNDSR	PTR(t1), PTR(t1), t2
	_LLC	PTR(t0), 1f
	_SCADDR	PTR(t1), PTR(t1), t0
	_JR	PTR(t1)
1:
#endif

	/* Set the trap vector to the real handler. */
	set_exception_handler

	/* Ensure sscratch is zero */
	CMV_CAP	CAP(t0), CAPN(0)
	CSRW_CAP	CAP_CSR(sscratch), CAP(t0)
#ifdef __riscv_xcheri
	/* Ensure stdc is null and thus not used */
	cspecialw	stdc, CAP(t0)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Initialize stack pointer */
	_LLC	PTR(s3), initstack
	_LLC	PTR(t0), initstack_end
	sub	t0, t0, s3
	_SCBNDSR	PTR(s3), PTR(s3), t0
	li	t1, CHERI_PERMS_KERNEL_DATA
	_ACPERM	PTR(s3), PTR(s3), t1
	_CADD	PTR(sp), PTR(s3), t0

	/* Allocate space for thread0 PCB and riscv_bootparams */
	_CADDI	PTR(sp), PTR(sp), -(PCB_SIZE + RISCV_BOOTPARAMS_SIZE) & ~STACKALIGNBYTES

	/* Clear BSS */
	_LLC	PTR(s0), _C_LABEL(__bss_start)
	_LLC	PTR(s1), _C_LABEL(_end)
1:
	_SD	zero, 0(PTR(s0))
	_CADDI	PTR(s0), PTR(s0), 8
	bltu	s0, s1, 1b

	/* Save omnipotent DDC and clear kernel's DDC. */
	_CSRR	PTR(s0), ddc
	_CMV	PTR(t0), cnull
	_CSRW	ddc, PTR(t0)

	/* Save modulep in cs2. */
	_CMV	PTR(s2), PTR(a0)

	/* Save DTB physical pointer in s1. */
	mv	s1, a1

	/* Initialize cap relocs. */
	li	t0, CHERI_PERMS_KERNEL_DATA
	_ACPERM	PTR(a0), PTR(s0), t0
	_LLC	PTR(ra), _C_LABEL(init_cap_relocs)
	li	t0, CHERI_PERMS_KERNEL_CODE
	_ACPERM	PTR(a1), PTR(ra), t0
	_JALR	PTR(ra)

	/* Initialize capabilities. */
	_CMV	PTR(a0), PTR(s0)
	_LGC	PTR(ra), _C_LABEL(cheri_init_capabilities)
	_JALR	PTR(ra)

	/* Fill riscv_bootparams */
	_SD	s9, RISCV_BOOTPARAMS_KERN_PHYS(PTR(sp))

	S_PTR	PTR(s3), RISCV_BOOTPARAMS_KERN_STACK(PTR(sp))
	_SD	s1, RISCV_BOOTPARAMS_DTBP_PHYS(PTR(sp))
	S_PTR	PTR(s2), RISCV_BOOTPARAMS_MODULEP(PTR(sp))

	/* Discard omnipotent cs0. */
	_CMV	PTR(s0), cnull

	/* Clear other capabilities no longer needed. */
	_CMV	PTR(s1), cnull
	_CMV	PTR(s2), cnull
	_CMV	PTR(s3), cnull

	li	t0, RISCV_BOOTPARAMS_SIZE
	_SCBNDSR	PTR(a0), PTR(sp), t0
	_LGC	PTR(ra), _C_LABEL(initriscv)
	_JALR	PTR(ra)			/* Off we go */
	_LGC	PTR(ra), _C_LABEL(mi_startup)
	_JALR	PTR(ra)
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
	CSRR_CAP	CAP(a0), ddc
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
	_LLC	PTR(t0), virt_map	/* physical address of virt_map */
	_LD	t1, 0(PTR(t0))	/* virtual address of virt_map */
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
#ifdef __CHERI_PURE_CAPABILITY__
.option push
.option nocapmode
#ifdef __riscv_zcheripurecap
	modesw.cap
#else
	lla	t0, 1f
	cspecialr	PTR(t1), pcc
	csetaddr	PTR(t1), PTR(t1), t0
	li	t0, 1
	csetflags	PTR(t1), PTR(t1), t0
	jr.cap	PTR(t1)
#endif
1:
.option pop
#endif
	/*
	 * Calculate the offset to __riscv_boot_ap
	 * for the current core, cpuid is in a0.
	 */
	li	t1, 4
	mulw	t1, t1, a0
	/* Get the pointer */

	_LLC	PTR(t0), __riscv_boot_ap
	_CADD	PTR(t0), PTR(t0), t1

1:
	/* Wait the kernel to be ready */
	_LW	t1, 0(PTR(t0))
	beqz	t1, 1b

	/* Setup stack pointer */
	_LLC	PTR(t0), bootstack
	L_PTR	PTR(sp), 0(PTR(t0))

	/* Get the kernel's load address */
	_LLC	PTR(ra), get_physmem
	_JALR	PTR(ra)

	/* Setup supervisor trap vector */
	_LLC	PTR(t0), mpva
	li	t1, KERNBASE
	sub	t1, t1, s9
	_CADD	PTR(t0), PTR(t0), t1
	_CSRW	CSR_STVEC, PTR(t0)

	/* Set page tables base register */
	_LLC	PTR(t2), kernel_pmap_store
	_LD	s2, PM_SATP(PTR(t2))
	sfence.vma
	csrw	satp, s2

	.align 2
mpva:
	/* Set the global pointer again, this time with the virtual address. */
#ifdef __CHERI_PURE_CAPABILITY__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
	_CMV	PTR(gp), PTR(null)
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Create a reduced PCC. */
	li	t0, KERNBASE
	_LLC	PTR(t1), _C_LABEL(_end)
	sub	t2, t1, t0
	_SCADDR	PTR(t1), PTR(t1), t0
	_SCBNDSR	PTR(t1), PTR(t1), t2
	_LLC	PTR(t0), 1f
	_SCADDR	PTR(t1), PTR(t1), t0
	_JR	PTR(t1)
1:
#endif

	/* Set the trap vector to the real handler. */
	set_exception_handler

	/* Ensure sscratch is zero */
	CMV_CAP	CAP(t0), CAPN(0)
	CSRW_CAP	CAP_CSR(sscratch), CAP(t0)
#ifdef __riscv_xcheri
	/* Ensure stdc is null and thus not used */
	cspecialw	stdc, CAP(t0)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	_LGC	PTR(ra), init_secondary
	_JALR	PTR(ra)
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
