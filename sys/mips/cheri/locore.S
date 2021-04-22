/*	$OpenBSD: locore.S,v 1.18 1998/09/15 10:58:53 pefo Exp $	*/
/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Digital Equipment Corporation and Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (C) 1989 Digital Equipment Corporation.
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appears in all copies.
 * Digital Equipment Corporation makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * from: Header: /sprite/src/kernel/mach/ds3100.md/RCS/loMem.s,
 *	v 1.1 89/07/11 17:55:04 nelson Exp  SPRITE (DECWRL)
 * from: Header: /sprite/src/kernel/mach/ds3100.md/RCS/machAsm.s,
 *	v 9.2 90/01/29 18:00:39 shirriff Exp  SPRITE (DECWRL)
 * from: Header: /sprite/src/kernel/vm/ds3100.md/vmPmaxAsm.s,
 *	v 1.1 89/07/10 14:27:41 nelson Exp  SPRITE (DECWRL)
 *
 *	from: @(#)locore.s	8.5 (Berkeley) 1/4/94
 *	JNPR: locore.S,v 1.6.2.1 2007/08/29 12:24:49 girish
 * $FreeBSD$
 */

/*
 *	Contains code that is the first executed at boot time on a CHERI CPU
 */

#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/cpuregs.h>
#include <machine/regnum.h>

#include <machine/cheriasm.h>
#include <machine/cherireg.h>
#include <cheri/cherireg.h>

#include "opt_stack.h"

#include "assym.inc"

	/* Don't warn about uses of c27-c30 */
	.set cheri_sysregs_accessible

	.data
#ifdef YAMON
GLOBAL(fenvp)
	.space 4
#endif

	.set noreorder

	.text

GLOBAL(btext)
ASM_ENTRY(_start)
VECTOR(_locore, unknown)
	/* UNSAFE TO USE a0..a3, need to preserve the args from boot loader */
	mtc0	zero, MIPS_COP_0_CAUSE	# Clear soft interrupts

	/*
	 * t0: Bits to preserve if set:
	 *	Soft reset
	 *	Boot exception vectors (firmware-provided)
	 */
	li	t0, (MIPS_SR_BEV | MIPS_SR_SR)
	/*
	 * t1: Bits to set explicitly:
	 *	Enable FPU
	 */
	li	t1, MIPS_SR_COP_1_BIT | MIPS_SR_COP_2_BIT
	or	t1, MIPS_SR_KX | MIPS_SR_SX | MIPS_SR_UX | MIPS_SR_FR
	/*
	 * Read coprocessor 0 status register, clear bits not
	 * preserved (namely, clearing interrupt bits), and set
	 * bits we want to explicitly set.
	 */
	mfc0	t2, MIPS_COP_0_STATUS
	and	t2, t0
	or	t2, t1
	mtc0	t2, MIPS_COP_0_STATUS
	COP0_SYNC

	/* Make sure KSEG0 is cached */
	li	t0, MIPS_CCA_CACHED
	mtc0	t0, MIPS_COP_0_CONFIG
	COP0_SYNC

#if defined(CPU_MALTA)
	/*
	 * Enable userspace cycle-count, cycle-count resolution, and CPU
	 * number registers available via rdhwr.
	 * Also enable beri specific statcounters.
	 */
	MFC0	t0, MIPS_COP_0_HWRENA
	or	t0, MIPS_HWRENA_CC | MIPS_HWRENA_CCRES | MIPS_HWRENA_CPUNUM | \
	    (7 << 4) | MIPS_HWRENA_BERI_STATCOUNTERS_MASK
	MTC0	t0, MIPS_COP_0_HWRENA
#endif

#ifdef YAMON
	/* Save YAMON boot environment pointer */
	ABSRELOC_LA(t0, _C_LABEL(fenvp))
	sw	a2, 0(t0)
#endif

#if defined(CPU_MALTA) && defined(SMP)
	/* XXX-AM: TODO adjust SMP initialization */
	.set push
	.set mips32r2
	jal	malta_cpu_configure
	nop
	jal	platform_processor_id
	nop
	beqz	v0, 1f
	nop
	j	malta_ap_wait
	nop
	.set pop
1:
#endif

	/*
	 * Grab the initial omnipotent capability
	 */
	cgetdefault	$c28

	/* Clear DDC and KDC */
	csetdefault	$cnull
	csetkdc		$cnull

	/*
	 * Create a reduced PCC.
	 *
	 * XXX-BD: Actually changing base/length requires changes in
	 * linkage.
	 */
	cgetpcc		$c27
	REG_LI		t0, CHERI_CAP_KERN_BASE
	csetoffset	$c27, $c27, t0
	REG_LI		t0, CHERI_CAP_KERN_LENGTH
	csetbounds	$c27, $c27, t0
	REG_LI		t0, CHERI_PERMS_KERNEL_CODE
	candperm	$c27, $c27, t0

	/* Preserve a copy in KCC for exception handlers.  */

	csetkcc		$c27

	/* Install the new PCC. */
	ABSRELOC_LA(t0, 1f)
	csetaddr	$c27, $c27, t0
	cjr		$c27
	nop
1:

	/*
	 * Initialize stack and call machine startup.
	 */
	cmove		CHERI_REG_STC, $c28
	ABSRELOC_LA(t0, _C_LABEL(pcpu_space))
	csetoffset	CHERI_REG_STC, CHERI_REG_STC, t0
	REG_LI		t0, PCPU_SIZE
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, t0
	REG_LI		t0, (PAGE_SIZE * 2) - PCPU_SIZE
	csetbounds	CHERI_REG_STC, CHERI_REG_STC, t0	# Boot stack capability
	LONG_SUBU	t0, t0, CALLFRAME_SIZ
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, t0	# Make room for initial callframe

	/* Need to preserve a0-a3 for platform start */
	move s0, a0
	move s1, a1
	move s2, a2
	move s3, a3

	/*
	 * Process capability relocations.
	 * This must be done before any PIC global access that uses the cap-table.
	 */
	cmove		$c3, $c28
	cgetpccsetoffset	$c4, zero
	ABSRELOC_LA(t0, _C_LABEL(init_cap_relocs))
	cgetpcc		$c12
	csetaddr	$c12, $c12, t0
	cjalr	$c12, $c17
	nop

	/* Now we can use cap-table relocations safely */
	cmove	$c3, $c28
	CAPCALL_PCREL_LOAD($c12, t0, _C_LABEL(cheri_init_capabilities))
	cjalr	$c12, $c17
	nop

	/* Clear most remaining capabilities */
	cclearlo	0xf7ff	# keep c11
	cclearhi	0x9fff	# keep c29, c30

	/* Call the platform-specific startup code. */
	move a0, s0
	move a1, s1
	move a2, s2
	move a3, s3
	CAPCALL_PCREL_LOAD($c12, t0, _C_LABEL(platform_start))
	cjalr	$c12, $c17
	nop

	/*
	 * thread0 set thread0 kstack to the bottom of the stack
	 * region, realign thread0 kstack and start using it.
	 */
	CAPTABLE_PCREL_LOAD($c3, t0, _C_LABEL(thread0_st))
	clc	CHERI_REG_STC, zero, TD_KSTACK($c3)
	cgetlen	a0, CHERI_REG_STC
	REG_LI	t0, ~(CHERICAP_SIZE - 1)
	and	a0, a0, t0
	LONG_SUBU	a0, a0, CALLFRAME_SIZ
	csetoffset	CHERI_REG_STC, CHERI_REG_STC, a0
#ifdef STACK
	/* Stop stack backtrace here */
	cmove	$c17, $cnull
	csc	$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
#endif

	CAPCALL_PCREL_LOAD($c12, t0, _C_LABEL(mi_startup))
	cjalr	$c12, $c17
	cmove	$c3, $cnull

	PANIC("Startup failed!")

VECTOR_END(_locore)
// CHERI CHANGES START
// {
//   "updated": 20200708,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
