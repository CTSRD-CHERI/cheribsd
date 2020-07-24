/*	$NetBSD: rtld_start.S,v 1.10 2009/12/14 00:41:19 matt Exp $	*/

/*
 * Copyright 1997 Michael L. Hitch <mhitch@montana.edu>
 * Portions copyright 2002 Charles M. Hannum <root@ihack.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <machine/asm.h>
#include <cheri/cherireg.h>
#include "SYS.h"

.globl _C_LABEL(_rtld_relocate_nonplt_self)
.globl _C_LABEL(_rtld)

/* XXXAR: This code currently requires non-PIC DLA expansions */
.option pic0
.set noreorder


#define	SFRAME_SIZE		(3*CHERICAP_SIZE)
#define	SFRAME_AUXARGS		(2*CHERICAP_SIZE)
#define	SFRAME_OBJP		(1*CHERICAP_SIZE)
#define	SFRAME_CLEANUP		(0*CHERICAP_SIZE)

/*
 *      c3      auxargs pointer
 *      c4      relocabase capability
 */
LEAF(rtld_start)
	// .cfi_startproc
	/*
	 * XXX: Clear DDC. Eventually the kernel should stop setting it in the
	 * first place.
	 */
	cgetnull	$c5
	csetdefault	$c5
	/*
	 * XXX: Assume the kernel aligned the stack correctly.
	 */
	dli		sp, -SFRAME_SIZE
	cincoffset	$c11, $c11, sp
	csc		$c3, zero, SFRAME_AUXARGS($c11)

	SETUP_GP64(s4, rtld_start)

	cmove		$c24, $c11

	/* $pcc still has large bounds here -> load _DYNAMIC from $pcc */
	PCREL_LOAD_CODE_PTR($c3, a0, _DYNAMIC)
	/* XXXAR: this assumes relocbase is R/W */
	/* TODO: Could also use cgetaddr+csetaddr to rederive from relocbase */
	csub		a0, $c3, $c4	/* get difference between relocbase and
					 * &_DYNAMIC (needed since they don't
					 * have the same base) */

	PCREL_LOAD_CODE_PTR($c12, t9, _rtld_relocate_nonplt_self)
	cjalr $c12, $c17; /* (&_DYNAMIC, relocbase) */
	cincoffset	$c3, $c4, a0	/* dynp (in delay slot) */

#if __CHERI_CAPABILITY_TABLE__ != 3
	/* For the non-pc-relative case set up $cgp now */
	PCREL_LOAD_CODE_PTR($cgp, t0, __cap_table_start)
	/* Use $c3 as the temporary register to get size of .captable */
	PCREL_LOAD_CODE_PTR($c3, t0, __cap_table_end)
	csub t0, $c3, $cgp
	csetbounds $cgp, $cgp, t0
	/* Clear all permissions except LOAD+LOAD_CAP */
	dli t0, (CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
	candperm $cgp, $cgp, t0
#endif

	clc		$c3, zero, SFRAME_AUXARGS($c11)
	/* XXX-BD: Should allocate cleanup and objp outside stack. */
	dli		t1, CHERICAP_SIZE
	dli		t0, SFRAME_CLEANUP
	cincoffset	$c4, $c11, t0			/* &cleanup */
	csetbounds	$c4, $c4, t1
	dli		t0, SFRAME_OBJP
	cincoffset	$c5, $c11, t0			/* &objp */
	csetbounds	$c5, $c5, t1
	/*
	 * Note: we could use PIC_CALL() here since $cgp is set up correctly
	 * by now, but since we have a large $pcc anyway, using a pc-relative
	 * call here avoids allocating a slot in the captable
	 */
	PCREL_LOAD_CODE_PTR($c12, t9, _rtld)
	cjalr $c12, $c17; /* c3 = _rtld(auxargs, cleanup, objp) */
	nop

	cmove		$c12, $c3
	clc		$c3, zero, SFRAME_AUXARGS($c11)
	clc		$c4, zero, SFRAME_CLEANUP($c11)
	clc		$c5, zero, SFRAME_OBJP($c11)

	cmove		$cra, $c12 /* return == PCC signals backtrace routine to stop */
	cjr		$c12
	nop
	// .cfi_endproc
END(rtld_start)

#define	_XCALLFRAME_SIZ		(11*SZREG + XCALLFRAME_CAPSIZ)
/* Ensure the callframe size is capability aligned: */
#define	XCALLFRAME_SIZ		((_XCALLFRAME_SIZ) + (CHERICAP_SIZE - (_XCALLFRAME_SIZ % CHERICAP_SIZE)))
#define	XCALLFRAME_RA		(10*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_GP		(9*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_S0		(8*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A3		(7*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A2		(6*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A1		(5*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A0		(4*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A7		(3*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A6		(2*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A5		(1*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_A4		(0*SZREG + XCALLFRAME_CAPSIZ)
#define	XCALLFRAME_CAPSIZ	(11*CHERICAP_SIZE)
#define	XCALLFRAME_CFP		(10*CHERICAP_SIZE)
/*
 * We need to save $c13 for varidics and on-stack arguments since the any calls
 * calls with variadic args in rtld (e.g. debug printfs) will clobber it
 */
#define	XCALLFRAME_C13		(9*CHERICAP_SIZE)
#define	XCALLFRAME_C3		(8*CHERICAP_SIZE)
#define	XCALLFRAME_C4		(7*CHERICAP_SIZE)
#define	XCALLFRAME_C5		(6*CHERICAP_SIZE)
#define	XCALLFRAME_C6		(5*CHERICAP_SIZE)
#define	XCALLFRAME_C7		(4*CHERICAP_SIZE)
#define	XCALLFRAME_C8		(3*CHERICAP_SIZE)
#define	XCALLFRAME_C9		(2*CHERICAP_SIZE)
#define	XCALLFRAME_C10		(1*CHERICAP_SIZE)
#define	XCALLFRAME_CRA		(0*CHERICAP_SIZE)

#if (XCALLFRAME_SIZ % CHERICAP_SIZE) != 0
#error BAD_XCALLFRAME_SIZE
#endif

LEAF(_rtld_bind_start)
	// move	v1, gp			/* save old GP */
	// FIXME: the .cfi annotations seem to be wrong since the backtrace is better without them...
	// .cfi_startproc
	// .cfi_def_cfa_register	$c11, 0
#ifdef DEBUG
	// FIXME: can we assume capability alignment?
	cgetaddr	t0, $c11
	andi	t0, t0, (CHERICAP_SIZE - 1)
	tne	t0, zero
#endif

	cincoffset $c11, $c11, -XCALLFRAME_SIZ	/* save arguments and sp value in stack */
	// .cfi_def_cfa_offset XCALLFRAME_SIZ
	//SETUP_GP64(XCALLFRAME_GP, _rtld_bind_start)
	csd	gp,  zero, XCALLFRAME_GP($c11)
	// .cfi_rel_offset gp, XCALLFRAME_GP
	csd	a0,  zero, XCALLFRAME_A0($c11)
	// .cfi_rel_offset a0, XCALLFRAME_A0
	csd	a1,  zero, XCALLFRAME_A1($c11)
	// .cfi_rel_offset a1, XCALLFRAME_A1
	csd	a2,  zero, XCALLFRAME_A2($c11)
	// .cfi_rel_offset a2, XCALLFRAME_A2
	csd	a3,  zero, XCALLFRAME_A3($c11)
	// .cfi_rel_offset a3, XCALLFRAME_A3
	csd	a4,  zero, XCALLFRAME_A4($c11)
	// .cfi_rel_offset a4, XCALLFRAME_A4
	csd	a5,  zero, XCALLFRAME_A5($c11)
	// .cfi_rel_offset a5, XCALLFRAME_A5
	csd	a6,  zero, XCALLFRAME_A6($c11)
	// .cfi_rel_offset a6, XCALLFRAME_A6
	csd	a7,  zero, XCALLFRAME_A7($c11)
	// .cfi_rel_offset a7, XCALLFRAME_A7
	csd	s0,  zero, XCALLFRAME_S0($c11)
	// .cfi_rel_offset s0, XCALLFRAME_S0
	/* XXX-BD: What about ccall functions?  Do we need v0, c1, c2? */
	csc	$c3, zero, XCALLFRAME_C3($c11)
	// .cfi_rel_offset $c3, XCALLFRAME_C3
	csc	$c4, zero, XCALLFRAME_C4($c11)
	// .cfi_rel_offset $c4, XCALLFRAME_C4
	csc	$c5, zero, XCALLFRAME_C5($c11)
	// .cfi_rel_offset $c5, XCALLFRAME_C5
	csc	$c6, zero, XCALLFRAME_C6($c11)
	// .cfi_rel_offset $c6, XCALLFRAME_C6
	csc	$c7, zero, XCALLFRAME_C7($c11)
	// .cfi_rel_offset $c7, XCALLFRAME_C7
	csc	$c8, zero, XCALLFRAME_C8($c11)
	// .cfi_rel_offset $c8, XCALLFRAME_C8
	csc	$c9, zero, XCALLFRAME_C9($c11)
	// .cfi_rel_offset $c9, XCALLFRAME_C9
	csc	$c10, zero, XCALLFRAME_C10($c11)
	// .cfi_rel_offset $c10, XCALLFRAME_C10
	csc	$c13, zero, XCALLFRAME_C13($c11)
	// .cfi_rel_offset $c13, XCALLFRAME_C13

	csc	$cra, zero, XCALLFRAME_CRA($c11)
	// .cfi_rel_offset $cra, XCALLFRAME_CRA
	// We also need to save the frame pointer since it is callee-save
	csc	$cfp, zero, XCALLFRAME_CFP($c11)
	// .cfi_rel_offset $cfp, XCALLFRAME_CFP
	cmove	$cfp, $c11

	// Current naive implementation contains rtld_cgp at offset 0
	cmove	$c3, $cgp
	// TODO: load this from privileged $chwr instead
	clc	$cgp, zero, 0($c3) #const void* rtld_cgp = plt_stub->rtld_cgp;
	// Now that the rtld $cgp has been restored we can call functions again
	// Note: PIC_CALL() may load from $cgp
	.set PIC_GLOBALS_POINTER_CHANGED, 0	# $cgp has been restored
	PIC_LOAD_CALL_PTR($c12, t9, _mips_rtld_bind) # $c3 = _mips_rtld_bind(plt_stub)
	cjalr $c12, $c17;
	nop;
	cmove	$c12, $c3

	cmove	$c11, $cfp
	// FIMXE: using .cfi_restore with a capreg crashes
	clc	$cfp, zero, XCALLFRAME_CFP($c11)
	//.cfi_restore $cfp
	clc	$cra, zero, XCALLFRAME_CRA($c11)
	//.cfi_restore $cra
	clc	$c13, zero, XCALLFRAME_C13($c11)
	//.cfi_restore $c13
	clc	$c10, zero, XCALLFRAME_C10($c11)
	//.cfi_restore $c10
	clc	$c9, zero, XCALLFRAME_C9($c11)
	// .cfi_restore $c9
	clc	$c8, zero, XCALLFRAME_C8($c11)
	//.cfi_restore $c8
	clc	$c7, zero, XCALLFRAME_C7($c11)
	//.cfi_restore $c7
	clc	$c6, zero, XCALLFRAME_C6($c11)
	//.cfi_restore $c6
	clc	$c5, zero, XCALLFRAME_C5($c11)
	//.cfi_restore $c5
	clc	$c4, zero, XCALLFRAME_C4($c11)
	//.cfi_restore $c4
	clc	$c3, zero, XCALLFRAME_C3($c11)
	// .cfi_restore $c3
	cld	s0, zero, XCALLFRAME_S0($c11)
	// .cfi_restore s0
	cld	a0, zero, XCALLFRAME_A0($c11)
	// .cfi_restore a0
	cld	a1, zero, XCALLFRAME_A1($c11)
	// .cfi_restore a1
	cld	a2, zero, XCALLFRAME_A2($c11)
	// .cfi_restore a2
	cld	a3, zero, XCALLFRAME_A3($c11)
	// .cfi_restore a3
	cld	a4, zero, XCALLFRAME_A4($c11)
	// .cfi_restore a4
	cld	a5, zero, XCALLFRAME_A5($c11)
	// .cfi_restore a5
	cld	a6, zero, XCALLFRAME_A6($c11)
	// .cfi_restore a6
	cld	a7, zero, XCALLFRAME_A7($c11)
	// .cfi_restore a7
	cld	gp, zero, XCALLFRAME_GP($c11)
	// .cfi_restore gp
#ifdef DEBUG
	# Check that the target resulting stack address is aligned
	cgetaddr	t0, $c11
	daddiu	t0, t0, XCALLFRAME_SIZ
	andi	t0, t0, (CHERICAP_SIZE - 1)
	tne	t0, zero
	cgetaddr	t0, $cfp
	andi	t0, t0, (CHERICAP_SIZE - 1)
	tne	t0, zero
#endif
	cjr	$c12	# call the resolved target
	cincoffset $c11, $c11, XCALLFRAME_SIZ	# delay slot
	// .cfi_endproc
END(_rtld_bind_start)
