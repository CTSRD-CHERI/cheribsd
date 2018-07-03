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
#include <machine/cherireg.h>
#include "SYS.h"

.globl _C_LABEL(_rtld_relocate_nonplt_self)
.globl _C_LABEL(_rtld)

/* XXXAR: This code currently requires non-PIC DLA expansions */
.option pic0


/*
 * NB: Use CHERICAP_SIZE to hold relocbase to retain stack alignment
 */

#define	SFRAME_SIZE		(4*CHERICAP_SIZE)
#define	SFRAME_AUXARGS		(3*CHERICAP_SIZE)
#define	SFRAME_OBJP		(2*CHERICAP_SIZE)
#define	SFRAME_CLEANUP		(1*CHERICAP_SIZE)
#define	SFRAME_RELOCBASE	(0*CHERICAP_SIZE)

/*
 *      c3      auxargs pointer
 *      c4      relocabase capability
 */
LEAF(rtld_start)
	/*
	 * XXX: Assume the kernel aligned the stack correctly.
	 */
	dli		sp, -SFRAME_SIZE
	cincoffset	$c11, $c11, sp
	csc		$c3, zero, SFRAME_AUXARGS($c11)

	SETUP_GP64(s4, rtld_start)

	cmove		$c24, $c11

	csc		$c4, zero, SFRAME_RELOCBASE($c11) /* relocbase */
	PIC_LOAD_CODE_PTR($c3, a0, _DYNAMIC)
	/* XXXAR: this assumes relocbase is R/W (could derive from ddc instead of relocbase too)*/
	csub		a0, $c3, $c4	/* get difference between relocbase and
					 * &_DYNAMIC (needed since they don't
					 * have the same base) */
	cincoffset	$c3, $c4, a0	/* dynp */

	PIC_CALL(_rtld_relocate_nonplt_self) /* &_DYNAMIC, relocbase */

	/*
	 * Now that we have processed the self relocations we can do the
	 * __cap_relocs processing (the location needs to be adjusted to the
	 * real address).
	 * TODO: since there should be no external symbols in __cap_relocs we
	 * should be able to do this before _rtld_relocate_nonplt_self and just
	 * add the relocabase value to all targets and sources instead of the
	 * more expensive ELF_REL processing.
	 */
	PIC_LOAD_CODE_PTR($c3, a0, __start___cap_relocs)
	PIC_LOAD_CODE_PTR($c4, a1, __stop___cap_relocs)
	PIC_CALL(_rtld_do___caprelocs_self) /* (&__start___cap_relocs, &__stop___cap_relocs) */


	clc		$c3, zero, SFRAME_AUXARGS($c11)
	/* XXX-BD: Should allocate cleanup and objp outside stack. */
	dli		t1, CHERICAP_SIZE
	dli		t0, SFRAME_CLEANUP
	cincoffset	$c4, $c11, t0			/* &cleanup */
	csetbounds	$c4, $c4, t1
	dli		t0, SFRAME_OBJP
	cincoffset	$c5, $c11, t0			/* &objp */
	csetbounds	$c5, $c5, t1
	PIC_CALL(_rtld)		/* v0 = _rtld(auxargs, cleanup, objp) */

	cmove		$c12, $c3
	clc		$c3, zero, SFRAME_AUXARGS($c11)
	clc		$c4, zero, SFRAME_CLEANUP($c11)
	clc		$c5, zero, SFRAME_OBJP($c11)

	cmove		$c17, $c12 /* return == PCC signals backtrace routine to stop */
	cjr		$c12
	nop
END(rtld_start)

#define	XCALLFRAME_CAPSIZ	(9*CHERICAP_SIZE)
#define	XCALLFRAME_SIZ		(12*SZREG + XCALLFRAME_CAPSIZ)
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
#define	XCALLFRAME_C3		(8*CHERICAP_SIZE)
#define	XCALLFRAME_C4		(7*CHERICAP_SIZE)
#define	XCALLFRAME_C5		(6*CHERICAP_SIZE)
#define	XCALLFRAME_C6		(5*CHERICAP_SIZE)
#define	XCALLFRAME_C7		(4*CHERICAP_SIZE)
#define	XCALLFRAME_C8		(3*CHERICAP_SIZE)
#define	XCALLFRAME_C9		(2*CHERICAP_SIZE)
#define	XCALLFRAME_C10		(1*CHERICAP_SIZE)
#define	XCALLFRAME_C17		(0*CHERICAP_SIZE)

	.globl	_rtld_bind_start
	.ent	_rtld_bind_start
_rtld_bind_start:
	.frame	sp, XCALLFRAME_SIZ, $15
	move	v1, gp			/* save old GP */
	dli	sp, -XCALLFRAME_SIZ
	cincoffset $c11, $c11, sp	/* save arguments and sp value in stack */
	//SETUP_GP64(XCALLFRAME_GP, _rtld_bind_start)
	csd	gp,  zero, XCALLFRAME_GP($c11)
	csd	a0,  zero, XCALLFRAME_A0($c11)
	csd	a1,  zero, XCALLFRAME_A1($c11)
	csd	a2,  zero, XCALLFRAME_A2($c11)
	csd	a3,  zero, XCALLFRAME_A3($c11)
	csd	a4,  zero, XCALLFRAME_A4($c11)
	csd	a5,  zero, XCALLFRAME_A5($c11)
	csd	a6,  zero, XCALLFRAME_A6($c11)
	csd	a7,  zero, XCALLFRAME_A7($c11)
	csd	$15, zero, XCALLFRAME_RA($c11)	/* ra is in t7/t3 */
	csd	s0,  zero, XCALLFRAME_S0($c11)
	/* XXX-BD: What about ccall functions?  Do we need v0, c1, c2? */
	csc	$c3, zero, XCALLFRAME_C3($c11)
	csc	$c4, zero, XCALLFRAME_C4($c11)
	csc	$c5, zero, XCALLFRAME_C5($c11)
	csc	$c6, zero, XCALLFRAME_C6($c11)
	csc	$c7, zero, XCALLFRAME_C7($c11)
	csc	$c8, zero, XCALLFRAME_C8($c11)
	csc	$c9, zero, XCALLFRAME_C9($c11)
	csc	$c10, zero, XCALLFRAME_C10($c11)
	csc	$c17, zero, XCALLFRAME_C17($c11)
	cmove	$c24, $c11

	move	a0, v1			/* old GP */
	PTR_SUBU	a0, a0, 0x7ff0	/* The offset of $gp from the	*/
       					/* beginning of the .got section: */
					/* $gp = .got + 0x7ff0, so	*/
					/* .got = $gp - 0x7ff0		*/
					/* Simple math as you can see.	*/
	ld	a0, 8(a0)	/* object = pltgot[1] */
	dli	t9, 0x7fffffffffffffff;
	and	a0, a0, t9
	cgetdefault	$c3
	csetoffset	$c3, $c3, a0
	move	a0, t8			/* symbol index */

	PIC_CALL(_mips_rtld_bind)
	cgetpccsetoffset $c12, v0

	cmove	$c11, $c24
	clc	$c17, zero, XCALLFRAME_C17($c11)
	clc	$c10, zero, XCALLFRAME_C10($c11)
	clc	$c9, zero, XCALLFRAME_C9($c11)
	clc	$c8, zero, XCALLFRAME_C8($c11)
	clc	$c7, zero, XCALLFRAME_C7($c11)
	clc	$c6, zero, XCALLFRAME_C6($c11)
	clc	$c5, zero, XCALLFRAME_C5($c11)
	clc	$c4, zero, XCALLFRAME_C4($c11)
	clc	$c3, zero, XCALLFRAME_C3($c11)
	cld	ra, zero, XCALLFRAME_RA($c11)
	cld	s0, zero, XCALLFRAME_S0($c11)
	cld	a0, zero, XCALLFRAME_A0($c11)
	cld	a1, zero, XCALLFRAME_A1($c11)
	cld	a2, zero, XCALLFRAME_A2($c11)
	cld	a3, zero, XCALLFRAME_A3($c11)
	cld	a4, zero, XCALLFRAME_A4($c11)
	cld	a5, zero, XCALLFRAME_A5($c11)
	cld	a6, zero, XCALLFRAME_A6($c11)
	cld	a7, zero, XCALLFRAME_A7($c11)
	cld	gp, zero, XCALLFRAME_GP($c11)
	//RESTORE_GP64
	dli	sp, XCALLFRAME_SIZ
	cjr	$c12
	cincoffset $c11, $c11, sp
END(_rtld_bind_start)
