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
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181121,
 *   "target_type": "prog",
 *   "changes": [
 *     "pointer_shape"
 *   ]
 * }
 * CHERI CHANGES END
 */

#include <machine/asm.h>

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cherireg.h>
#include "SYS.h"
#endif

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ > 4)
	.cfi_sections .debug_frame
#endif

.globl _C_LABEL(_rtld_relocate_nonplt_self)
.globl _C_LABEL(_rtld)

#ifdef __CHERI_PURE_CAPABILITY__

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
	dli		sp, -SFRAME_SIZE
	cincoffset	$c11, $c11, sp
	csc		$c3, zero, SFRAME_AUXARGS($c11)

	SETUP_GP64(s4, rtld_start)

	cmove		$c24, $c11

	/* $pcc still has large bounds here -> load _DYNAMIC from $pcc */
	PCREL_LOAD_CODE_PTR($c4, a0, _DYNAMIC)
	PCREL_LOAD_CODE_PTR($c12, t9, _rtld_relocate_nonplt_self)
	cjalr $c12, $c17; /* (auxv, &_DYNAMIC) */
	nop /* delay slot */

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

#else /* __CHERI_PURE_CAPABILITY__ */

#define	PTR_SIZE	(1<<PTR_SCALESHIFT)

/*
 *      a0      stack pointer
 *      a1      rtld cleanup (filled in by dynamic loader)
 *      a2      rtld object (filled in by dynamic loader)
 *      a3      ps_strings
 */
NESTED(rtld_start, 4*PTR_SIZE, ra)	
	.mask	0x10090000,-PTR_SIZE
	.set	noreorder

	SETUP_GP
	PTR_SUBU sp, 4*PTR_SIZE		/* adjust stack pointer */
	SETUP_GP64(s4, rtld_start)
	SAVE_GP(0)
					/* -> 1*PTR_SIZE(sp) for atexit */
					/* -> 2*PTR_SIZE(sp) for obj_main */
	move	s0, a0			/* save stack pointer from a0 */
	move	s3, a3			/* save ps_strings pointer */

	PTR_LA	a1, 1f
	bal	1f
	PTR_LA	t0, _C_LABEL(_rtld_relocate_nonplt_self)
1:	PTR_SUBU a1, ra, a1		/* relocbase */
	PTR_LA	a0, _DYNAMIC
	PTR_ADDU t9, a1, t0
	jalr	t9			/* _rtld_relocate_nonplt_self(dynp, relocabase) */
	PTR_ADDU a0, a1, a0		/* &_DYNAMIC */

	move	a0, s0			/* sp */
	PTR_ADDU a1, sp, 2*PTR_SIZE	/* &our atexit function */
	PTR_ADDU a2, sp, 3*PTR_SIZE	/* obj_main entry */
	PTR_SUBU sp, 4*SZREG		/* ABI requires to reserve memory for 4 regs */
	PTR_LA	t9, _C_LABEL(_rtld)
	jalr	t9			/* v0 = _rtld(sp, cleanup, objp) */
	nop
	PTR_ADDU sp, 4*SZREG

	PTR_L	a1, 2*PTR_SIZE(sp)	/* our atexit function */
	PTR_L	a2, 3*PTR_SIZE(sp)	/* obj_main entry */
	PTR_ADDU sp, 4*PTR_SIZE		/* readjust stack */
	move	a0, s0			/* stack pointer */
	move	t9, v0
	PTR_SUBU sp, 4*SZREG		/* ABI requires to reserve memory for 4 regs */
	move	ra,t9			/* RA == PC signals backtrace routine to stop */
	j	t9			/* _start(sp, cleanup, obj); */
	move	a3, s3			/* restore ps_strings */
END(rtld_start)

#define	XCALLFRAME_SIZ		(12*SZREG)
#define	XCALLFRAME_RA		(10*SZREG)
#define	XCALLFRAME_GP		(9*SZREG)
#define	XCALLFRAME_S0		(8*SZREG)
#define	XCALLFRAME_A3		(7*SZREG)
#define	XCALLFRAME_A2		(6*SZREG)
#define	XCALLFRAME_A1		(5*SZREG)
#define	XCALLFRAME_A0		(4*SZREG)
#if defined(__mips_n32) || defined(__mips_n64)
#define	XCALLFRAME_A7		(3*SZREG)
#define	XCALLFRAME_A6		(2*SZREG)
#define	XCALLFRAME_A5		(1*SZREG)
#define	XCALLFRAME_A4		(0*SZREG)
#endif

/*
 * Trampoline for "old" PLT stubs which use .got entries.
 */
	.globl	_rtld_bind_start
	.ent	_rtld_bind_start
_rtld_bind_start:
	.frame	sp, XCALLFRAME_SIZ, $15
	.cfi_startproc simple
	.cfi_def_cfa sp, 0
	.cfi_register ra, $15
	move	v1, gp			/* save old GP */
#if defined(__mips_o32) || defined(__mips_o64)
	PTR_ADDU t9, 8			/* modify T9 to point at .cpload */
#endif
	SETUP_GP
	PTR_SUBU sp, XCALLFRAME_SIZ	/* save arguments and sp value in stack */
	.cfi_def_cfa_offset XCALLFRAME_SIZ
	SETUP_GP64(XCALLFRAME_GP, _rtld_bind_start)
	SAVE_GP(XCALLFRAME_GP)
#if defined(__mips_n32) || defined(__mips_n64)
	REG_S	a4,  XCALLFRAME_A4(sp)
	.cfi_rel_offset a4, XCALLFRAME_A4
	REG_S	a5,  XCALLFRAME_A5(sp)
	.cfi_rel_offset a5, XCALLFRAME_A5
	REG_S	a6,  XCALLFRAME_A6(sp)
	.cfi_rel_offset a6, XCALLFRAME_A6
	REG_S	a7,  XCALLFRAME_A7(sp)
	.cfi_rel_offset a7, XCALLFRAME_A7
#endif
	REG_S	a0,  XCALLFRAME_A0(sp)
	.cfi_rel_offset a0, XCALLFRAME_A0
	REG_S	a1,  XCALLFRAME_A1(sp)
	.cfi_rel_offset a1, XCALLFRAME_A1
	REG_S	a2,  XCALLFRAME_A2(sp)
	.cfi_rel_offset a2, XCALLFRAME_A2
	REG_S	a3,  XCALLFRAME_A3(sp)
	.cfi_rel_offset a3, XCALLFRAME_A3
	REG_S	$15,  XCALLFRAME_RA(sp)	/* ra is in t7/t3 */
	.cfi_rel_offset ra, XCALLFRAME_RA
	REG_S	s0,  XCALLFRAME_S0(sp)
	.cfi_rel_offset s0, XCALLFRAME_S0
	move	s0, sp

	move	a0, v1			/* old GP */
	PTR_SUBU	a0, a0, 0x7ff0		/* The offset of $gp from the	*/
       					/* beginning of the .got section: */
					/* $gp = .got + 0x7ff0, so	*/
					/* .got = $gp - 0x7ff0		*/
					/* Simple math as you can see.	*/
#if defined(__mips_n64)
	ld	a0, 8(a0)		/* object = pltgot[1] */
	and	a0, a0, 0x7fffffffffffffff
#else
	lw	a0, 4(a0)		/* object = pltgot[1] & 0x7fffffff */
	and	a0, a0, 0x7fffffff
#endif
	move	a1, t8			/* symbol index */

	PTR_LA	t9, _C_LABEL(_mips_rtld_bind)
	jalr	t9
	nop

	move	sp, s0
	REG_L	ra, XCALLFRAME_RA(sp)
	.cfi_restore ra
	REG_L	s0, XCALLFRAME_S0(sp)
	.cfi_restore s0
	REG_L	a0, XCALLFRAME_A0(sp)
	.cfi_restore a0
	REG_L	a1, XCALLFRAME_A1(sp)
	.cfi_restore a1
	REG_L	a2, XCALLFRAME_A2(sp)
	.cfi_restore a2
	REG_L	a3, XCALLFRAME_A3(sp)
	.cfi_restore a3
#if defined(__mips_n32) || defined(__mips_n64)
	REG_L	a4, XCALLFRAME_A4(sp)
	.cfi_restore a4
	REG_L	a5, XCALLFRAME_A5(sp)
	.cfi_restore a5
	REG_L	a6, XCALLFRAME_A6(sp)
	.cfi_restore a6
	REG_L	a7, XCALLFRAME_A7(sp)
	.cfi_restore a7
#endif
	RESTORE_GP64
	PTR_ADDU sp, XCALLFRAME_SIZ
	move	t9, v0
	jr	t9
	nop
	.cfi_endproc
END(_rtld_bind_start)


/*
 * Trampoline for PLT stubs using .pltrel entries and .got.plt.
 */
	.globl	_rtld_pltbind_start
	.ent	_rtld_pltbind_start
_rtld_pltbind_start:
	.frame	sp, XCALLFRAME_SIZ, $15
	.cfi_startproc simple
	.cfi_def_cfa sp, 0
	.cfi_register ra, $15
#if defined(__mips_o32)
	move	v1, gp			/* save pointer to .got.plt */
#else
	move	v1, t2			/* save pointer to .got.plt */
#endif
#if defined(__mips_o32) || defined(__mips_o64)
	PTR_ADDU t9, 8			/* modify T9 to point at .cpload */
#endif
	SETUP_GP
	PTR_SUBU sp, XCALLFRAME_SIZ	/* save arguments and sp value in stack */
	.cfi_def_cfa_offset XCALLFRAME_SIZ
	SETUP_GP64(XCALLFRAME_GP, _rtld_pltbind_start)
	SAVE_GP(XCALLFRAME_GP)
#if defined(__mips_n32) || defined(__mips_n64)
	REG_S	a4,  XCALLFRAME_A4(sp)
	.cfi_rel_offset a4, XCALLFRAME_A4
	REG_S	a5,  XCALLFRAME_A5(sp)
	.cfi_rel_offset a5, XCALLFRAME_A5
	REG_S	a6,  XCALLFRAME_A6(sp)
	.cfi_rel_offset a6, XCALLFRAME_A6
	REG_S	a7,  XCALLFRAME_A7(sp)
	.cfi_rel_offset a7, XCALLFRAME_A7
#endif
	REG_S	a0,  XCALLFRAME_A0(sp)
	.cfi_rel_offset a0, XCALLFRAME_A0
	REG_S	a1,  XCALLFRAME_A1(sp)
	.cfi_rel_offset a1, XCALLFRAME_A1
	REG_S	a2,  XCALLFRAME_A2(sp)
	.cfi_rel_offset a2, XCALLFRAME_A2
	REG_S	a3,  XCALLFRAME_A3(sp)
	.cfi_rel_offset a3, XCALLFRAME_A3
	REG_S	$15,  XCALLFRAME_RA(sp)	/* ra is in t7/t3 */
	.cfi_rel_offset ra, XCALLFRAME_RA
	REG_S	s0,  XCALLFRAME_S0(sp)
	.cfi_rel_offset s0, XCALLFRAME_S0
	move	s0, sp

	move	a0, v1			/* .got.plt */
#if defined(__mips_n64)
	ld	a0, 8(a0)		/* object = .got.plt[1] */
	sll	a1, t8, 4		/* PLT entry index to .rel.plt offset */
#else
	lw	a0, 4(a0)		/* object = .got.plt[1] */
	sll	a1, t8, 3		/* PLT entry index to .rel.plt offset */
#endif

	PTR_LA	t9, _C_LABEL(_rtld_bind)
	jalr	t9
	nop

	move	sp, s0
	REG_L	ra, XCALLFRAME_RA(sp)
	.cfi_restore ra
	REG_L	s0, XCALLFRAME_S0(sp)
	.cfi_restore s0
	REG_L	a0, XCALLFRAME_A0(sp)
	.cfi_restore a0
	REG_L	a1, XCALLFRAME_A1(sp)
	.cfi_restore a1
	REG_L	a2, XCALLFRAME_A2(sp)
	.cfi_restore a2
	REG_L	a3, XCALLFRAME_A3(sp)
	.cfi_restore a3
#if defined(__mips_n32) || defined(__mips_n64)
	REG_L	a4, XCALLFRAME_A4(sp)
	.cfi_restore a4
	REG_L	a5, XCALLFRAME_A5(sp)
	.cfi_restore a5
	REG_L	a6, XCALLFRAME_A6(sp)
	.cfi_restore a6
	REG_L	a7, XCALLFRAME_A7(sp)
	.cfi_restore a7
#endif
	RESTORE_GP64
	PTR_ADDU sp, XCALLFRAME_SIZ
	move	t9, v0
	jr	t9
	nop
	.cfi_endproc
END(_rtld_pltbind_start)

#endif /* __CHERI_PURE_CAPABILITY__ */
