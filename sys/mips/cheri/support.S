/*-
 * Copyright (c) 2014-2015 Robert N. M. Watson
 * Copyright (c) 2017 SRI International
 * Copyright (c) 2017 Alfredo Mazzinghi
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

/*
 *	Contains capability-enabled assembly language support routines.
 */

#include "opt_ddb.h"
#include <sys/errno.h>
#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/regnum.h>
#include <machine/cpuregs.h>
#include <machine/pcb.h>
#include <machine/cheriasm.h>

#include <cheri/cherireg.h>

#include "assym.inc"

	.set	cheri_sysregs_accessible
	.set	noreorder

	.text

/*
 * pure capability ABI-only versions of the support routines
 */

/*
 * Copy a null terminated string from the user address space into
 * the kernel address space.
 *
 * copyinstr(caddr_t fromaddr, caddr_t toaddr, u_int maxlength, uint *lencopied)
 * accepts:
 * c3 - source address
 * c4 - destination address
 * c5 - pointer length copied
 * a0 - maximum length
 */
NESTED(copyinstr, CALLFRAME_SIZ, ra)
XNESTED(copyinstr_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase	t0, $c3 # make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_LOAD($c12, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_LOAD($c2, copyerr)	# prepare the onfault jump point
	CAPCALL_LOAD($c12, copystr_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from copyinstr */
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
XEND(copyinstr_c)
END(copyinstr)

/*
 * Copy a null terminated string from the kernel address space into
 * the user address space.
 *
 * copyoutstr(caddr_t fromaddr, caddr_t toaddr, u_int maxlength, u_int *lencopied)
 * accepts:
 * c3 - source address
 * c4 - destination address
 * c5 - pointer length copied
 * a0 - maximum length
 */
NESTED(copyoutstr, CALLFRAME_SIZ, ra)
XNESTED(copyoutstr_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase	t0, $c4 # make sure destination is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_LOAD($c12, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_LOAD($c2, copyerr)	# prepare the onfault jump point
	CAPCALL_LOAD($c12, copystr_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from copyoutstr */
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
XEND(copyoutstr_c)
END(copyoutstr)

/*
 * Copy specified amount of data from user space into the kernel
 *	copyin(caddr_t from, caddr_t to, u_int len)
 * accepts:
 * c3 - user source pointer
 * c4 - kernel destination pointer
 * a0 - length of the copy
 */
NESTED(copyin, CALLFRAME_SIZ, ra)
XNESTED(copyin_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c3	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_LOAD($c12, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_LOAD($c2, copyerr)	# prepare the onfault jump point
	CAPCALL_LOAD($c12, bcopynocap_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
XEND(copyin_c)
END(copyin)

/*
 * Copy specified amount of data from user space into the kernel, preserving
 * capability tags
 * copyincap(caddr_t from, caddr_t to, u_int len)
 * accepts:
 * c3 - user source pointer
 * c4 - kernel destination pointer
 * a0 - length of the copy
 */
NESTED(copyincap, CALLFRAME_SIZ, ra)
XNESTED(copyincap_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c3	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_LOAD($c12, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_LOAD($c2, copyerr)	# prepare the onfault jump point
	CAPCALL_LOAD($c12, bcopy_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
XEND(copyincap_c)
END(copyincap)

/*
 * Copy specified amount of data from kernel to the user space
 * copyout(caddr_t from, caddr_t to, u_int len)
 * accepts:
 * c3 - kernel source pointer
 * c4 - user destination pointer
 * a0 - length of the copy
 */
NESTED(copyout, CALLFRAME_SIZ, ra)
XNESTED(copyout_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c4	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_LOAD($c12, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_LOAD($c2, copyerr)	# prepare the onfault jump point
	CAPCALL_LOAD($c12, bcopynocap_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
XEND(copyout_c)
END(copyout)

/*
 * Copy specified amount of data from kernel to the user space, preserving
 * capability tags
 * copyoutcap(caddr_t from, caddr_t to, u_int len)
 * accepts:
 * c3 - kernel source pointer
 * c4 - user destination pointer
 * a0 - length of the copy
 */
NESTED(copyoutcap, CALLFRAME_SIZ, ra)
XNESTED(copyoutcap_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c4	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_LOAD($c12, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_LOAD($c2, copyerr)	# prepare the onfault jump point
	CAPCALL_LOAD($c12, bcopy_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
XEND(copyoutcap_c)
END(copyoutcap)

LEAF(copyerr)
	// ori	zero, zero, 0xbeef
	clc	$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
	cjr	$c17
	li	v0, EFAULT			# return error
END(copyerr)

/*
 * {fu,su},{ibyte,isword,iword}, fetch or store a byte, short or word to
 * user text space.
 * {fu,su},{byte,sword,word}, fetch or store a byte, short or word to
 * user data space.
 * accepts:
 * c3 - target address
 * c4 - destination address
 */
LEAF(fueword64)
XLEAF(fueword_c)
XLEAF(fueword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	cld	v0, zero, 0($c3)	# fetch word
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csd	v0, zero, 0($c4)	# store word
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2	# fswberr
	nop
XEND(fueword)
XEND(fueword_c)
END(fueword64)

LEAF(fueword32)
XLEAF(fueword32_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clw	v0, zero, 0($c3)	# fetch word
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csw	v0, zero, 0($c4)	# store word
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2
	nop
XEND(fueword32_c)
END(fueword32)

LEAF(fuesword)
XLEAF(fuesword_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clhu	v0, zero, 0($c3)	# fetch short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csh	v0, zero, 0($c4)	# store short
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2	# fswberr
	nop
XEND(fuesword_c)
END(fuesword)

LEAF(fubyte)
XLEAF(fubyte_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clbu	v0, zero, 0($c3)	# fetch byte
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# fswberr
	nop
XEND(fubyte_c)
END(fubyte)

LEAF(fuecap)
	cgetaddr	t0, $c3
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f	# make sure address is in user space
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	clc	$c3, zero, 0($c3)	# fetch capability
	csc	$c3, zero, 0($c4)	# store capability
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2	# fswberr
	nop
END(fuecap)

LEAF(suword64_c)
XLEAF(suword_c)
XLEAF(suword64)
XLEAF(suword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csd	a0, zero, 0($c3)	# store word
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
XEND(suword)
XEND(suword64)
XEND(suword_c)
END(suword64_c)

LEAF(sucap)
	CAPTABLE_LOAD($c2, fswberr)
	cgetbase	t0, $c3
	blt	t0, zero, 1f	# make sure address is in user space
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csc	$c4, zero, 0($c3)	# store cap
	CHERI_NULL($c2)
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
END(sucap)

LEAF(suword32)
XLEAF(suword32_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csw	a0, zero, 0($c3)	# store word
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
XEND(suword32_c)
END(suword32)

/*
 * casueword_c(9)
 * <v0>u_long casueword_c(<c3>u_long *p, <a0>u_long oldval,
 *     <c4>u_long *oldval_p, <a1>u_long newval);
 */
/*
 * casueword32_c(9)
 * <v0>uint32_t casueword32_c(<c3>uint32_t *p, <a0>uint32_t oldval,
 *     <c4>int32_t *oldval_p, <a1>uint32_t newval);
 */
LEAF(casueword32)
XLEAF(casueword32_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
2:
	move	t0, a1
	cllw	t1, $c3		# load word
	bne	a0, t1, 3f
	nop
	cscw	t0, zero, $c3	# store word
	beqz	t0, 2b
	nop
	j	4f
	li	v0, 0
3:
	li	v0, -1
4:
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	csw	t1, zero, 0($c4)	# unconditionally store old word
1:
	cjr	$c2	# fswberr
	nop
XEND(casueword32_c)
END(casueword32)

LEAF(casueword64_c)
XLEAF(casueword_c)
XLEAF(casueword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
2:
	move	t0, a1
	clld	t1, $c3
	bne	a0, t1, 3f
	nop
	cscd	t0, zero, $c3	# store word
	beqz	t0, 2b
	nop
	j	4f
	li	v0, 0
3:
	li	v0, -1
4:
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	csd	t1, zero, 0($c4)	# unconditionally store old word
1:
	cjr	$c2	# fswberr
	nop
XEND(casueword)
XEND(casueword_c)
END(casueword64_c)

/*
 * Will have to flush the instruction cache if byte merging is done in hardware.
 */
LEAF(susword)
XLEAF(susword_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csh	a0, zero, 0($c3)	# store short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
XEND(susword_c)
END(susword)

LEAF(subyte)
XLEAF(subyte_c)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csb	a0, zero, 0($c3)	# store short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
XEND(subyte_c)
END(subyte)

LEAF(fswberr)
	cjr	$c17
	li	v0, -1
END(fswberr)

#if 0 /* patched out */
/*
 * fuswintr and suswintr are just like fusword and susword except that if
 * the page is not in memory or would cause a trap, then we return an error.
 * The important thing is to prevent sleep() and switch().
 */
LEAF(fuswintr)
	cgetbase t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswintrberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clhu	v0, zero, 0($c3)	# fetch short
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# fswintrberr
	nop
END(fuswintr)

LEAF(suswintr)
	cgetbase t0, $c3	# make sure source is in userspace
	CAPTABLE_LOAD($c2, fswintrberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csh	a0, zero, 0($c3)	# store short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswintrberr
	nop
END(suswintr)

LEAF(fswintrberr)
	cjr	$c17
	li	v0, -1
END(fswintrberr)

#endif /* patched out */

/*
 * <c3>void *memset(<c3>void *s1, <a0>int c, <a1>int len)
 * NetBSD: memset.S,v 1.3 2001/10/16 15:40:53 uch Exp
 */
LEAF(memset)
XLEAF(memset_c)
	blt	a1, 12, memsetsmallclr	# small amount to clear?
	cmove	$c1, $c3		# save c3 for result

	sll	t1, a0, 8		# compute  c << 8 in t1
	or	t1, t1, a0		# compute c << 8 | c in t1
	sll	t2, t1, 16		# shift that left 16
	or	t1, t2, t1		# or together

	cgetbase	t2, $c3
	cgetoffset	t3, $c3
	PTR_ADDU	t3, t2, t3
	PTR_SUBU	t0, zero, t3	# compute # bytes to word align address
	and	t0, t0, 3
	beq	t0, zero, 1f		# skip if word aligned
	PTR_SUBU	a1, a1, t0	# subtract from remaining count
	REG_LI	t3, 0
	cincoffset	$c2, $c1, t0
3:
	cincoffset	$c1, $c1, 1
	ceq	t0, $c1, $c2
	beq	t0, zero, 3b
	csb	a0, zero, -1($c1)	# store 1, 2, or 3 bytes to align
1:
	and	v1, a1, 3		# compute number of whole words left
	PTR_SUBU	t0, a1, v1
	PTR_SUBU	a1, a1, t0
	cincoffset	$c2, $c1, t0	# compute ending address
2:
	cincoffset	$c1, $c1, 4	# clear words
	ceq	t0, $c1, $c2		#  unrolling loop does not help
	beq	t0, zero, 2b		#  since we are limited by memory speed
	csw	t1, zero, -4($c1)

memsetsmallclr:
	ble	a1, zero, 2f
	cincoffset	$c2, $c1, a1	# compute ending address
1:
	cincoffset	$c1, $c1, 1	# clear bytes
	ceq	t0, $c1, $c2
	beq	t0, zero, 1b
	csb	a0, zero, -1($c1)
2:
	cjr	$c17
	nop
END(memset)

/*
 * bzero(<c3>s1, <a0>n)
 */
LEAF(bzero)
XLEAF(blkclr)
	blt	a0, 12, smallclr	# small amount to clear?
	nop

	cgetbase	t0, $c3
	cgetoffset	a3, $c3
	PTR_ADDU	a3, a3, t0
	// PTR_SUBU	a3, zero, a0
	and	a3, a3, 3		# compute # bytes to word align address
	beq	a3, zero, 1f		# skip if word aligned
	PTR_SUBU	a0, a0, a3	# subtract from remaining count

	cincoffset	$c2, $c3, a3
3:
	cincoffset	$c3, $c3, 1
	cltu	t0, $c3, $c2
	bne	t0, zero, 3b
	csb	zero, zero, -1($c3)
1:
	and		v0, a0, 3	# compute misaligned tail
	PTR_SUBU	a3, a0, v0	# compute number of bytes to copy
	move	a0, v0			# a0 is the remaining tail bytes to copy
	cincoffset	$c2, $c3, a3	# compute ending address
2:
	cincoffset	$c3, $c3, 4	# clear words
	cltu	t0, $c3, $c2		#  unrolling loop does not help
	bne	t0, zero, 2b		#  since we are limited by memory speed
	csw	zero, zero, -4($c3)
smallclr:
	ble	a0, zero, 2f
	cincoffset	$c2, $c3, a0	# compute ending address
1:
	cincoffset	$c3, $c3, 1	# clear bytes
	cltu	t0, $c3, $c2
	bne	t0, zero, 1b
	csb	zero, zero, -1($c3)
2:
	cjr	$c17
	nop
END(bzero)

/*
 * Compare byte string
 * bcmp(s1, s2, n)
 * c3: s1
 * c4: s2
 * a0: n
 */
LEAF(bcmp)
	blt	a0, 16, smallcmp	# is it worth any trouble?
	cgetaddr	t0, $c3
	cgetaddr	t1, $c4
	xor	v0, t0, t1		# compare low two bits of addresses
	and	v0, v0, 3
	PTR_SUBU	a3, zero, t1		# compute # bytes to word align address
	bne	v0, zero, smallcmp	# not possible to align addresses
	and	a3, a3, 3

	beq	a3, zero, 1f
	PTR_SUBU	a0, a0, a3		# subtract from remaining count
	move	v0, v1			# init v0,v1 so unmodified bytes match
	/* Compare unaligned bytes, read 1, 2, or 3 bytes */
4:
	clb	v0, zero, 0($c3)
	clb	v1, zero, 0($c4)
	cincoffset	$c3, $c3, 1
	bne	v0, v1, nomatch
	cincoffset	$c4, $c4, 1
	daddi	a3, a3, -1
	bnez	a3, 4b
1:
	and	a3, a0, ~3		# compute number of whole words left
	PTR_SUBU	a0, a0, a3		#   which has to be >= (16-3) & ~3
	cincoffset	$c5, $c3, a3		# compute ending address
2:
	clw	v0, zero, 0($c3)		# compare words
	clw	v1, zero, 0($c4)
	cincoffset	$c3, $c3, 4
	bne	v0, v1, nomatch
	cincoffset	$c4, $c4, 4
	cne	v0, $c3, $c5
	bnez	v0, 2b
	nop
	/* Fall through, finish remainder */
smallcmp:
	ble	a0, zero, match
	cincoffset $c5, $c3, a0		# compute ending address
1:
	clb	v0, zero, 0($c3)
	clb	v1, zero, 0($c4)
	cincoffset	$c3, $c3, 1
	bne	v0, v1, nomatch
	cincoffset	$c4, $c4, 1
	ceq	v0, $c5, $c3
	beqz	v0, 1b
	nop
match:
	cjr	$c17
	move	v0, zero
nomatch:
	cjr	$c17
	li	v0, 1
END(bcmp)


/*
 * Find first bit set
 * bit = ffs(value)
 * a0: value
 */
LEAF(ffs)
	beq	a0, zero, 2f
	move	v0, zero
1:
	and	v1, a0, 1		# bit set?
	addu	v0, v0, 1
	beq	v1, zero, 1b		# no, continue
	srl	a0, a0, 1
2:
	cjr	$c17
	nop
END(ffs)


#if defined(DDB) || defined(DEBUG)

LEAF(kdbpeek)
	PTR_LA	v1, ddberr
	and	v0, a0, 3			# unaligned ?
	GET_CPU_PCPU(t1)
	PTR_L	t1, PC_CURPCB(t1)
	bne	v0, zero, 1f
	PTR_S	v1, U_PCB_ONFAULT(t1)

	lw	v0, (a0)
	jr	ra
	PTR_S	zero, U_PCB_ONFAULT(t1)

1:
	LWHI	v0, 0(a0)
	LWLO	v0, 3(a0)
	jr	ra
	PTR_S	zero, U_PCB_ONFAULT(t1)
END(kdbpeek)

LEAF(kdbpeekd)
	PTR_LA	v1, ddberr
	and	v0, a0, 3			# unaligned ?
	GET_CPU_PCPU(t1)
	PTR_L	t1, PC_CURPCB(t1)
	bne	v0, zero, 1f
	PTR_S	v1, U_PCB_ONFAULT(t1)

	ld	v0, (a0)
	jr	ra
	PTR_S	zero, U_PCB_ONFAULT(t1)

1:
	REG_LHI	v0, 0(a0)
	REG_LLO	v0, 7(a0)
	jr	ra
	PTR_S	zero, U_PCB_ONFAULT(t1)
END(kdbpeekd)

ddberr:
	jr	ra
	nop

#if defined(DDB)
LEAF(kdbpoke)
	PTR_LA	v1, ddberr
	and	v0, a0, 3			# unaligned ?
	GET_CPU_PCPU(t1)
	PTR_L	t1, PC_CURPCB(t1)
	bne	v0, zero, 1f
	PTR_S	v1, U_PCB_ONFAULT(t1)

	sw	a1, (a0)
	jr	ra
	PTR_S	zero, U_PCB_ONFAULT(t1)

1:
	SWHI	a1, 0(a0)
	SWLO	a1, 3(a0)
	jr	ra
	PTR_S	zero, U_PCB_ONFAULT(t1)
END(kdbpoke)

	.data
	.globl	esym
esym:	.word	0

#endif /* DDB */
#endif /* DDB || DEBUG */

	.text
LEAF(breakpoint)
	break	MIPS_BREAK_SOVER_VAL
	jr	ra
	nop
END(breakpoint)

LEAF(setjmp)
	mfc0	v0, MIPS_COP_0_STATUS	# Later the "real" spl value!
	REG_S	s0, (SZREG * PCB_REG_S0)(a0)
	REG_S	s1, (SZREG * PCB_REG_S1)(a0)
	REG_S	s2, (SZREG * PCB_REG_S2)(a0)
	REG_S	s3, (SZREG * PCB_REG_S3)(a0)
	REG_S	s4, (SZREG * PCB_REG_S4)(a0)
	REG_S	s5, (SZREG * PCB_REG_S5)(a0)
	REG_S	s6, (SZREG * PCB_REG_S6)(a0)
	REG_S	s7, (SZREG * PCB_REG_S7)(a0)
	REG_S	s8, (SZREG * PCB_REG_S8)(a0)
	REG_S	sp, (SZREG * PCB_REG_SP)(a0)
	REG_S	ra, (SZREG * PCB_REG_RA)(a0)
	REG_S	v0, (SZREG * PCB_REG_SR)(a0)
#ifdef CPU_CHERI
	/* XXXRW: CHERI kernel setjmp here? */
#endif
	jr	ra
	li	v0, 0			# setjmp return
END(setjmp)

LEAF(longjmp)
	REG_L	v0, (SZREG * PCB_REG_SR)(a0)
	REG_L	ra, (SZREG * PCB_REG_RA)(a0)
	REG_L	s0, (SZREG * PCB_REG_S0)(a0)
	REG_L	s1, (SZREG * PCB_REG_S1)(a0)
	REG_L	s2, (SZREG * PCB_REG_S2)(a0)
	REG_L	s3, (SZREG * PCB_REG_S3)(a0)
	REG_L	s4, (SZREG * PCB_REG_S4)(a0)
	REG_L	s5, (SZREG * PCB_REG_S5)(a0)
	REG_L	s6, (SZREG * PCB_REG_S6)(a0)
	REG_L	s7, (SZREG * PCB_REG_S7)(a0)
	REG_L	s8, (SZREG * PCB_REG_S8)(a0)
	REG_L	sp, (SZREG * PCB_REG_SP)(a0)
#ifdef CPU_CHERI
	/* XXXRW: CHERI kernel longjmp here? */
#endif
	mtc0	v0, MIPS_COP_0_STATUS	# Later the "real" spl value!
	ITLBNOPFIX
	jr	ra
	li	v0, 1			# longjmp return
END(longjmp)

LEAF(mips3_ld)
	.set push
	.set noreorder
	.set mips64
#if defined(__mips_o32)
	mfc0	t0, MIPS_COP_0_STATUS		# turn off interrupts
	and	t1, t0, ~(MIPS_SR_INT_IE)
	mtc0	t1, MIPS_COP_0_STATUS
	COP0_SYNC
	nop
	nop
	nop

	ld	v0, 0(a0)
#if _BYTE_ORDER == _BIG_ENDIAN
	dsll	v1, v0, 32
	dsra	v1, v1, 32			# low word in v1
	dsra	v0, v0, 32			# high word in v0
#else
	dsra	v1, v0, 32			# high word in v1
	dsll	v0, v0, 32
	dsra	v0, v0, 32			# low word in v0
#endif

	mtc0	t0, MIPS_COP_0_STATUS		# restore intr status.
	COP0_SYNC
	nop
#else /* !__mips_o32 */
	ld	v0, 0(a0)
#endif /* !__mips_o32 */

	jr	ra
	nop
	.set pop
END(mips3_ld)

LEAF(mips3_sd)
	.set push
	.set mips64
	.set noreorder
#if defined(__mips_o32)
	mfc0	t0, MIPS_COP_0_STATUS		# turn off interrupts
	and	t1, t0, ~(MIPS_SR_INT_IE)
	mtc0	t1, MIPS_COP_0_STATUS
	COP0_SYNC
	nop
	nop
	nop

	# NOTE: a1 is padding!

#if _BYTE_ORDER == _BIG_ENDIAN
	dsll	a2, a2, 32			# high word in a2
	dsll	a3, a3, 32			# low word in a3
	dsrl	a3, a3, 32
#else
	dsll	a2, a2, 32			# low word in a2
	dsrl	a2, a2, 32
	dsll	a3, a3, 32			# high word in a3
#endif
	or	a1, a2, a3
	sd	a1, 0(a0)

	mtc0	t0, MIPS_COP_0_STATUS		# restore intr status.
	COP0_SYNC
	nop
#else /* !__mips_o32 */
	sd	a1, 0(a0)
#endif /* !__mips_o32 */

	jr	ra
	nop
	.set pop
END(mips3_sd)

#ifdef CPU_QEMU_MALTA
LEAF(cheri_trace_log)
	.set push
	.set noreorder
	li	$0, 0xface
	cjr	$c17
	nop
	.set pop
END(cheri_trace_log)
#endif
// CHERI CHANGES START
// {
//   "updated": 20200708,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
