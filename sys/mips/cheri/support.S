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
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase	t0, $c3 # make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_PCREL_LOAD($c12, t0, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_PCREL_LOAD($c2, t0, copyerr)	# prepare the onfault jump point
	CAPCALL_PCREL_LOAD($c12, t0, copystr_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$cnull, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from copyinstr */
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
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
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase	t0, $c4 # make sure destination is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_PCREL_LOAD($c12, t0, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_PCREL_LOAD($c2, t0, copyerr)	# prepare the onfault jump point
	CAPCALL_PCREL_LOAD($c12, t0, copystr_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$cnull, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from copyoutstr */
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
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
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c3	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_PCREL_LOAD($c12, t0, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_PCREL_LOAD($c2, t0, copyerr)	# prepare the onfault jump point
	CAPCALL_PCREL_LOAD($c12, t0, bcopynocap_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	csc	$cnull, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
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
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c3	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_PCREL_LOAD($c12, t0, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_PCREL_LOAD($c2, t0, copyerr)	# prepare the onfault jump point
	CAPCALL_PCREL_LOAD($c12, t0, bcopy_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	csc	$cnull, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
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
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c4	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_PCREL_LOAD($c12, t0, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_PCREL_LOAD($c2, t0, copyerr)	# prepare the onfault jump point
	CAPCALL_PCREL_LOAD($c12, t0, bcopynocap_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	csc	$cnull, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
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
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)

	cgetbase t0, $c4	# make sure source is in userspace
	bge	t0, zero, 1f
	nop

	CAPTABLE_PCREL_LOAD($c12, t0, copyerr)
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	CAPTABLE_PCREL_LOAD($c2, t0, copyerr)	# prepare the onfault jump point
	CAPCALL_PCREL_LOAD($c12, t0, bcopy_c)
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	csc	$cnull, zero, U_PCB_ONFAULT($c1)

	clc		$c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	/* Propagate v0 return value from cheri_bcopy */
	li	v0, 0
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
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
XLEAF(fueword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	cld	v0, zero, 0($c3)	# fetch word
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	csd	v0, zero, 0($c4)	# store word
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2	# fswberr
	nop
XEND(fueword)
END(fueword64)

LEAF(fueword32)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clw	v0, zero, 0($c3)	# fetch word
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	csw	v0, zero, 0($c4)	# store word
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2
	nop
END(fueword32)

LEAF(fuesword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clhu	v0, zero, 0($c3)	# fetch short
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	csh	v0, zero, 0($c4)	# store short
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2	# fswberr
	nop
END(fuesword)

LEAF(fubyte)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clbu	v0, zero, 0($c3)	# fetch byte
	cjr	$c17
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# fswberr
	nop
END(fubyte)

LEAF(fuecap)
	cgetaddr	t0, $c3
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f	# make sure address is in user space
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	clc	$c3, zero, 0($c3)	# fetch capability
	csc	$c3, zero, 0($c4)	# store capability
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	li	v0, 0
1:
	cjr	$c2	# fswberr
	nop
END(fuecap)

LEAF(suword64)
XLEAF(suword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csd	a0, zero, 0($c3)	# store word
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
XEND(suword)
END(suword64)

LEAF(sucap)
	CAPTABLE_PCREL_LOAD($c2, t0, fswberr)
	cgetbase	t0, $c3
	blt	t0, zero, 1f	# make sure address is in user space
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csc	$c4, zero, 0($c3)	# store cap
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
END(sucap)

LEAF(suword32)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csw	a0, zero, 0($c3)	# store word
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
END(suword32)

/*
 * casueword(9)
 * <v0>u_long casueword(<c3>u_long *p, <a0>u_long oldval,
 *     <c4>u_long *oldval_p, <a1>u_long newval);
 */
/*
 * casueword32(9)
 * <v0>uint32_t casueword32(<c3>uint32_t *p, <a0>uint32_t oldval,
 *     <c4>int32_t *oldval_p, <a1>uint32_t newval);
 */
LEAF(casueword32)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
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
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	csw	t1, zero, 0($c4)	# unconditionally store old word
1:
	cjr	$c2	# fswberr
	nop
END(casueword32)

LEAF(casueword64)
XLEAF(casueword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
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
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	csd	t1, zero, 0($c4)	# unconditionally store old word
1:
	cjr	$c2	# fswberr
	nop
XEND(casueword)
END(casueword64)

/*
 * Will have to flush the instruction cache if byte merging is done in hardware.
 */
LEAF(susword)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csh	a0, zero, 0($c3)	# store short
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
END(susword)

LEAF(subyte)
	cgetaddr t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csb	a0, zero, 0($c3)	# store short
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# fswberr
	nop
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
	CAPTABLE_PCREL_LOAD($c2, t1, fswintrberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	clhu	v0, zero, 0($c3)	# fetch short
	cjr	$c17
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# fswintrberr
	nop
END(fuswintr)

LEAF(suswintr)
	cgetbase t0, $c3	# make sure source is in userspace
	CAPTABLE_PCREL_LOAD($c2, t1, fswintrberr)
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)	# store onfault function
	csh	a0, zero, 0($c3)	# store short
	csc	$cnull, zero, U_PCB_ONFAULT($c1)
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
	blt	a1, 12, memsetsmallclr	# small amount to clear?
	cmove	$c1, $c3		# save c3 for result

	sll	t1, a0, 8		# compute  c << 8 in t1
	or	t1, t1, a0		# compute c << 8 | c in t1
	sll	t2, t1, 16		# shift that left 16
	or	t1, t2, t1		# or together

	cgetbase	t2, $c3
	cgetoffset	t3, $c3
	LONG_ADDU	t3, t2, t3
	LONG_SUBU	t0, zero, t3	# compute # bytes to word align address
	and	t0, t0, 3
	beq	t0, zero, 1f		# skip if word aligned
	LONG_SUBU	a1, a1, t0	# subtract from remaining count
	REG_LI	t3, 0
	cincoffset	$c2, $c1, t0
3:
	cincoffset	$c1, $c1, 1
	ceq	t0, $c1, $c2
	beq	t0, zero, 3b
	csb	a0, zero, -1($c1)	# store 1, 2, or 3 bytes to align
1:
	and	v1, a1, 3		# compute number of whole words left
	LONG_SUBU	t0, a1, v1
	LONG_SUBU	a1, a1, t0
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
 * blkclr(<c3>s1, <a0>n)
 */
LEAF(blkclr)
	blt	a0, 12, smallclr	# small amount to clear?
	nop

	cgetbase	t0, $c3
	cgetoffset	a3, $c3
	LONG_ADDU	a3, a3, t0
	// LONG_SUBU	a3, zero, a0
	and	a3, a3, 3		# compute # bytes to word align address
	beq	a3, zero, 1f		# skip if word aligned
	LONG_SUBU	a0, a0, a3	# subtract from remaining count

	cincoffset	$c2, $c3, a3
3:
	cincoffset	$c3, $c3, 1
	cltu	t0, $c3, $c2
	bne	t0, zero, 3b
	csb	zero, zero, -1($c3)
1:
	and		v0, a0, 3	# compute misaligned tail
	LONG_SUBU	a3, a0, v0	# compute number of bytes to copy
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
END(blkclr)

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

	.text
LEAF(breakpoint)
	break	MIPS_BREAK_SOVER_VAL
	cjr	$c17
	nop
END(breakpoint)

LEAF(setjmp)
	mfc0	v0, MIPS_COP_0_STATUS	# Later the "real" spl value!
	csd	s0, zero, (SZREG * PCB_REG_S0)($c3)
	csd	s1, zero, (SZREG * PCB_REG_S1)($c3)
	csd	s2, zero, (SZREG * PCB_REG_S2)($c3)
	csd	s3, zero, (SZREG * PCB_REG_S3)($c3)
	csd	s4, zero, (SZREG * PCB_REG_S4)($c3)
	csd	s5, zero, (SZREG * PCB_REG_S5)($c3)
	csd	s6, zero, (SZREG * PCB_REG_S6)($c3)
	csd	s7, zero, (SZREG * PCB_REG_S7)($c3)
	csd	s8, zero, (SZREG * PCB_REG_S8)($c3)
	csd	sp, zero, (SZREG * PCB_REG_SP)($c3)
	csd	ra, zero, (SZREG * PCB_REG_RA)($c3)
	csd	v0, zero, (SZREG * PCB_REG_SR)($c3)
	REG_LI	t0, 12
	csc	$c17, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C17)($c3)
	csc	$c18, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C18)($c3)
	csc	$c19, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C19)($c3)
	csc	$c20, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C20)($c3)
	csc	$c21, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C21)($c3)
	csc	$c22, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C22)($c3)
	csc	$c23, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C23)($c3)
	csc	$c24, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C24)($c3)
	csc	$c26, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C26)($c3)
	csc	$c11, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_STC)($c3)

	cjr	$c17
	li	v0, 0			# setjmp return
END(setjmp)

LEAF(longjmp)
	cld	v0, zero, (SZREG * PCB_REG_SR)($c3)
	cld	ra, zero, (SZREG * PCB_REG_RA)($c3)
	cld	s0, zero, (SZREG * PCB_REG_S0)($c3)
	cld	s1, zero, (SZREG * PCB_REG_S1)($c3)
	cld	s2, zero, (SZREG * PCB_REG_S2)($c3)
	cld	s3, zero, (SZREG * PCB_REG_S3)($c3)
	cld	s4, zero, (SZREG * PCB_REG_S4)($c3)
	cld	s5, zero, (SZREG * PCB_REG_S5)($c3)
	cld	s6, zero, (SZREG * PCB_REG_S6)($c3)
	cld	s7, zero, (SZREG * PCB_REG_S7)($c3)
	cld	s8, zero, (SZREG * PCB_REG_S8)($c3)
	cld	sp, zero, (SZREG * PCB_REG_SP)($c3)
	REG_LI	t0, 12
	clc	$c17, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C17)($c3)
	clc	$c18, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C18)($c3)
	clc	$c19, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C19)($c3)
	clc	$c20, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C20)($c3)
	clc	$c21, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C21)($c3)
	clc	$c22, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C22)($c3)
	clc	$c23, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C23)($c3)
	clc	$c24, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C24)($c3)
	clc	$c26, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_C26)($c3)
	clc	$c11, t0, (CHERICAP_SIZE * CHERIKFRAME_OFF_STC)($c3)

	mtc0	v0, MIPS_COP_0_STATUS	# Later the "real" spl value!
	ITLBNOPFIX
	cjr	$c17
	li	v0, 1			# longjmp return
END(longjmp)

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
