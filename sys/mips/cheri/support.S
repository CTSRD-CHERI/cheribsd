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
#include <machine/cherireg.h>
#include <machine/cheriasm.h>

#include "assym.s"

	.set	noreorder

	.text

/*
 * Copy a string from one capabilty to another up to a maximum length.
 * Return the length by reference.
 *
 * copystr_c() accepts:
 * c3 - source pointer
 * c4 - destination pointer
 * c5 - pointer length copied (size_t)
 * a0 - maximum length
 */
LEAF(copystr_c)
#ifdef CHERI_KERNEL
XLEAF(copystr)
#endif
	li		v0, 0	/* Hopefully we succeed */
	beqz		a0, cstr_return_toolong /* Return if zero-length. */
	li		t1, 1	/* Length we will have copied in loop */
cstr_loop:
	clbu		t0, t1, -1($c3)
	beq		t0, zero, cstr_return_nul
	csb		t0, t1, -1($c4)
	bne		t1, a0, cstr_loop
	daddiu		t1, t1, 1

cstr_return_toolong:
	li		v0, ENAMETOOLONG
	daddiu		t1, t1, -1	/* Count is 1 too high */
cstr_return_nul:	/* Store length read if c5 is non-NULL */
	cbez		$c5, cstr_return
	nop
	csd		t1, zero, 0($c5)	/* Store bytes copied */
cstr_return:
#ifdef CHERI_KERNEL
	cjr	$c17
#else
	jr	ra
#endif
	nop
END(copystr_c)

/*
 * pure capability ABI-only versions of the support routines
 */
#ifdef CHERI_KERNEL

/*
 * Implement CHERI memcpy() and bcopy() variants in assembly; C works fine in
 * the kernel most of the time, but copyincap() and copyoutcap() require that
 * no callee-save registers be trampled over due to fault-based error
 * handling.
 *
 * This version handles both aligned and unaligned access.
 * This version also handles overlapping copies.
 * This version does not preserve memory tags.
 *
 *
 * bcopy() accepts:
 * c3 - source pointer
 * c4 - destination pointer
 * a0 - length
 *
 * memcpy() has inverted source/destination pointers.
 */
LEAF(memcpynocap)
XLEAF(memcpynocap_c)
	cmove	$c1, $c3
	cmove	$c3, $c4
	cmove	$c4, $c1
XLEAF(bcopynocap)
XLEAF(bcopynocap_c)
	beqz	a0, 5f	/* return immediately if zero-length */
	cltu	t0, $c4, $c3	/* forward or backward copy? */
	bnez	t0, 9f	/* forward */
	/* backward copy */
	cmove	$c2, $c4	/* end pointer in c2 */
	cincoffset	$c3, $c3, a0
	cincoffset	$c4, $c4, a0
	b 8f	/* do_copy */
	li	v0, -1	/* byte copy increment */
9:	/* forward: */
	li	v0, 1	/* byte copy increment */
	cincoffset	$c2, $c4, a0	/* end pointer in c2 */
8:	/* do_copy: */
	cgetbase	t2, $c3
	cgetoffset	t1, $c3
	daddu	t2, t2, t1	/* src cursor in t2 */
	cgetbase	t3, $c4
	cgetoffset	t1, $c4
	daddu	t3, t3, t1	/* dest cursor in t3 */
	/* enough bytes to copy for an aligned copy? */
	slti	t1, a0, CHERICAP_SIZE
	bnez	t1, 3f /* check_word_align */
	/* check dest alignment */
	andi	t1, t3, (CHERICAP_SIZE - 1)
	beqz	t1, 7f	/* cap_copy */
3:	/* check_word_align: */
	/* enough bytes to copy for an aligned copy? */
	slti	t1, a0, SZREG
	bnez	t1, 6f /* byte_copy */
	andi	t1, t3, (SZREG - 1)
	bnez	t1, 6f	/* byte_copy */
	nop
	/* fall through */

	/* word_copy: */
	andi	t1, t2, (SZREG - 1)	/* check src alignment */
	bnez	t1, 6f	/* byte_copy */
	li	v1, -SZREG	/* delay slot: backward loop increment */
	bltz	v0, 1f	/* word_copy_back */
	and	a0, a0, v1	/* delay slot: aligned copy length */
	/* forward copy */
	li	v1, SZREG	/* forward loop increment */
	li	t3, 0	/* forward loop offset in t3 */
	b	2f	/* word_loop */
	cincoffset	$c13, $c4, a0
1:	/* word_copy_back: */
	/* backward copy */
	dsub	a0, zero, a0	/* negate copy length becase c4 points at the end */
	li	t3, -SZREG	/* backward loop offset in t3 */
	cincoffset	$c13, $c4, a0
2:	/* word_loop: */
	cld	t0, t3, 0($c3)
	csd	t0, t3, 0($c4)
	cincoffset	$c4, $c4, v1
	ceq	t0, $c13, $c4	/* did we reach the aligned end? */
	beqz	t0, 2b	/* word_loop */
	cincoffset	$c3, $c3, v1
	b	6f	/* byte_copy */
	nop

7:	/* cap_copy: */
	andi	t1, t2, (CHERICAP_SIZE - 1)	/* check src alignment */
	bnez	t1, 6f	/* byte_copy */
	li	v1, -CHERICAP_SIZE	/* delay slot: backward loop increment */
	bltz	v0, 1f	/* cap_copy_back */
	and	a0, a0, v1	/* delay slot: aligned copy length */
	/* forward copy  */
	li	v1, CHERICAP_SIZE	/* forward loop increment */
	li	t3, 0	/* forward loop offset in t3 */
	b	2f	/* cap_loop */
	cincoffset	$c13, $c4, a0
1:	/* cap_copy_back: */
	/* backward copy  */
	dsub	a0, zero, a0	/* negate copy length becase c4 points at the end */
	li	t3, -CHERICAP_SIZE	/* backward loop offset in t3 */
	cincoffset	$c13, $c4, a0
2:	/* cap_loop: */
	clc	$c14, zero, 0($c3)
	ccleartag	$c14, $c14
	csc	$c14, zero, 0($c4)
	cincoffset	$c4, $c4, v1
	ceq	t0, $c13, $c4	/* did we reach the aligned end? */
	beqz	t0, 2b	/* cap_loop */
	cincoffset	$c3, $c3, v1
	/* fall through */

6:	/* byte_copy: */
	ceq	t0, $c2, $c4	/* did we reach the actual end? */
	bnez	t0, 5f	/* return */
	li	t3, 0	/* delay slot: forward loop offset */
	bgtz	v0, 1f	/* if forward copy, skip to byte_loop */
	nop
	li	t3, -1	/* backward loop offset */
1:	/* byte_loop: */
	clb	t0, t3, 0($c3)
	csb	t0, t3, 0($c4)
	cincoffset	$c4, $c4, v0
	ceq	t0, $c2, $c4	/* did we reach the end? */
	beqz	t0, 1b	/* byte_loop */
	cincoffset	$c3, $c3, v0

5:	/* return: */
	cjr	$c17
	cmove	$c3, $c1	/* need to return original c3 for memcpy */
END(memcpynocap)

/*
 * See memcpy() bcopy()
 * This version preserves memory tags, however it requres
 * the input and output pointers to be capability-aligned.
 */
LEAF(memcpy)
XLEAF(memcpy_c)
XLEAF(cheri_memcpy)
	cmove	$c1, $c3
	cmove	$c3, $c4
	cmove	$c4, $c1
XLEAF(bcopy)
XLEAF(bcopy_c)
XLEAF(cheri_bcopy)
	//ori	zero, zero, 0xbeef
	beqz	a0, 9f /* return immediately if zero-length. */
	cltu	v0, $c4, $c3	/* v0 <- forward or backward copy? */
	bnez	v0, 2f		/* forward */
	li	v0, +1	/* delay slot: loop increment direction (forward copy) */

	/* backward bcopy */
	cincoffset	$c4, $c4, a0	/* dst to the end of buffer */
	cincoffset 	$c3, $c3, a0	/* src to the end of buffer */
	li	v0, -1	/* loop increment direction */
	b	2f	/* bcopy main loop */
	/* fall through to bcopy main loop */
2:
	cgetbase	t3, $c4	/* t3 <- base of dst, used to check alignment */
	cgetbase	t2, $c3	/* t2 <- base of src, used to check alignment */
	/* compute loop shift from direction */
	daddiu	a1, v0, -1
	sra	a1, a1, 1	/* a1 = (fwd) ? 0 : -1 bytecopy loop offset */
3:	/* copy bytes until we are aligned to CHERICAP_SIZE or we are done */
	beqz	a0, 9f	/* if we are done copying just return */
	cgetoffset	t1, $c4
	daddu	t1, t1, t3	/* current dst cursor */
	andi	t1, t1, (CHERICAP_SIZE - 1)	/* t1 <- !aligned(dst) */
	seq	t1, t1, zero
	cgetoffset	t0, $c3
	daddu	t0, t0, t2	/* current src cursor */
	andi	t0, t0, (CHERICAP_SIZE - 1)	/* a0 <- !aligned(src) */
	seq	t0, t0, zero
	and	t1, t1, t0	/* t1 <- aligned(dst) and aligned(src) */
	bnez	t1, 2f	/* done, next loop */
	nop	/* XXX-AM probably we can remove this */
	clb	t0, a1, 0($c3)
	cincoffset	$c3, $c3, v0
	csb	t0, a1, 0($c4)
	cincoffset	$c4, $c4, v0
	b	3b	/* loop */
	daddiu	a0, a0, -1	/* consumed another byte */

2:	/* copy aligned bytes until we are past end */
	sll	v1, v0, CHERICAP_SHIFT	/* v1 <- loop increment +- CHERICAP_SIZE */
	sll	t2, a1, CHERICAP_SHIFT	/* t2 <- loop offset 0/-CHERICAP_SIZE */
	li	t0, (-CHERICAP_SIZE) /* find aligned length to copy */
	and	t0, a0, t0
	srl	t3, t0, CHERICAP_SHIFT	/* number of aligned loop iterations */
	dsubu	a0, a0, t0	/* update a0 with remaining tail bytes */
3:
	beqz	t3, 2f	/* done, next loop */
	daddiu	t3, t3, -1
	clc	$c5, t2, 0($c3)
	cincoffset	$c3, $c3, v1
	csc	$c5, t2, 0($c4)
	b	3b	/* loop */
	cincoffset	$c4, $c4, v1

2:	/* copy unaligned bytes until the end */
	beqz	a0, 9f	/* done */
	daddiu	a0, a0, -1
	clb	t0, a1, 0($c3)
	cincoffset	$c3, $c3, v0
	csb	t0, a1, 0($c4)
	b	2b	/* loop */
	cincoffset	$c4, $c4, v0
9:	/* done, just return */
	cjr	$c17
	cmove	$c3, $c1	/* need to return original c3 for memcpy */
END(memcpy)

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
	cgetbase	t0, $c3 # make sure source is in userspace
	bge	t0, zero, 1f
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	PTR_LA	t0, _C_LABEL(copyerr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1, t0)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	t0, copyerr
	cgetpccsetoffset $c2, t0	# prepare the onfault jump point
	PTR_LA	t9, _C_LABEL(copystr)
	cgetpccsetoffset $c12, t9
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
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
	cgetbase	t0, $c4 # make sure destination is in userspace
	bge	t0, zero, 1f
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	PTR_LA	t0, _C_LABEL(copyerr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1, t0)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	t0, copyerr
	cgetpccsetoffset $c2, t0	# prepare the onfault jump point
	PTR_LA	t9, _C_LABEL(copystr)
	cgetpccsetoffset $c12, t9
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
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
XNESTED(copyin_c)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	cgetbase t0, $c3	# make sure source is in userspace
	bge	t0, zero, 1f
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	PTR_LA	t0, _C_LABEL(copyerr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1, t0)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	t0, copyerr
	cgetpccsetoffset $c2, t0	# prepare the onfault jump point
	PTR_LA	t9, _C_LABEL(bcopy)
	cgetpccsetoffset $c12, t9
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
	cjr	$c17
	move	v0, zero
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
	cgetbase t0, $c3	# make sure source is in userspace
	bge	t0, zero, 1f
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	PTR_LA	t0, _C_LABEL(copyerr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1, t0)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	t0, copyerr
	cgetpccsetoffset $c2, t0	# prepare the onfault jump point
	PTR_LA	t9, _C_LABEL(cheri_bcopy)
	cgetpccsetoffset $c12, t9
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
	cjr	$c17
	move	v0, zero
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
	cgetbase t0, $c4	# make sure source is in userspace
	bge	t0, zero, 1f
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	PTR_LA	t0, _C_LABEL(copyerr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1, t0)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	t0, copyerr
	cgetpccsetoffset $c2, t0	# prepare the onfault jump point
	PTR_LA	t9, _C_LABEL(bcopy)
	cgetpccsetoffset $c12, t9
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
	cjr	$c17
	move	v0, zero
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
	cgetbase t0, $c4	# make sure source is in userspace
	bge	t0, zero, 1f
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	PTR_LA	t0, _C_LABEL(copyerr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
1:
	GET_CPU_PCPU($c1, t0)	# clobbers at
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	t0, copyerr
	cgetpccsetoffset $c2, t0	# prepare the onfault jump point
	PTR_LA	t9, _C_LABEL(cheri_bcopy)
	cgetpccsetoffset $c12, t9
	cjalr	$c12, $c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)

	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1) # bcopy modified v1, so reload
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
	cjr	$c17
	move	v0, zero
END(copyoutcap)

LEAF(copyerr)
	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
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
 */
LEAF(fuword64)
XLEAF(fuword)
	cgetbase t0, $c3	# make sure source is in userspace
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	v0, fswberr
	cgetpccsetoffset $c2, v0
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cld	v0, zero, 0($c3)	# fetch word
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	PTR_LA	t0, _C_LABEL(fswberr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
END(fuword64)

LEAF(fuword32)
	cgetbase t0, $c3	# make sure source is in userspace
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	v0, fswberr
	cgetpccsetoffset $c2, v0
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	clw	v0, zero, 0($c3)	# fetch word
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	PTR_LA	t0, _C_LABEL(fswberr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
END(fuword32)

LEAF(fusword)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswberr)
	blt	t0, zero, 1f
	cgetpccsetoffset	$c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	clhu	v0, zero, 0($c3)	# fetch short
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# jump to fswberr
	nop
END(fusword)

LEAF(fubyte)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswberr)
	blt	t0, zero, 1f
	cgetpccsetoffset	$c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	clbu	v0, zero, 0($c3)	# fetch byte
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# jump to fswberr
	nop
END(fubyte)

LEAF(suword64)
XLEAF(suword)
	cgetbase t0, $c3	# make sure source is in userspace
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	v0, fswberr
	cgetpccsetoffset $c2, v0
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csd	a0, zero, 0($c3)	# store word
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	PTR_LA	t0, _C_LABEL(fswberr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
END(suword64)

LEAF(suword32)
	cgetbase t0, $c3	# make sure source is in userspace
	blt	t0, zero, 1f
	nop
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	PTR_LA	v0, fswberr
	cgetpccsetoffset $c2, v0
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csw	a0, zero, 0($c3)	# store word
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	PTR_LA	t0, _C_LABEL(fswberr)
	cgetpccsetoffset	$c12, t0
	cjr	$c12
	nop
END(suword32)

/*
 * casuword(9)
 * <v0>u_long casuword(<c3>u_long *p, <a0>u_long oldval, <a1>u_long newval)
 */
/*
 * casuword32(9)
 * <v0>uint32_t casuword(<c3>uint32_t *p, <a0>uint32_t oldval,
 *			 <a1>uint32_t newval)
 */
LEAF(casuword32)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswberr)
	blt	t0, zero, 1f
	cgetpccsetoffset	$c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
2:
	move	t0, a1
	cllw	v0, $c3
	bne	a0, v0, 3f
	nop
	cscw	t0, zero, $c3	# store word
	beqz	t0, 2b
	nop
	j	4f
	nop
3:
	li	v0, -1
4:
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	nop
1:
	cjr	$c2	# jump to fswberr
	nop
END(casuword32)

LEAF(casuword64)
XLEAF(casuword)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswberr)
	blt	t0, zero, 1f
	cgetpccsetoffset	$c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
2:
	move	t0, a1
	clld	v0, $c3
	bne	a0, v0, 3f
	nop
	cscd	t0, zero, $c3	# store word
	beqz	t0, 2b
	nop
	j	4f
	nop
3:
	li	v0, -1
4:
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	nop
1:
	cjr	$c2	# jump to fswberr
	nop
END(casuword64)

/*
 * Will have to flush the instruction cache if byte merging is done in hardware.
 */
LEAF(susword)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswberr)
	blt	t0, zero, 1f
	cgetpccsetoffset $c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csh	a0, zero, 0($c3)	# store short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# jump to fswberr
	nop
END(susword)

LEAF(subyte)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswberr)
	blt	t0, zero, 1f
	cgetpccsetoffset $c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csb	a0, zero, 0($c3)	# store short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# jump to fswberr
	nop
END(subyte)

LEAF(fswberr)
	cjr	$c17
	li	v0, -1
END(fswberr)

/*
 * fuswintr and suswintr are just like fusword and susword except that if
 * the page is not in memory or would cause a trap, then we return an error.
 * The important thing is to prevent sleep() and switch().
 */
LEAF(fuswintr)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswintrberr)
	blt	t0, zero, 1f
	cgetpccsetoffset	$c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	clhu	v0, zero, 0($c3)	# fetch short
	CHERI_NULL($c2)
	cjr	$c17
	csc	$c2, zero, U_PCB_ONFAULT($c1)
1:
	cjr	$c2	# jump to fswintrberr
	nop
END(fuswintr)

LEAF(suswintr)
	cgetbase t0, $c3	# make sure source is in userspace
	PTR_LA	v0, _C_LABEL(fswintrberr)
	blt	t0, zero, 1f
	cgetpccsetoffset $c2, v0
	GET_CPU_PCPU($c1, t0)
	clc	$c1, zero, PC_CURPCB($c1)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	csh	a0, zero, 0($c3)	# store short
	CHERI_NULL($c2)
	csc	$c2, zero, U_PCB_ONFAULT($c1)
	cjr	$c17
	move	v0, zero
1:
	cjr	$c2	# jump to fswintrberr
	nop
END(suswintr)

LEAF(fswintrberr)
	cjr	$c17
	li	v0, -1
END(fswintrberr)

/*
 * <c3>void *memset(<c3>void *s1, <a0>int c, <a1>int len)
 * NetBSD: memset.S,v 1.3 2001/10/16 15:40:53 uch Exp
 */
LEAF(memset)
XLEAF(memset_c)
	blt	a1, 12, memsetsmallclr	# small amount to clear?
	cmove	$c1, $c3		# save c3 for result

	sll	t1, a0, 8		# compute  c << 8 in t1
	or	t1, t1, a1		# compute c << 8 | c in t1
	sll	t2, t1, 16		# shift that left 16
	or	t1, t2, t1		# or together

	/*
	 * XXX-AM: can we ignore the base?
	 */
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
	cincoffset	$c2, $c3, a1	# compute ending address
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

	/* XXX-AM: can we ignore the base? */
	cgetbase	t0, $c3
	cgetoffset	a3, $c3
	PTR_ADDU	a3, a3, t0
	PTR_SUBU	a3, zero, a0	# compute # bytes to word align address
	and	a3, a3, 3
	beq	a3, zero, 1f		# skip if word aligned
	PTR_SUBU	a0, a0, a3	# subtract from remaining count

	REG_LI	t3, 0			# clear 1, 2, or 3 bytes to align
	cincoffset	$c2, $c3, a3
3:
	cincoffset	$c3, $c3, 1
	ceq	t0, $c3, $c2
	beq	t0, zero, 3b
	csb	zero, zero, -1($c1)
1:
	and	v0, a0, 3		# compute number of words left
	PTR_SUBU	a3, a0, v0
	move	a0, v0
	cincoffset	$c2, $c3, a3	# compute ending address
2:
	cincoffset	$c3, $c3, 4	# clear words
	ceq	t0, $c3, $c2		#  unrolling loop does not help
	beq	t0, zero, 2b		#  since we are limited by memory speed
	csw	zero, zero, -4($c3)
smallclr:
	ble	a0, zero, 2f
	cincoffset	$c2, $c3, a0	# compute ending address
1:
	cincoffset	$c3, $c3, 1	# clear bytes
	ceq	t0, $c3, $c2
	beq	t0, zero, 1b
	csb	zero, zero, -1($c3)
2:
	cjr	$c17
	nop
END(bzero)


/*
 * bcmp(s1, s2, n)
 */
LEAF(bcmp)
	blt	a2, 16, smallcmp	# is it worth any trouble?
	xor	v0, a0, a1		# compare low two bits of addresses
	and	v0, v0, 3
	PTR_SUBU	a3, zero, a1		# compute # bytes to word align address
	bne	v0, zero, unalignedcmp	# not possible to align addresses
	and	a3, a3, 3

	beq	a3, zero, 1f
	PTR_SUBU	a2, a2, a3		# subtract from remaining count
	move	v0, v1			# init v0,v1 so unmodified bytes match
	LWHI	v0, 0(a0)		# read 1, 2, or 3 bytes
	LWHI	v1, 0(a1)
	PTR_ADDU	a1, a1, a3
	bne	v0, v1, nomatch
	PTR_ADDU	a0, a0, a3
1:
	and	a3, a2, ~3		# compute number of whole words left
	PTR_SUBU	a2, a2, a3		#   which has to be >= (16-3) & ~3
	PTR_ADDU	a3, a3, a0		# compute ending address
2:
	lw	v0, 0(a0)		# compare words
	lw	v1, 0(a1)
	PTR_ADDU	a0, a0, 4
	bne	v0, v1, nomatch
	PTR_ADDU	a1, a1, 4
	bne	a0, a3, 2b
	nop
	b	smallcmp		# finish remainder
	nop
unalignedcmp:
	beq	a3, zero, 2f
	PTR_SUBU	a2, a2, a3		# subtract from remaining count
	PTR_ADDU	a3, a3, a0		# compute ending address
1:
	lbu	v0, 0(a0)		# compare bytes until a1 word aligned
	lbu	v1, 0(a1)
	PTR_ADDU	a0, a0, 1
	bne	v0, v1, nomatch
	PTR_ADDU	a1, a1, 1
	bne	a0, a3, 1b
	nop
2:
	and	a3, a2, ~3		# compute number of whole words left
	PTR_SUBU	a2, a2, a3		#   which has to be >= (16-3) & ~3
	PTR_ADDU	a3, a3, a0		# compute ending address
3:
	LWHI	v0, 0(a0)		# compare words a0 unaligned, a1 aligned
	LWLO	v0, 3(a0)
	lw	v1, 0(a1)
	PTR_ADDU	a0, a0, 4
	bne	v0, v1, nomatch
	PTR_ADDU	a1, a1, 4
	bne	a0, a3, 3b
	nop
smallcmp:
	ble	a2, zero, match
	PTR_ADDU	a3, a2, a0		# compute ending address
1:
	lbu	v0, 0(a0)
	lbu	v1, 0(a1)
	PTR_ADDU	a0, a0, 1
	bne	v0, v1, nomatch
	PTR_ADDU	a1, a1, 1
	bne	a0, a3, 1b
	nop
match:
	j	ra
	 move	v0, zero
nomatch:
	j	ra
	li	v0, 1
END(bcmp)


/*
 * bit = ffs(value)
 */
LEAF(ffs)
	.set	noreorder
	beq	a0, zero, 2f
	move	v0, zero
1:
	and	v1, a0, 1		# bit set?
	addu	v0, v0, 1
	beq	v1, zero, 1b		# no, continue
	srl	a0, a0, 1
2:
	j	ra
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

#endif /* CHERI_KERNEL */
