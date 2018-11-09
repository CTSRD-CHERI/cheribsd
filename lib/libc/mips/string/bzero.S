/*	$NetBSD: bzero.S,v 1.10 2009/12/14 02:53:52 matt Exp $	*/

/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
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
 */
#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
	ASMSTR("from: @(#)bzero.s	8.1 (Berkeley) 6/4/93")
#else
	ASMSTR("$NetBSD: bzero.S,v 1.10 2009/12/14 02:53:52 matt Exp $")
#endif
#endif /* LIBC_SCCS and not lint */

#define _LOCORE		/* XXX not really, just assembly-code source */
#include <machine/endian.h>

#ifdef __ABICALLS__
	.abicalls
#endif

/* bzero(s1, n) */
LEAF(bzero)
	.set	noreorder
#if 1 /* TODO: CPU_QEMU_CHERI. but keep it here to verify that it works even with the nop */
	/* Use the QEMU magic memset nop to speed up emulation: */
	PTR_LI	v0, 0
	PTR_LI	v1, 1	# selector for QEMU magic memset nop
	move	t1, a1	# save a1 since we need to adjust args for memset
	move	a2, a1
	PTR_LI	a1, 0	# memset to zero
	ori	$0, $0, 0xC0DE	# call QEMU magic memset
	/* If the magic nop changed $v1 to 0xdec0ded then we can return */
	beq	v1, 0xdec0ded, .Lbzero_return
	move	a1, t1	# restore a1 in delay slot
.Lmemset_magic_fail:
	beq	v1, 1, .Lbzero_mips_impl # if $v1 is unchanged then the magic memset is not supported
	nop
	/* Not 0xdecoded and not 0x1 -> we failed and the tlb miss handler did not continue at the magic nop! */
	PTR_LA	t9, _C_LABEL(abort)
	jalr	t9
	nop
.Lbzero_mips_impl:
#endif
	blt		a1, 3*SZREG, .Lsmallclr # small amount to clear?
	PTR_SUBU	a3, zero, a0	# compute # bytes to word align address
	and		a3, a3, SZREG-1
	beq		a3, zero, 1f	# skip if word aligned
	PTR_SUBU	a1, a1, a3	# subtract from remaining count
	REG_SHI		zero, 0(a0)	# clear 1-7 bytes to align
	PTR_ADDU	a0, a0, a3
1:
	and		v0, a1, SZREG-1	# compute number of words left
	PTR_SUBU	a3, a1, v0
	move		a1, v0
	PTR_ADDU	a3, a3, a0	# compute ending address
2:
	PTR_ADDU	a0, a0, SZREG	# clear words
	bne		a0, a3, 2b	#  unrolling loop doesn't help
	REG_S		zero, -SZREG(a0) # since we are limited by memory speed
.Lsmallclr:
	ble		a1, zero, .Lbzero_return
	PTR_ADDU	a3, a1, a0	# compute ending address
1:
	PTR_ADDU	a0, a0, 1	# clear bytes
	bne		a0, a3, 1b
	sb		zero, -1(a0)
.Lbzero_return:
	j		ra
	nop
END(bzero)
