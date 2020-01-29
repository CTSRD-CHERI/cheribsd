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

// #define _LOCORE		/* XXX not really, just assembly-code source */
//#include <machine/endian.h>
#include "SYS.h"

#ifdef __ABICALLS__
	.abicalls
#endif

/*
 * memset(void *s1, int c, int len)
 * NetBSD: memset.S,v 1.3 2001/10/16 15:40:53 uch Exp
 */
LEAF(memset)
	.set noreorder
#if 1 /* TODO: CPU_QEMU_CHERI. but keep it here to verify that it works even with the nop */
	/* Use the QEMU magic memset nop to speed up emulation: */
	PTR_LI	v0, 0
	PTR_LI	v1, 1	# selector for QEMU magic memset nop
	ori	$0, $0, 0xC0DE	# call QEMU magic memset
	/* If the magic nop changed $v1 to 0xdec0ded then we can return */
	beq	v1, 0xdec0ded, .Lmemset_return
	nop
.Lmemset_magic_fail:
	beq	v1, 1, .Lmemset_mips_impl # if $v1 is unchanged then the magic memset is not supported
	nop
	/* Not 0xdecoded and not 0x1 -> we failed and the tlb miss handler did not continue at the magic nop! */
	PTR_LA	t9, _C_LABEL(abort)
	jalr	t9
	nop
.Lmemset_mips_impl:
#endif

	blt	a2, 12, .Lmemsetsmallclr	# small amount to clear?
	move	v0, a0			# save s1 for result

	sll	t1, a1, 8		# compute  c << 8 in t1
	or	t1, t1, a1		# compute c << 8 | c in 11
	sll	t2, t1, 16		# shift that left 16
	or	t1, t2, t1		# or together

	PTR_SUBU	t0, zero, a0		# compute # bytes to word align address
	and	t0, t0, 3
	beq	t0, zero, 1f		# skip if word aligned
	PTR_SUBU	a2, a2, t0		# subtract from remaining count
	SWHI	t1, 0(a0)		# store 1, 2, or 3 bytes to align
	PTR_ADDU	a0, a0, t0
1:
	and	v1, a2, 3		# compute number of whole words left
	PTR_SUBU	t0, a2, v1
	PTR_SUBU	a2, a2, t0
	PTR_ADDU	t0, t0, a0		# compute ending address
2:
	PTR_ADDU	a0, a0, 4		# clear words
	bne	a0, t0, 2b		#  unrolling loop does not help
	sw	t1, -4(a0)		#  since we are limited by memory speed

.Lmemsetsmallclr:
	ble	a2, zero, 2f
	PTR_ADDU	t0, a2, a0		# compute ending address
1:
	PTR_ADDU	a0, a0, 1		# clear bytes
	PTR_SUBU	a2, a2, 1		# update len
	bne	a0, t0, 1b
	sb	a1, -1(a0)
2:
.Lmemset_return:
#if defined(CHECK_MEMSET_CLEARED_CORRECTLY)
	/* Check it's all set correctly: */
.Lcheck_all_set:
	ble	a2, zero, .Lmemset_real_return
	nop
1:
	lbu	t0, 0(a0)
	bne	t0, a1, .Lmemset_failed_to_clear
	PTR_SUBU	a2, a2, 1
	ble	a2, zero, .Lmemset_real_return
	PTR_ADDU	a0, a0, 1
	b 1b
	nop
.Lmemset_failed_to_clear:
	PTR_LA a0, memset_wrong_bytes
	PTR_LA t9, _C_LABEL(puts)
	jalr t9
	nop
	PTR_LA t9, _C_LABEL(abort)
	jalr t9
#endif
.Lmemset_real_return:
	jr	ra
	nop
	.set reorder
END(memset)

.rodata
memset_wrong_bytes:
	.asciiz "MEMSET didn't set all bytes!"
