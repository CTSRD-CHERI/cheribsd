/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <machine/asm.h>
#include <machine/cheriasm.h>

#include <cheri/cherireg.h>

.set noat
.set noreorder

#ifdef __KERN_FUNC_PREFIX
#define	FUNC_PREFIX(f)	kern_ ## f
#else
#define	FUNC_PREFIX(f)	f
#endif

/*
 * Implement CHERI memcpy() and bcopy() variants in assembly; C works fine in
 * the kernel most of the time, but copyincap() and copyoutcap() require
 * that no callee-save registers be trampled over due to fault-based error
 * handling.
 *
 * This version handles both aligned and unaligned access.
 * This version also handles overlapping copies.
 * All entry points except the "nocap" ones preserve tags if the pointers
 * are equally aligned mod CHERICAP_SIZE.
 *
 * bcopy versions accepts:
 * c3 - source pointer
 * c4 - destination pointer
 * a0 - length
 *
 * memcpy has inverted source/destination pointers and returns dest.
 */
LEAF(FUNC_PREFIX(memcpy_c))
XLEAF(FUNC_PREFIX(memmove_c))
	cmove	$c1, $c3
	cmove	$c3, $c4
	cmove	$c4, $c1
	b FUNC_PREFIX(bcopy_c)		/* skip stripping LOAD_CAP */
	nop
XLEAF(FUNC_PREFIX(memcpynocap_c))
XLEAF(FUNC_PREFIX(memmovenocap_c))
	cmove	$c1, $c3
	cmove	$c3, $c4
	cmove	$c4, $c1
XLEAF(FUNC_PREFIX(bcopynocap_c))
	beqz		a0, .L.return	/* return immediately if zero-length */
	li	t0, ~CHERI_PERM_LOAD_CAP
	candperm	$c3, $c3, t0	/* strip LOAD_CAP from dst */
XLEAF(FUNC_PREFIX(bcopy_c))
	beqz		a0, .L.return	/* return immediately if zero-length */
	cltu		t0, $c3, $c4	/* forward or backward copy? */
#ifdef INVARIANTS
	csetbounds	$c3, $c3, a0
	csetbounds	$c4, $c4, a0
	li		t8, ~(CHERI_PERM_STORE_CAP|CHERI_PERM_STORE)
	candperm	$c3, $c3, t8
	li		t8, ~(CHERI_PERM_LOAD_CAP|CHERI_PERM_LOAD)
	candperm	$c4, $c4,t8
#endif
	bnez		t0, .L.backward

.L.forward:
	cgetbase	t0, $c3
	cgetoffset	t8, $c3
	daddu		t0, t0, t8	// t0: src virtual address
	cgetbase	t1, $c4
	cgetoffset	t8, $c4
	daddu		t1, t1, t8	// t1: dst virtual address

.L.f_byte_copy:
	/*
	 * Two pointers of unknown alignment.  If they have the same
	 * alignment mod double-word size we copy up to the next dword
	 * boundry.  If not, then we copy the whole lot one byte at a
	 * time.
	 */
	andi		t2, t0, (SZREG-1)
	andi		t3, t1, (SZREG-1)
	bne		t2, t3, .L.f_cannot_be_word_aligned
	move		a1, a0		// a1: how much to copy
	li		t9, SZREG	// enough bytes to copy for a word aligned copy?
	dsub		t8, t9, t2
	daddu		t9, t9, t8
	slt		t9, a0, t9
	bnez		t9, .L.f_cannot_be_word_aligned
.L.f_can_be_word_aligned:
	andi		t8, t0, (SZREG-1)
	li		t9, SZREG
	beqz		t8, .L.f_dword_copy	// already aligned (common)
	dsub		t8, t9, t8
	slt		t9, t8, a1		// Make sure we have this much
	movn		a1, t8, t9
.L.f_cannot_be_word_aligned:
	li		a2, 1		// a2: how much we will have copied
.L.f_byte_loop:
	clb		t9, a2, -1($c3)
	csb		t9, a2, -1($c4)
	bne		a1, a2, .L.f_byte_loop
	daddi		a2, 1

	daddu		t0, t0, a1	// update virtual addresses
	daddu		t1, t1, a1
	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dsub		a0, a0, a1	// update amount to copy
	beqz		a0, .L.return	// exit if done

.L.f_dword_copy:
	/*
	 * Two word aligned pointers.  If they have the same
	 * alignment mod capability size, we copy up to capability
	 * alignment.  Otherwise we copy up to any tail.
	 *
	 * XXX: if dest disallows capability stores we should copy all...
	 */
	andi		t2, t0, (CHERICAP_SIZE - 1)
	andi		t3, t1, (CHERICAP_SIZE - 1)
	and		a1, a0, -SZREG	// a1: amount we could copy
	bne		t2, t3, .L.f_cannot_be_cap_aligned
	li		t9, CHERICAP_SIZE // enough bytes to copy for a cap aligned copy?
	dsub		t9, t9, t2
	slt		t9, a0, t9
	bnez		t9, .L.f_cannot_be_cap_aligned
.L.f_can_be_cap_aligned:
	andi		t8, t0, (CHERICAP_SIZE - 1)	// just to capability
	li		t9, CHERICAP_SIZE
	beqz		t8, .L.f_cap_copy	// already aligned (common)
	dsub		t8, t9, t8
	slt		t9, t8, a1
	movn		a1, t8, t9
.L.f_cannot_be_cap_aligned:
	beqz		a1, .L.f_copy_tail	// No words to copy and not alignable
	li		a2, SZREG	// a2: how much we will have copied
.L.f_dword_loop:
	cld		t9, a2, -SZREG($c3)
	csd		t9, a2, -SZREG($c4)
	bne		a1, a2, .L.f_dword_loop
	daddi		a2, SZREG

	daddu		t0, t0, a1	// update virtual addresses
	daddu		t1, t1, t1
	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dsub		a0, a0, a1	// update amount to copy
	beqz		a0, .L.return	// exit if done

.L.f_cap_copy:
	/*
	 * Two capability aligned pointers.  Copy up to any odd trailer.
	 */
	slti		t9, a0, CHERICAP_SIZE
	and		a1, a0, -CHERICAP_SIZE	// mask off trailer
	bnez		t9, .L.f_copy_tail
	nop
	li		a2, CHERICAP_SIZE // a2: how much we will have copied
.L.f_cap_loop:
	/* XXX: ISA says offset if <<4, but -1 is rejected by llvm... */
	clc		$c2, a2, -CHERICAP_SIZE($c3)
	csc		$c2, a2, -CHERICAP_SIZE($c4)
	bne		a1, a2, .L.f_cap_loop
	daddi		a2, CHERICAP_SIZE

	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dsub		a0, a0, a1	// update amount to copy
	beqz		a0, .L.return	// exit if done

.L.f_copy_tail:
	li		a2, 1		// a2: how much we will have copied
.L.f_tail_loop:
	clb		t9, a2, -1($c3)
	csb		t9, a2, -1($c4)
	bne		a0, a2, .L.f_tail_loop
	daddi		a2, 1

	b .L.return
	nop

.L.backward:
	cincoffset	$c3, $c3, a0	// Move to the end
	cincoffset	$c4, $c4, a0
	cgetbase	t0, $c3
	cgetoffset	t8, $c3
	daddu		t0, t0, t8	// t0: src virtual address (end)
	cgetbase	t1, $c4
	cgetoffset	t8, $c4
	daddu		t1, t1, t8	// t1: dst virtual address (end)

.L.b_byte_copy:
	/*
	 * Two pointers at the end of regions of unknown alignment.
	 * If they share the same alignment mod double-word size, copy
	 * backwards one byte at a time to the next double-word boundary.
	 */
	andi		t2, t0, (SZREG-1)
	andi		t3, t1, (SZREG-1)
	li		t9, SZREG	// enough bytes to copy for a word aligned copy?
	daddu		t9, t2, t9
	slt		t9, a0, t9
	bnez		t9, .L.b_cannot_be_dword_aligned
	move		a1, a0		// a1: how much to copy
	bne		t2, t3, .L.b_cannot_be_dword_aligned
.L.b_can_be_dword_aligned:
	andi		t8, t0, (SZREG-1)	// a1: just to align
	beqz		t8, .L.b_dword_copy	// tail is dword aligned
	slt		t9, t8, a1		// is there space?
	movn		a1, t8, t9
.L.b_cannot_be_dword_aligned:
	dsub		a1, zero, a1	// End (negative) offset
	li		a2, -1		// a2: offset we will have copy
	li		a3, -1		// a3: increment
.L.b_byte_loop:
	clb		t9, a2, 0($c3)
	csb		t9, a2, 0($c4)
	bne		a1, a2, .L.b_byte_loop
	daddu		a2, a2, a3

	dadd		t0, t0, a1	// update virtual addresses
	dadd		t1, t1, a1
	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dadd		a0, a0, a1	// update amount to copy
	beqz		a0, .L.return	// exit if done

.L.b_dword_copy:
	/*
	 * Check if we have enough data to use the dword copy.
	 */
	li		a2, SZREG	// a2: size of double-word
	slt		t9, a0, a2	// Check if we have data for a dword
	bnez		t9, .L.b_copy_head

	/*
	 * Two pointers at the end of the un-copied regions with double
	 * word alignment.  If they have the same alignment mod
	 * capability size, we copy down to capability alignment.
	 * Otherwise we copy up to any header.
	 *
	 * XXX: if dest disallows capability stores we should copy all...
	 */
	andi		t2, t0, (CHERICAP_SIZE - 1)
	andi		t3, t1, (CHERICAP_SIZE - 1)
	and		a1, a0, -SZREG	// a1: mask off header
	bne		t2, t3, .L.b_cannot_be_cap_aligned
	li		t9, CHERICAP_SIZE	// enough bytes to copy for a cap aligned copy?
	daddu		t9, t9, t2
	slt		t9, a0, t9
	bnez		t9, .L.b_cannot_be_cap_aligned
.L.b_can_be_cap_aligned:
	andi		t8, t0, (CHERICAP_SIZE - 1)	// just to capability
	beqz		t8, .L.b_cap_copy	// already aligned (common)
	slt		t9, t8, a1		// is there space?
	movn		a1, t8, t9
.L.b_cannot_be_cap_aligned:
	dsub		a1, zero, a1	// End (negative) offset
	li		a2, -SZREG	// a2: offset we will copy
	li		a3, -SZREG	// a3: increment
.L.b_dword_loop:
	cld		t9, a2, 0($c3)
	csd		t9, a2, 0($c4)
	bne		a1, a2, .L.b_dword_loop
	daddu		a2, a2, a3

	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dadd		a0, a0, a1	// update amount to copy
	beqz		a0, .L.return	// exit if done

.L.b_cap_copy:
	/*
	 * Two capability aligned pointers to the end of the buffers.
	 * Copy down the any unaligned header.
	 */
	li		a2, -CHERICAP_SIZE	// a2: offset we will copy
	and		a1, a0, a2		// a1: amount we could copy
	slt		t9, a0, CHERICAP_SIZE
	bnez		t9, .L.b_copy_head
	li		a3, -CHERICAP_SIZE	// a3: incremnt
	dsub		a1, zero, a1	// a1: end offset (negative)
.L.b_cap_loop:
	clc		$c2, a2, 0($c3)
	csc		$c2, a2, 0($c4)
	bne		a1, a2, .L.b_cap_loop
	daddu		a2, a2, a3

	cincoffset	$c3, $c3, a1	// update capability offsets
	cincoffset	$c4, $c4, a1
	dadd		a0, a0, a1	// update amount to copy

.L.b_copy_head:
	beqz		a0, .L.return
	dsub		a1, zero, a0	// a1: offset to copy to
	li		a2, -1		// a2: offset we will copy
	li		a3, -1		// a3: increment
.L.b_head_loop:
	clb		t9, a2, 0($c3)
	csb		t9, a2, 0($c4)
	bne		a1, a2, .L.b_head_loop
	dadd		a2, a2, a3

.L.return:
#ifndef __CHERI_PURE_CAPABILITY__
	jr	ra
#else
	cjr     $c17
#endif
	cmove	$c3, $c1	/* need to return original c3 for memcpy */
XEND(FUNC_PREFIX(bcopy_c))
XEND(FUNC_PREFIX(bcopynocap_c))
XEND(FUNC_PREFIX(memmovenocap_c))
XEND(FUNC_PREFIX(memcpynocap_c))
XEND(FUNC_PREFIX(memmove_c))
END(FUNC_PREFIX(memcpy_c))

// CHERI CHANGES START
// {
//   "updated": 20190517,
//   "target_type": "kernel",
//   "changes_purecap": [
//	"support"
//   ]
// }
// CHERI CHANGES END
