#-
# Copyright (c) 2012-2017 Robert N. M. Watson
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#include <machine/cherireg.h>

#.set mips64
.set noreorder
#.set nobopt
.set noat

#
# Assembly wrapper for CCall on an object-capability.  Its function is to save
# and restore any general-purpose and capability registers needed on either
# side of CCall, but not handled by the compiler.  This is done by creating an
# on-stack frame which will be pointed to by $idc before CCall, and then
# unwrapping it again.  We rely on the compiler and CCall to sort out clearing
# of registers that require it, since they have the information to do so.
#
# Calling conventions into cheri_invoke:
#
# Registers	Description
# $c0		MIPS address space
# $c1, $c2	Invoked capabilities
# $c3..$c10	Argument capabilities
# $c11..$c16	Caller-save capabilities
# $c17..$c26	Callee-save capabilities
#
# Calling conventions implemented by CCall:
#
# $c1		Invoked code capability
# $c2		Invoked data capability
# $c3..$c10	Argument capabilities; $c3 as return capability
# $c11..$c16	n/a
# $c17..$c25	n/a
# $c26		IDC
#
# XXXRW: Worries/TODO:
#
# - Floating-point registers.
# - The compiler needs to handle unused argument/return registers.
#

	.text
	.global cheri_invoke
	.ent	cheri_invoke
cheri_invoke:

	#
	# Wrap up all caller-save state suitable to be preseved by CCall and
	# restored by CReturn.  This happens in two phases:
	#
	# 1. First, use the conventional stack to save as many caller-save
	# general-purpose and capability registers as possible.
	#
	# 2. Produce a value for $csp that bundles these up suitable to
	# bootstrap restoration.  This will save the original $idc, $csp,
	# $sp, and $ddc.
	#
	# Then after CReturn, reverse these steps by first unwrapping $idc,
	# and then performing a more normal function return.
	#
	# The caller $csp will describe a stack fragment, which gives us a bit
	# of space to store useful things, such as $sp, that are otherwise
	# quite hard to restore (for obvious reasons).
	#
	# NB: This is still required for the hybrid ABI, unlike the
	# pure-capability ABI, because we need to save and restore $sp.
	#
	# Save callee-save general-purpose registers.
	#
	# Caller-save registers are: $s0..$s7, $gp, $sp, $s8 ($fp).
	#
	# Do also save $ra so that we can return properly.
	#
	# NB: Use 96 rather than 88 for the stack to ensure 32-byte alignment
	# for capabilities stored and loaded from it later.
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_save_regs:
	daddiu	$sp, -96
	sd	$s0, 0($sp)
	sd	$s1, 8($sp)
	sd	$s2, 16($sp)
	sd	$s3, 24($sp)
	sd	$s4, 32($sp)
	sd	$s5, 40($sp)
	sd	$s6, 48($sp)
	sd	$s7, 56($sp)
	sd	$gp, 64($sp)
	sd	$fp, 72($sp)
	sd	$ra, 80($sp)
	sd	$t9, 88($sp)

	#
	# Save capability registers we later need to restore (that won't be
	# handled by CCall for us).
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_save_caps:
	daddiu	$sp, -10*CHERICAP_SIZE
	csc	$c17, $sp, 0($c11)
	csc	$c18, $sp, CHERICAP_SIZE($c11)
	csc	$c19, $sp, 2*CHERICAP_SIZE($c11)
	csc	$c20, $sp, 3*CHERICAP_SIZE($c11)
	csc	$c21, $sp, 4*CHERICAP_SIZE($c11)
	csc	$c22, $sp, 5*CHERICAP_SIZE($c11)
	csc	$c23, $sp, 6*CHERICAP_SIZE($c11)
	csc	$c24, $sp, 7*CHERICAP_SIZE($c11)
	csc	$c25, $sp, 8*CHERICAP_SIZE($c11)
	csc	$c26, $sp, 9*CHERICAP_SIZE($c11)

	#
	# Prepare $c11 to be saved (and restored) by CCall; don't need to seal
	# as CCall will protect its integrity.  No more stack use after this
	# point until $c11 and $sp are restored.  Move $c0 through $c12 to
	# avoid direct use.
	#
cheri_invoke_bundle_idc:
	cgetdefault	$c12
	daddiu		$sp, -3*CHERICAP_SIZE
	csd		$sp, $sp, 2*CHERICAP_SIZE($c11)	  # MIPS stack pointer
	csc		$c12, $sp, 1*CHERICAP_SIZE($c11)  # Default cap.
	csc		$c11, $sp, 0*CHERICAP_SIZE($c11)  # CHERI stack cap.
	cfromptr	$c11, $c11, $sp
	csetbounds	$c11, $c11, 3*CHERICAP_SIZE

	#
	# The compiler is responsible for scrubbing unused argument registers
	# (since only it has the information required to do so).  CCall is
	# responsible for scrubbing all other registers.
	#

	#
	# Construct link-address PCC.
	#
	# XXXRW: Do we want a CCall variant like CJALR that automatically
	# builds the desired capability?
	#
	dla		$t0, cheri_invoke_ccall_linkaddr
	cgetpcc		$c17
	csetoffset	$c17, $c17, $t0

	#
	# Invoke object capability.  CCall/CReturn will save and restore $csp.
	#
cheri_invoke_ccall:
	ccall	$c1, $c2, 1
	nop
cheri_invoke_ccall_linkaddr:

	#
	# Restore $idc-saved recovery state; $idc must be restored last.  The
	# stack is usable again after this.  Move $c0 through $c12 to avoid
	# direct use.
	#
cheri_invoke_unbundle_idc:
	cld		$sp, $zero, 2*CHERICAP_SIZE($c11) # MIPS stack pointer
	clc		$c12, $zero, 1*CHERICAP_SIZE($c11)# Default cap.
	clc		$c11, $zero, 0*CHERICAP_SIZE($c11)# CHERI stack cap.
	daddiu		$sp, 3*CHERICAP_SIZE
	csetdefault	$c12

	#
	# Restore capability registers from stack.
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_restore_caps:
	clc	$c17, $sp, 0($c11)
	clc	$c18, $sp, CHERICAP_SIZE($c11)
	clc	$c19, $sp, 2*CHERICAP_SIZE($c11)
	clc	$c20, $sp, 3*CHERICAP_SIZE($c11)
	clc	$c21, $sp, 4*CHERICAP_SIZE($c11)
	clc	$c22, $sp, 5*CHERICAP_SIZE($c11)
	clc	$c23, $sp, 6*CHERICAP_SIZE($c11)
	clc	$c24, $sp, 7*CHERICAP_SIZE($c11)
	clc	$c25, $sp, 8*CHERICAP_SIZE($c11)
	clc	$c26, $sp, 9*CHERICAP_SIZE($c11)
	bnez	$a0, set_cheri_errno
	daddiu	$sp, 10*CHERICAP_SIZE

	#
	# CCall has conservatively cleared all non-return-value registers, and
	# so we don't need to.

	#
	# Restore general-purpose registers from the stack.
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_restore_regs:
	ld	$s0, 0($sp)
	ld	$s1, 8($sp)
	ld	$s2, 16($sp)
	ld	$s3, 24($sp)
	ld	$s4, 32($sp)
	ld	$s5, 40($sp)
	ld	$s6, 48($sp)
	ld	$s7, 56($sp)
	ld	$gp, 64($sp)
	ld	$fp, 72($sp)
	ld	$ra, 80($sp)
	daddiu	$sp, 96

	#
	# Return to C-language caller.
	#
cheri_invoke_return:
	jr	$ra
	nop				# Branch-delay slot

set_cheri_errno:
#ifndef __PIC__
	lui     $at, %tprel_hi(cherierrno)
	.set    push
	.set    mips32r2
	rdhwr   $t0, $29
	.set    pop
	daddiu  $at, $at, %tprel_lo(cherierrno)
	daddu   $at, $t0, $at
	sw      $a0, 0($at)
#else
	ld	$t9, 88($sp)
	sd	$a0, 88($sp)
	#
	# Set up $gp.
	#
	lui	$at, %hi(%neg(%gp_rel(cheri_invoke)))
	daddu	$at, $at, $t9
	daddiu	$gp, $at, %lo(%neg(%gp_rel(cheri_invoke)))
	#
	# Get the address of the thread-local cherierrno variable.
	#
	lui	$at, %call_hi(__tls_get_addr)
	daddu	$at, $at, $gp
	ld	$t9, %call_lo(__tls_get_addr)($at)
	jalr	$t9
	daddiu	$a0, $gp, %tlsgd(cherierrno)
	#
	# Store the signal value in cherierrno.
	#
	ld	$a0, 88($sp)
	sw	$a0, 0($v0)
#endif // __PIC__
	#
	# Store the values in v0 / v1 that code that doesn't know about
	# cherierrno might be expecting.
	#
	daddiu	$v0, $zero, -1
	b	cheri_invoke_restore_regs
	move	$v1, $a0

	.end	cheri_invoke

	.type	cherierrno,@object      # @cherierrno
	.section	.tbss,"awT",@nobits
	.globl	cherierrno
	.align	2
cherierrno:
	.4byte	0                       # 0x0
	.size	cherierrno, 4
