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
# $c17..$c25	Callee-save capabilities
# $c26		IDC
#
# Calling conventions implemented around CCall:
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
	.option pic0
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
	# 2. Produce a value for $idc that bundles these up suitable to
	# bootstrap trestoration.  This will save the original $idc, $csp,
	# and $c0.
	#
	# Then after CReturn, reverse these steps by first unwrapping $idc,
	# and then performing a more normal function return.
	#
	# The caller $idc will describe a stack fragment, which gives us a bit
	# of space to store useful things, such as $csp, that are otherwise
	# quite hard to restore (for obvious reasons).
	#
	# Save callee-save general-purpose registers.
	#
	# Caller-save registers are: $s0..$s7, $gp, $s8 ($fp).
	#
	# NB: Use 96 rather than 88 for the stack to ensure 32-byte alignment
	# for capabilities stored and loaded from it later.
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_save_regs:
	cincoffset	$csp, $csp, -96
	csd	$s0, $zero, 0($csp)
	csd	$s1, $zero, 8($csp)
	csd	$s2, $zero, 16($csp)
	csd	$s3, $zero, 24($csp)
	csd	$s4, $zero, 32($csp)
	csd	$s5, $zero, 40($csp)
	csd	$s6, $zero, 48($csp)
	csd	$s7, $zero, 56($csp)
	csd	$gp, $zero, 64($csp)
	csd	$fp, $zero, 72($csp)
	csd	$ra, $zero, 80($csp)

	#
	# Save capability registers we later need to restore (that won't be
	# handled by CCall for us).
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_save_caps:
	cincoffset	$csp, $csp, -9*CHERICAP_SIZE
	csc	$c17, $zero, 0($csp)
	csc	$c18, $zero, CHERICAP_SIZE($csp)
	csc	$c19, $zero, 2*CHERICAP_SIZE($csp)
	csc	$c20, $zero, 3*CHERICAP_SIZE($csp)
	csc	$c21, $zero, 4*CHERICAP_SIZE($csp)
	csc	$c22, $zero, 5*CHERICAP_SIZE($csp)
	csc	$c23, $zero, 6*CHERICAP_SIZE($csp)
	csc	$c24, $zero, 7*CHERICAP_SIZE($csp)
	csc	$c25, $zero, 8*CHERICAP_SIZE($csp)

	#
	# Prepare $idc to be saved (and restored) by CCall; don't need to seal
	# as CCall will protect its integrity.  No more stack use after this
	# point until $csp is restored.  Move $c0 through $c12 to avoid direct
	# use.  (In contrast to the hybrid ABI, $sp is not saved/restored
	# here.)
	#
cheri_invoke_bundle_idc:
	cincoffset	$csp, $csp, -3*CHERICAP_SIZE
	cgetdefault	$c12
	csc		$c12, $zero, 2*CHERICAP_SIZE($csp)# Default capability
	csc		$csp, $zero, CHERICAP_SIZE($csp)# CHERI stack capability
	csc		$c26, $zero, 0($csp)	# Save original $idc
	dli		$t0, 3*CHERICAP_SIZE
	csetbounds	$c26, $csp, $t0

	#
	# The compiler is responsible for scrubbing unused argument registers
	# (since only it has the information required to do so).  CCall is
	# responsible for scrubbing all other registers.
	#

	#
	# Invoke object capability.  CCall/CReturn will save and restore IDC.
	#
cheri_invoke_ccall:
	ccall	$c1, $c2

	#
	# Restore $idc-saved recovery state; $idc must be restored last.  The
	# stack is usable again after this.  Move $c0 through $c12 to avoid
	# direct use.
	#
cheri_invoke_unbundle_idc:
	clc		$c12, $zero, 2*CHERICAP_SIZE($c26)# Default capability
	csetdefault	$c12
	clc		$csp, $zero, CHERICAP_SIZE($c26) # CHERI stack capability
	clc		$c26, $zero, 0($c26)	# Restore original $idc
	cincoffset	$csp, $csp, 3*CHERICAP_SIZE

	#
	# Restore capability registers from stack.
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
cheri_invoke_restore_caps:
	clc	$c17, $zero, 0($csp)
	clc	$c18, $zero, CHERICAP_SIZE($csp)
	clc	$c19, $zero, 2*CHERICAP_SIZE($csp)
	clc	$c20, $zero, 3*CHERICAP_SIZE($csp)
	clc	$c21, $zero, 4*CHERICAP_SIZE($csp)
	clc	$c22, $zero, 5*CHERICAP_SIZE($csp)
	clc	$c23, $zero, 6*CHERICAP_SIZE($csp)
	clc	$c24, $zero, 7*CHERICAP_SIZE($csp)
	clc	$c25, $zero, 8*CHERICAP_SIZE($csp)
	bnez	$a0, set_cheri_errno
	cincoffset	$csp, $csp, 9*CHERICAP_SIZE

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
	cld	$s0, $zero, 0($csp)
	cld	$s1, $zero, 8($csp)
	cld	$s2, $zero, 16($csp)
	cld	$s3, $zero, 24($csp)
	cld	$s4, $zero, 32($csp)
	cld	$s5, $zero, 40($csp)
	cld	$s6, $zero, 48($csp)
	cld	$s7, $zero, 56($csp)
	cld	$gp, $zero, 64($csp)
	cld	$fp, $zero, 72($csp)
	cld	$ra, $zero, 80($csp)
	cincoffset	$csp, $csp, 96

	#
	# Return to C-language caller.
	#
cheri_invoke_return:
	cjr	$c17
	nop				# Branch-delay slot

set_cheri_errno:
	#
	# Get the address of the thread-local cherierrno variable.
	#
#ifdef HAVE_WORKING_TLS
	lui	$at, %tprel_hi(cherierrno)
	.set	push
	.set	mips32r2
	rdhwr	$t0, $29
	.set	pop
	daddiu	$at, $at, %tprel_lo(cherierrno)
	daddu	$at, $t0, $at
	b	cheri_invoke_restore_regs
	sw	$a0, 0($at)

	.end	cheri_invoke

#else
	#
	# We currently don't have working TLS inside sandboxes, so set a global.
	#
	dla	$a2, cherierrno
	b	cheri_invoke_restore_regs
	csw	$a0, $a2, 0($c0)
	.end	cheri_invoke
#endif

	.type	cherierrno,@object      # @cherierrno
#ifdef HAVE_WORKING_TLS
	.section	.tbss,"awT",@nobits
#endif
	.globl	cherierrno
	.align	2
cherierrno:
	.4byte	0
	.size	cherierrno, 4
