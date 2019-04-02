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
#define _CHERI_INTERNAL
#include <machine/cheriasm.h>

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
# Calling conventions into libcheri_invoke:
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
	.option pic0
	.global libcheri_invoke
	.global cheri_invoke
	.ent	libcheri_invoke
libcheri_invoke:
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
	# and $ddc.
	#
	# Then after CReturn, reverse these steps by first unwrapping $idc,
	# and then performing a more normal function return.
	#
	# The caller $csp will describe a stack fragment, which gives us a bit
	# of space to store useful things that are otherwise hard to restore.
	#
	# NB: This is no longer required for the pure-capability ABI.
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
libcheri_invoke_save_regs:
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
libcheri_invoke_save_caps:
	cgetdefault	$c12
	cincoffset	$csp, $csp, -11*CHERICAP_SIZE
	csc	$c17, $zero, 0($csp)
	csc	$c18, $zero, CHERICAP_SIZE($csp)
	csc	$c19, $zero, 2*CHERICAP_SIZE($csp)
	csc	$c20, $zero, 3*CHERICAP_SIZE($csp)
	csc	$c21, $zero, 4*CHERICAP_SIZE($csp)
	csc	$c22, $zero, 5*CHERICAP_SIZE($csp)
	csc	$c23, $zero, 6*CHERICAP_SIZE($csp)
	csc	$c24, $zero, 7*CHERICAP_SIZE($csp)
	csc	$c25, $zero, 8*CHERICAP_SIZE($csp)
	csc	$c26, $zero, 9*CHERICAP_SIZE($csp)
	csc	$c12, $zero, 10*CHERICAP_SIZE($csp)

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
	dla		$t0, libcheri_invoke_ccall_linkaddr
	cgetpcc		$c17
	csetoffset	$c17, $c17, $t0

	#
	# Invoke object capability.  CCall/CReturn will save and restore $csp.
	#
libcheri_invoke_ccall:
	CCALL($c1, $c2)
libcheri_invoke_ccall_linkaddr:

	#
	# Restore capability registers from stack.
	#
libcheri_invoke_restore_caps:
	clc	$c17, $zero, 0($csp)
	clc	$c18, $zero, CHERICAP_SIZE($csp)
	clc	$c19, $zero, 2*CHERICAP_SIZE($csp)
	clc	$c20, $zero, 3*CHERICAP_SIZE($csp)
	clc	$c21, $zero, 4*CHERICAP_SIZE($csp)
	clc	$c22, $zero, 5*CHERICAP_SIZE($csp)
	clc	$c23, $zero, 6*CHERICAP_SIZE($csp)
	clc	$c24, $zero, 7*CHERICAP_SIZE($csp)
	clc	$c25, $zero, 8*CHERICAP_SIZE($csp)
	clc	$c26, $zero, 9*CHERICAP_SIZE($csp)
	clc	$c12, $zero, 10*CHERICAP_SIZE($csp)
	csetdefault	$c12

libcheri_invoke_set_errno:
	bnez	$a0, libcheri_set_errno
	cincoffset	$csp, $csp, 11*CHERICAP_SIZE	# Branch-delay slot

	#
	# CCall has conservatively cleared all non-return-value registers, and
	# so we don't need to.

	#
	# Restore general-purpose registers from the stack.
	#
	# XXXRW: Possibly with the __ccall calling convention, the compiler
	# should be doing this?
	#
libcheri_invoke_restore_regs:
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
libcheri_invoke_return:
	cjr	$c17
	nop				# Branch-delay slot

libcheri_set_errno:
	#
	# Get the address of the thread-local libcheri_errno variable.
	#
#ifdef HAVE_WORKING_TLS
#ifdef __CHERI_CAPABILITY_TLS__
	/* Note: initial-exec since we don't have captable pointer */
	lui	$at, %tprel_hi(__libcheri_stack_tls_storage)
	daddiu	$at, $at, %tprel_lo(__libcheri_stack_tls_storage)
	creadhwr $c3, $chwr_userlocal
#else
	/* Legacy: we need a valid $ddc here */
	lui	$at, %tprel_hi(libcheri_errno)
	.set	push
	.set	mips32r2
	rdhwr	$t0, $29
	.set	pop
	daddiu	$at, $at, %tprel_lo(libcheri_errno)
	daddu	$at, $t0, $at
	cgetdefault $c3
#endif
	b	libcheri_invoke_restore_regs
	csw	$a0, $at, 0($c3)
#else
#ifdef __CHERI_CAPABILITY_TABLE__
#error "This code will not work with a captable since $ddc is null"
#endif
	#
	# We currently don't have working TLS inside sandboxes, so set a global.
	#
	dla	$a2, libcheri_errno
	b	libcheri_invoke_restore_regs
	csw	$a0, $a2, 0($ddc)
#endif
	teq $zero, $zero
	.end	libcheri_invoke
	# Also add size information for cheri_invoke to avoid linker warnings
.L.cheri_invoke.end:
	.size cheri_invoke, .L.cheri_invoke.end - cheri_invoke


	.type	libcheri_errno,@object      # @libcheri_errno
#ifdef HAVE_WORKING_TLS
	.section	.tbss,"awT",@nobits
#endif
	.globl	libcheri_errno
	.align	2
libcheri_errno:
	.4byte	0
	.size	libcheri_errno, 4
