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
#include "abicall.s"

#.set mips64
.set noreorder
#.set nobopt
.set noat

#
# CHERI sandbox run-time linker entry point, used for constructors and
# destructors.  Identical calling convention to that described in
# crt_invoke.S -- please see the comments there.
#
# Most code borrowed from crt_invoke.S; notice that exit/abort symbols here
# are not global, and that there is no path to invoke().
#

# XXXAR: LLD linker script output section assignment appears to be broken
# right now. It just assigns the input section name to the output section.
# To work around this we just give it the name of the output section that we want
# 	.text
	.section rtld_vector_text,"ax",@progbits
	.option pic0
	.global __rtld_vector
	.type __rtld_vector,@function
	.ent __rtld_vector
__rtld_vector:

	#
	# Load $idc-relative offset of the Sandbox Metadata (SBM) area
	#
	dli	$t0, 0x1000

	#
	# The compiler is responsible for scrubbing unused argument registers
	# (since only it has the information required to do so).  CCall is
	# responsible for scrubbing all other registers.
	#

	#
	# Set up global pointer.
	#
	# XXXRW: Should this now be setting $cgp?
	#
	dla	$gp, _gp

	#
	# Method switch for the run-time linker vector.
	#
	dli	$at, -1
	beq	$v0, $at, constructors
	nop

	# dli	$at, 2
	# beq	$v0, $at, destructors
	# nop

	#
	# No matching function; return (-1).
	#
	cfromptr	$c3, $c3, $zero
	dli	$v0, -1
	dli	$v1, 0

creturn_target:
	#
	# The compiler is responsible for scrubbing unused return-value
	# registers (since only it has the information required to do so).
	# CReturn is responsible for scrubbing all other registers.
	#

	#
	# Return to caller -- load sbm_creturn_object.{co_code, co_data} into
	# $c1 and $c2, and ccall into the creturn trampoline.
	#
	# XXXRW: Do we need to CGetDefault to load the right $c26 here?
	#
	cgetdefault	$c26
	dli	$t0, 0x1000
	clc	$c1, $t0, 32 + 4*CHERICAP_SIZE($c26)
	clc	$c2, $t0, 32 + 5*CHERICAP_SIZE($c26)
	CCALL($c1, $c2)

constructors:
	#
	# Extract heap base, heap length, and CHERI system object reference
	# from sandbox metadata.  These must match sandboxasm.h.
	#
	# XXXRW: I'm having trouble using the C preprocessor to provide these
	# values in assembly, so hard-coded for now.  We could also just defer
	# these calculations to C.
	#
	ld	$t1, 0($t0)
	dla	$t2, _sb_heapbase;
	sd	$t1, 0($t2)

	ld	$t1, 8($t0)
	dla	$t2, _sb_heaplen;
	sd	$t1, 0($t2)

	# Code capability
	clc	$c12, $t0, 32($c26)
	dla	$t2, _libcheri_system_object;
	csc	$c12, $t2, 0($c26)

	# Data capability
	clc	$c12, $t0, 32+CHERICAP_SIZE($c26)
	dla	$t2, _libcheri_system_object;
	csc	$c12, $t2, CHERICAP_SIZE($c26)

	#
	# Perform global capability and constructor initialisation from C; the
	# C code must be very careful not to depend on the outcome of any
	# constructors!  Here, as above, set $v0 to indicate success, and scrub
	# $v1/$c3 before returning.
	#
	dla	$t9, crt_sandbox_init
	abicall	$t9

	#
	# Return with $v0 set to '0'; $v1 and $c3 scrubbed.
	#
	cfromptr	$c3, $c3, $zero
	dli	$v0, 0
	b	creturn_target
	dli	$v1, 0		# Branch-delay slot
	.end __rtld_vector

	.data
