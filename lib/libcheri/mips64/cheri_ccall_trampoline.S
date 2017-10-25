#-
# Copyright (c) 2017 Robert N. M. Watson
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

.set noreorder
.set noat

#define	_CHERI_INTERNAL
#include <machine/cheriasm.h>
#include <machine/cherireg.h>

/*
 * Userspace implementation of libcheri invocation and return semantics.
 * These vectors are intended to run on the inside of sealed call and return
 * code capabilities, perform any necessary checks, transform the capability
 * register file, and then jump into the target domain.
 *
 * The design is similar to our earlier prototype based on a dedicated
 * exception handler, in that we rely on hardware acceleration of certain
 * checks, push and pop trusted stack frames, and clear the register file as
 * required.  There are some necessary differences:
 *
 * (1) We enter and end with a jump-like, rather than exception enter/return
 *     semantic.  This means two different code capabilities pointing at the
 *     runtime, selecting call or return semantics.
 * (2) We locate a trusted stack using the ambient environments compiler/
 *     linker-provided thread-local storage (TLS) rather than kernel
 *     per-thread state.
 * (2) Error handling is quite different, as we can't simply jump into the
 *     kernel's exception handler.  Instead we trigger a suitable signal, or
 *     return to the originating context.  (XXXRW: More here?)
 *
 * This code assumes that the architecture validates:
 * - cs and ds accessibility
 * - cs and ds tags
 * - cs and ds seals
 * - cs.otype == ds.otype
 * - cs and ds permissions
 * - cs.offset vs cs.length
 */

/*
 * Implementations of CCall suitable for use within a sealed code capability.
 *
 * The first is used for rtld initialisation and destruction.  The second
 * nearly identical vector is used for general invocation.  We would most
 * ideally share an implementation, varying the target $pcc load based on
 * sealed-capability object type -- but, unfortunately, the current userspace
 * CCall instruction doesn't [yet] provide reliable access to the operand
 * sealed capabilities.
 *
 * XXXRW: This would ideally be fixed.
 *
 * The effective ABI from the caller is as follows:
 *
 * $c1 - Sealed code capability
 * $c2 - Sealed data capability
 * $c11 - Return data capability (to be saved for later return)
 * $c17 - Return code capability (to be saved for later return)
 *
 * Guarantees from the archicture are as follows:
 *
 * $pcc - Unsealed code capability for this domain-transition routine
 * $c26 - Unsealed data capability describing the target object (IDC)
 *
 * XXXRW: Currently, it appears to be difficult for us to check that $c1 and
 * $c2 were used, since we are assured only inbound unsealed capabilities in
 * $pcc and $idc.  Ideally we could check they were used, and throw an
 * exception if not, so that we could rely on sealed versions being present.
 *
 * Local register use key:
 * $c12		Target $pcc to jump to in the destination object.
 * $c14		Earlier: trusted stack.  Later: trusted stack frame.
 * $c17		Earlier: return code capability.  Later: target $pcc.
 * $c26		IDC as provided by CCall -- pointer to object description.
 *
 * XXXRW: Quite a bit of work left to do here, as both register clearing and
 * capability flow control are unimplemented.
 *
 * XXXRW: Some careful thinking about signal handlers and atomicity is still
 * required here.  Machine-dependent trusted-stack unwind code may need to
 * recognise when the interrupted $pcc falls during invocation or return, and
 * "pick" one side or the other [accurately].  Fortunately, we have one
 * particular store that "commits" the transition: the in-place update of the
 * trusted stack pointer.
 */
	.text
	.global	libcheri_ccall_rtld_vector
	.ent	libcheri_ccall_rtld_vector
libcheri_ccall_rtld_vector:

libcheri_ccall_rtld_validate_args:
	/* XXXRW: NOT YET */

libcheri_ccall_rtld_check_globals:
	/* XXXRW: NOT YET */

	/*
	 * We are now committed to performing a protection-domain switch.  IDC
	 * points at the sandbox_object, from which we must retrieve any
	 * necessary capabilities to reach the trusted stack, etc.
	 *
	 * Use thread-local storage to retrieve the trusted stack for the
	 * current pthread.  Load TLS data relative to sbo_libcheri_tls
	 * (referring to the ambient portion of the process).  Prepare $c14
	 * for use in pointing at the trusted-stack container structure.
	 *
	 * XXXRW: Clang appears to generate roughly this code across multiple
	 * ABIs and regardless of -fpic/-fno-pic, if -mno-abicalls is used.
	 * So, go with this in all cases, but much testing definitely
	 * required -- e.g., once we have dynamically linked pure-capability
	 * binaries using.
	 */
	lui     $at, %tprel_hi(__cheri_stack_tls_storage)
	.set	push
	.set	mips32r2
	rdhwr	$t0, $29
	.set	pop
	daddiu	$at, $at, %tprel_lo(__cheri_stack_tls_storage)
	daddu	$at, $t0, $at
	clc		$c14, $zero, (5*CHERICAP_SIZE)($c26)
	csetoffset	$c14, $c14, $at

libcheri_ccall_rtld_push_stack:
	/* Retrieve current trusted stack pointer. */
	cld	$t0, $zero, 0($c14)		# XXXRW: Hard-coded offset

	/* If at the bottom (byte offset 0), then overflow. */
	beqz	$t0, libcheri_ccall_rtld_stack_overflow

	/* Decrement trusted stack pointer. */
	daddiu	$t0, $t0, -3*CHERICAP_SIZE

	/* Write back trusted stack pointer - cs_tsp. */
	csd	$t0, $zero, 0($c14)		# XXXRW: Hard-coded offset

	/* Calculate $c14-relative offset to stack frame. */
	daddiu	$t0, $t0, 32			# XXXRW: Hard-coded offset

	/* NB: In this model, we don't need to increment the saved $pcc. */

	/* Save caller return $pcc. */
	csc	$c17, $t0, 0($c14)		# XXXRW: Hard-coded offset

	/* Save caller return $csp. */
	csc	$c11, $t0, CHERICAP_SIZE($c14)	# XXXRW: Hard-coded offset

	/* Save callee sandbox pointer. */
	csc	$c26, $t0, (2*CHERICAP_SIZE)($c14)# XXXRW: Hard-coded offset

	/* XXXRW: Tracing?  Could do utrace, potentially...  Or jump into C? */

libcheri_ccall_rtld_extract_target:
	/*
	 * Retrieve and install the target protection domain's DDC, PCC, and
	 * IDC, which are pointed to by the trampoline's IDC.
	 *
	 * NB: Notice capability offset 1 for rtld initialisation.
	 */
	clc	$c12, $zero, (4*CHERICAP_SIZE)($c26) # XXXRW: Hard-coded offset
	csetdefault	$c12
	clc	$c12, $zero, (1*CHERICAP_SIZE)($c26) # XXXRW: Hard-coded offset
	clc	$c26, $zero, (0*CHERICAP_SIZE)($c26) # XXXRW: Hard-coded offset

libcheri_ccall_rtld_clear_regs:
	CHERI_CLEAR_GPLO16( \
		CHERI_CLEAR_GPLO_AT | \
		CHERI_CLEAR_GPLO_V1 | \
		CHERI_CLEAR_GPLO_T0 | \
		CHERI_CLEAR_GPLO_T1 | \
		CHERI_CLEAR_GPLO_T2 | \
		CHERI_CLEAR_GPLO_T3 )
	CHERI_CLEAR_GPHI16( \
		CHERI_CLEAR_GPHI_S0 | \
		CHERI_CLEAR_GPHI_S1 | \
		CHERI_CLEAR_GPHI_S2 | \
		CHERI_CLEAR_GPHI_S3 | \
		CHERI_CLEAR_GPHI_S4 | \
		CHERI_CLEAR_GPHI_S5 | \
		CHERI_CLEAR_GPHI_S6 | \
		CHERI_CLEAR_GPHI_S7 | \
		CHERI_CLEAR_GPHI_T8 | \
		CHERI_CLEAR_GPHI_T9 | \
		CHERI_CLEAR_GPHI_GP | \
		CHERI_CLEAR_GPHI_SP | \
		CHERI_CLEAR_GPHI_S8 | \
		CHERI_CLEAR_GPHI_RA )
	mtlo	$zero
	mthi	$zero

libcheri_ccall_rtld_clear_fpregs:
	/* XXXRW: Floating-point registers. */

libcheri_ccall_rtld_clear_caps:
	CHERI_CLEAR_CAPLO16( \
		CHERI_CLEAR_CAPLO_C11 | \
		/* CHERI_CLEAR_CAPLO_C12 | */ \
		CHERI_CLEAR_CAPLO_C13 | \
		CHERI_CLEAR_CAPLO_C14 | \
		CHERI_CLEAR_CAPLO_C15 )
	CHERI_CLEAR_CAPHI16( \
		CHERI_CLEAR_CAPHI_C16 | \
		CHERI_CLEAR_CAPHI_C17 | \
		CHERI_CLEAR_CAPHI_C18 | \
		CHERI_CLEAR_CAPHI_C19 | \
		CHERI_CLEAR_CAPHI_C20 | \
		CHERI_CLEAR_CAPHI_C21 | \
		CHERI_CLEAR_CAPHI_C22 | \
		CHERI_CLEAR_CAPHI_C23 | \
		CHERI_CLEAR_CAPHI_C24 | \
		CHERI_CLEAR_CAPHI_C25)

libcheri_ccall_rtld_return:
	cjr	$c12
	nop					# Branch-delay slot

libcheri_ccall_rtld_local_argument:
libcheri_ccall_rtld_stack_overflow:
	/* XXXRW: What do we want to do here?  Just trap for now. */
	teq	$zero, $zero
	.end	libcheri_ccall_rtld_vector

/*
 * Variation on CCall vector suitable for general invocation.
 *
 * XXXRW: This should be identical to the above other than the load offset for
 * the target PCC, and the names of in-function symbols.
 *
 * XXXRW: Ideally, this would be the same code as above, dependent on the
 * object type and a conditional move to load the right value, rather than a
 * separate trampoline.
 */

	.text
	.global	libcheri_ccall_invoke_vector
	.ent	libcheri_ccall_invoke_vector
libcheri_ccall_invoke_vector:

libcheri_ccall_invoke_validate_args:
	/* XXXRW: NOT YET */

libcheri_ccall_invoke_check_globals:
	/* XXXRW: NOT YET */

	/*
	 * We are now committed to performing a protection-domain switch.
	 *
	 * Use thread-local storage to retrieve the trusted stack for the
	 * current pthread.  Load TLS data relative to IDC (referring to the
	 * ambient portion of the process).  Prepare $c14 for use in pointing
	 * at the trusted-stack container structure.
	 *
	 * XXXRW: Clang appears to generate roughly this code across multiple
	 * ABIs and regardless of -fpic/-fno-pic, if -mno-abicalls is used.
	 * So, go with this in all cases, but much testing definitely
	 * required -- e.g., once we have dynamically linked pure-capability
	 * binaries using.
	 */
	lui     $at, %tprel_hi(__cheri_stack_tls_storage)
	.set	push
	.set	mips32r2
	rdhwr	$t0, $29
	.set	pop
	daddiu	$at, $at, %tprel_lo(__cheri_stack_tls_storage)
	daddu	$at, $t0, $at
	clc		$c14, $zero, (5*CHERICAP_SIZE)($c26)
	csetoffset	$c14, $c14, $at

libcheri_ccall_invoke_push_stack:
	/* Retrieve current trusted stack pointer - cs_tsp. */
	cld	$t0, $zero, 0($c14)		# XXXRW: Hard-coded offset

	/* If at the bottom (byte offset 0), then overflow. */
	beqz	$t0, libcheri_ccall_invoke_stack_overflow

	/* Decrement trusted stack pointer. */
	daddiu	$t0, $t0, -3*CHERICAP_SIZE

	/* Write back trusted stack pointer. */
	csd	$t0, $zero, 0($c14)		# XXXRW: Hard-coded offset

	/* Calculate $c14-relative offset to stack frame. */
	daddiu	$t0, $t0, 32			# XXXRW: Hard-coded offset

	/* NB: In this model, we don't need to increment the saved $pcc. */

	/* Save caller return $pcc. */
	csc	$c17, $t0, 0($c14)		# XXXRW: Hard-coded offset

	/* Save caller return $csp. */
	csc	$c11, $t0, CHERICAP_SIZE($c14)	# XXXRW: Hard-coded offset

	/* Save callee sandbox pointer. */
	csc	$c26, $t0, (2*CHERICAP_SIZE)($c14)# XXXRW: Hard-coded offset

	/* XXXRW: Tracing?  Could do utrace, potentially...  Or jump into C? */

libcheri_ccall_invoke_extract_target:
	/*
	 * Retrieve and install the target protection domain's DDC, PCC, and
	 * IDC, which are pointed to by the trampoline's IDC.
	 *
	 * NB: Notice capability offset 2 for general invocation.
	 */
	clc	$c12, $zero, (4*CHERICAP_SIZE)($c26) # XXXRW: Hard-coded offset
	csetdefault	$c12
	clc	$c12, $zero, (2*CHERICAP_SIZE)($c26) # XXXRW: Hard-coded offset
	clc	$c26, $zero, (0*CHERICAP_SIZE)($c26) # XXXRW: Hard-coded offset

libcheri_ccall_invoke_clear_regs:
	CHERI_CLEAR_GPLO16( \
		CHERI_CLEAR_GPLO_AT | \
		CHERI_CLEAR_GPLO_V1 | \
		CHERI_CLEAR_GPLO_T0 | \
		CHERI_CLEAR_GPLO_T1 | \
		CHERI_CLEAR_GPLO_T2 | \
		CHERI_CLEAR_GPLO_T3 )
	CHERI_CLEAR_GPHI16( \
		CHERI_CLEAR_GPHI_S0 | \
		CHERI_CLEAR_GPHI_S1 | \
		CHERI_CLEAR_GPHI_S2 | \
		CHERI_CLEAR_GPHI_S3 | \
		CHERI_CLEAR_GPHI_S4 | \
		CHERI_CLEAR_GPHI_S5 | \
		CHERI_CLEAR_GPHI_S6 | \
		CHERI_CLEAR_GPHI_S7 | \
		CHERI_CLEAR_GPHI_T8 | \
		CHERI_CLEAR_GPHI_T9 | \
		CHERI_CLEAR_GPHI_GP | \
		CHERI_CLEAR_GPHI_SP | \
		CHERI_CLEAR_GPHI_S8 | \
		CHERI_CLEAR_GPHI_RA )
	mtlo	$zero
	mthi	$zero

libcheri_ccall_invoke_clear_fpregs:
	/* XXXRW: Floating-point registers. */

libcheri_ccall_invoke_clear_caps:
	CHERI_CLEAR_CAPLO16( \
		CHERI_CLEAR_CAPLO_C11 | \
		/* CHERI_CLEAR_CAPLO_C12 | */ \
		CHERI_CLEAR_CAPLO_C13 | \
		CHERI_CLEAR_CAPLO_C14 | \
		CHERI_CLEAR_CAPLO_C15 )
	CHERI_CLEAR_CAPHI16( \
		CHERI_CLEAR_CAPHI_C16 | \
		CHERI_CLEAR_CAPHI_C17 | \
		CHERI_CLEAR_CAPHI_C18 | \
		CHERI_CLEAR_CAPHI_C19 | \
		CHERI_CLEAR_CAPHI_C20 | \
		CHERI_CLEAR_CAPHI_C21 | \
		CHERI_CLEAR_CAPHI_C22 | \
		CHERI_CLEAR_CAPHI_C23 | \
		CHERI_CLEAR_CAPHI_C24 | \
		CHERI_CLEAR_CAPHI_C25)

libcheri_ccall_invoke_return:
	cjr	$c12
	nop					# Branch-delay slot

libcheri_ccall_invoke_local_argument:
libcheri_ccall_invoke_stack_overflow:
	/* XXXRW: What do we want to do here?  Just trap for now. */
	teq	$zero, $zero
	.end	libcheri_ccall_invoke_vector

/*
 * Implementation of CCall suitable for use within a sealed code capability --
 * used for CReturn.
 *
 * Local register use key:
 * $c14		Earlier: trusted stack.  Later: trusted stack frame.
 * $c17		Target $pcc to jump back to in the caller destination object.
 * $c26		IDC as provided by CCall -- pointer to object description.
 */
	.global libcheri_creturn_vector
	.ent	libcheri_creturn_vector
libcheri_creturn_vector:

creturn_check_global:
	/* XXXRW: NOT YET */

	/*
	 * We are now committed to performing a protection-domain switch.
	 *
	 * Use thread-local storage to retrieve the trusted stack for the
	 * current pthread.  Load TLS data relative to IDC (referring to the
	 * ambient portion of the process).  Prepare $c14 for use in pointing
	 * at the trusted-stack container structure.
	 *
	 * XXXRW: Read note above on TLS and testing.
	 */
	lui     $at, %tprel_hi(__cheri_stack_tls_storage)
	.set	push
	.set	mips32r2
	rdhwr	$t0, $29
	.set	pop
	daddiu	$at, $at, %tprel_lo(__cheri_stack_tls_storage)
	daddu	$at, $t0, $at
	csetoffset	$c14, $c26, $at

creturn_pop_stack:
	/* Retrieve current trusted stack pointer. */
	cld	$t0, $zero, 0($c14)		# XXXRW: Hard-coded offset

	/* Retrieve size of trusted stack. */
	cld	$t1, $zero, 8($c14)		# XXXRW: Hard-coded offset

	beq	$t0, $t1, creturn_stack_underflow
	nop

	/* Increment (copy of) trusted stack pointer - cs_tsp. */
	daddiu	$t1, $t0, 3*CHERICAP_SIZE

	/* Write back incremented trusted stack pointer. */
	csd	$t1, $zero, 0($c14)		# XXXRW: Hard-coded offset

	/* Calculate $c14-relative offset to stack frame. */
	daddiu	$t0, $t0, 32			# XXXRW: Hard-coded offset

	/* Pop caller return $pcc. */
	clc	$c17, $t0, 0($c14)		# XXXRW: Hard-coded offset

	/* Pop caller return $c11. */
	clc	$c11, $t0, CHERICAP_SIZE($c14)	# XXXRW: Hard-coded offset

creturn_clear_regs:
	CHERI_CLEAR_GPLO16( \
		CHERI_CLEAR_GPLO_AT | \
		CHERI_CLEAR_GPLO_A0 | \
		CHERI_CLEAR_GPLO_A1 | \
		CHERI_CLEAR_GPLO_A2 | \
		CHERI_CLEAR_GPLO_A3 | \
		CHERI_CLEAR_GPLO_A4 | \
		CHERI_CLEAR_GPLO_A5 | \
		CHERI_CLEAR_GPLO_A6 | \
		CHERI_CLEAR_GPLO_A7 | \
		CHERI_CLEAR_GPLO_T0 | \
		CHERI_CLEAR_GPLO_T1 | \
		CHERI_CLEAR_GPLO_T2 | \
		CHERI_CLEAR_GPLO_T3 )
	CHERI_CLEAR_GPHI16( \
		CHERI_CLEAR_GPHI_S0 | \
		CHERI_CLEAR_GPHI_S1 | \
		CHERI_CLEAR_GPHI_S2 | \
		CHERI_CLEAR_GPHI_S3 | \
		CHERI_CLEAR_GPHI_S4 | \
		CHERI_CLEAR_GPHI_S5 | \
		CHERI_CLEAR_GPHI_S6 | \
		CHERI_CLEAR_GPHI_S7 | \
		CHERI_CLEAR_GPHI_T8 | \
		CHERI_CLEAR_GPHI_T9 | \
		CHERI_CLEAR_GPHI_GP | \
		CHERI_CLEAR_GPHI_SP | \
		CHERI_CLEAR_GPHI_S8 | \
		CHERI_CLEAR_GPHI_RA )
	mtlo	$zero
	mthi	$zero

creturn_clear_fpregs:
	/* XXXRW: Floating-point registers. */

creturn_clear_caps:
	CHERI_CLEAR_CAPLO16( \
		CHERI_CLEAR_CAPLO_C1  | \
		CHERI_CLEAR_CAPLO_C2  | \
		CHERI_CLEAR_CAPLO_C4  | \
		CHERI_CLEAR_CAPLO_C5  | \
		CHERI_CLEAR_CAPLO_C6  | \
		CHERI_CLEAR_CAPLO_C7  | \
		CHERI_CLEAR_CAPLO_C8  | \
		CHERI_CLEAR_CAPLO_C9  | \
		CHERI_CLEAR_CAPLO_C10 | \
		/* CHERI_CLEAR_CAPLO_C11 | */ \
		CHERI_CLEAR_CAPLO_C12 | \
		CHERI_CLEAR_CAPLO_C13 | \
		CHERI_CLEAR_CAPLO_C14 | \
		CHERI_CLEAR_CAPLO_C15 )
	CHERI_CLEAR_CAPHI16( \
		CHERI_CLEAR_CAPHI_C16 | \
		/* CHERI_CLEAR_CAPHI_C17 | */ \
		CHERI_CLEAR_CAPHI_C18 | \
		CHERI_CLEAR_CAPHI_C19 | \
		CHERI_CLEAR_CAPHI_C20 | \
		CHERI_CLEAR_CAPHI_C21 | \
		CHERI_CLEAR_CAPHI_C22 | \
		CHERI_CLEAR_CAPHI_C23 | \
		CHERI_CLEAR_CAPHI_C24 | \
		CHERI_CLEAR_CAPHI_C25)

creturn_return:
	cjr	$c17
	nop					# Branch-delay slot

creturn_local_retval:
creturn_stack_underflow:
	/* XXXRW: What do we want to do here?  Just trap for now. */
	teq	$zero, $zero
	.end	libcheri_creturn_vector
