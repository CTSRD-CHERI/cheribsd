/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 * Copyright (c) 2011-2018 Robert N. M. Watson
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

#include <machine/cheriasm.h>
#include <machine/cherireg.h>

.set cheri_sysregs_accessible	# Don't warn about uses of c27-c30

.macro cheriboot secondary
	/*
	 * Grab the initial omnipotent capability
	 */
	cgetdefault	CHERI_REG_C28

	/*
	 * Create a reduced DDC.
	 *
	 * XXX-BD: Actually changing base/length requires changes in
	 * linkage.
	 */
	cmove		CHERI_REG_C27, CHERI_REG_C28
	REG_LI		t0, CHERI_CAP_KERN_BASE
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI		t0, CHERI_CAP_KERN_LENGTH
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI		t0, CHERI_PERMS_KERNEL_DATA
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0

	/* Preserve a copy in KDC for exception handlers. */
	csetkdc		CHERI_REG_C27

	/* Install the new DDC. */
	csetdefault	CHERI_REG_C27

	/*
	 * Create a reduced PCC.
	 *
	 * XXX-BD: Actually changing base/length requires changes in
	 * linkage.
	 */
	cgetpcc		CHERI_REG_C27
	REG_LI		t0, CHERI_CAP_KERN_BASE
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI		t0, CHERI_CAP_KERN_LENGTH
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI		t0, CHERI_PERMS_KERNEL_CODE
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0

	/* Preserve a copy in KCC for exception handlers.  */

	csetkcc		CHERI_REG_C27

	/* Install the new PCC. */
	REG_LI		t0, CHERI_CAP_KERN_BASE
	cgetpcc		CHERI_REG_C29
	cgetoffset	t1, CHERI_REG_C29			# 1
	PTR_SUBU	t1, t1, t0				# 2
	PTR_ADDIU	t1, t1, (4 * 7)				# 3
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t1	# 4
	cjr		CHERI_REG_C27				# 5
	nop							# 6
	# 7 (land here)

	/*
	 * Create the parent kernel sealing capablity.
	 */
	cmove		CHERI_REG_C27, CHERI_REG_C28
	REG_LI	t0, CHERI_SEALCAP_KERNEL_BASE
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI	t0, CHERI_SEALCAP_KERNEL_LENGTH
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI	t0, CHERI_SEALCAP_KERNEL_PERMS
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0
	PTR_LA	t0, _C_LABEL(kernel_sealcap)
	csc	CHERI_REG_C27, t0, 0($ddc)

.if \secondary == 0
	/*
	 * Create a capability covering all of userspace from which to
	 * derive new capabilities in execve(), etc.
	 *
	 * XXX-BD: A hardline, no-exceptions W^X implementation would split
	 * the userspace capability here.
	 *
	 * XXX-BD: This is actually an ABI property and should probably
	 * per sysent.
	 */
	cmove		CHERI_REG_C27, CHERI_REG_C28
	REG_LI	t0, CHERI_CAP_USER_DATA_BASE
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI	t0, CHERI_CAP_USER_DATA_LENGTH
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI	t0, CHERI_CAP_USER_DATA_PERMS | CHERI_CAP_USER_CODE_PERMS
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0
	PTR_LA	t0, _C_LABEL(userspace_cap)
	csc	CHERI_REG_C27, t0, 0($ddc)

	/*
	 * Create a capability for userspace to seal capabilities with.
	 */
	cmove		CHERI_REG_C27, CHERI_REG_C28
	REG_LI	t0, CHERI_SEALCAP_USERSPACE_BASE
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI	t0, CHERI_SEALCAP_USERSPACE_LENGTH
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0
	REG_LI	t0, CHERI_SEALCAP_USERSPACE_PERMS
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0
	PTR_LA	t0, _C_LABEL(user_sealcap)
	csc	CHERI_REG_C27, t0, 0($ddc)
.endif

	/*
	 * Store the omnipotent capability to allow swap to be restored.
	 */
	PTR_LA	t0, _C_LABEL(swap_restore_cap)
	csc	CHERI_REG_C28, t0, 0($ddc)

	/*
	 * Zero out our temporary registers.
	 *
	 * XXXRW: Do we want to rely on default initialisation of all CP2
	 * registers here?
	 */
	cmove CHERI_REG_C27, $cnull
	cmove CHERI_REG_C28, $cnull
.endm
