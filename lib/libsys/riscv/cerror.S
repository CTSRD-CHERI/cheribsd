/*-
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
#include "SYS.h"

#define FRAME_SIZE	(2 * __SIZEOF_POINTER__) /* Always multiple of 16 */
#define SPILLSLOT_RA	(0 * __SIZEOF_POINTER__)
#define SPILLSLOT_ERRNO	(1 * __SIZEOF_POINTER__)

ENTRY(cerror)
#ifdef __CHERI_PURE_CAPABILITY__
	cincoffset	csp, csp, -FRAME_SIZE
	csc	cra, SPILLSLOT_RA(csp)
	csd	a0, SPILLSLOT_ERRNO(csp)	# spill new errno value
	ccall	_C_LABEL(__error)		# locate address of errno (in ca0)
	cld	a1, SPILLSLOT_ERRNO(csp)	# re-load new errno value
	csw	a1, 0(ca0)			# update errno value
	clc	cra, SPILLSLOT_RA(csp)
	li	a0, -1			# Set both return registers to -1 to
	li	a1, -1			# indicate syscall failure.
	cincoffset	csp, csp, FRAME_SIZE
	cret
#else
	addi	sp, sp, -FRAME_SIZE
	sd	a0, SPILLSLOT_ERRNO(sp)
	sd	ra, SPILLSLOT_RA(sp)
	call	_C_LABEL(__error)
	ld	a1, SPILLSLOT_ERRNO(sp)
	ld	ra, SPILLSLOT_RA(sp)
	sw	a1, 0(a0)
	li	a0, -1
	li	a1, -1
	addi	sp, sp, FRAME_SIZE
	ret
#endif
END(cerror)
