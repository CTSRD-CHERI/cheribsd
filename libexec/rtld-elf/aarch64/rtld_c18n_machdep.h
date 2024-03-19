/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
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

#ifndef RTLD_C18N_MACHDEP_H
#define RTLD_C18N_MACHDEP_H

#define	C18N_TRUSTED_FRAME_SIZE		15

#ifndef IN_ASM
/*
 * Stack unwinding
 */
struct trusted_frame {
	void *fp;
	void *pc;
	/*
	 * Address of the next trusted frame
	 */
	ptraddr_t next;
	/*
	 * Number of return value registers, encoded in enum tramp_ret_args
	 */
	uint8_t ret_args : 2;
	/*
	 * This field contains the code address in the trampoline that the
	 * callee should return to. This is only used by unwinders to detect
	 * compartment boundaries.
	 */
	ptraddr_t cookie : 62;
	/*
	 * INVARIANT: This field contains the top of the caller's stack when the
	 * caller made the call.
	 */
	void *n_sp;
	/*
	 * INVARIANT: This field contains the top of the caller's stack when the
	 * caller was last entered.
	 */
	ptraddr_t o_sp;
	/*
	 * This field contains the address of the trusted stack before the
	 * current frame was pushed. It is only used by unwinders.
	 */
	ptraddr_t csp;
	/*
	 * c19 to c28
	 */
	void *regs[10];
};
_Static_assert(
    sizeof(struct trusted_frame) == sizeof(uintptr_t) * C18N_TRUSTED_FRAME_SIZE,
    "Unexpected struct trusted_frame size");
#endif
#endif
