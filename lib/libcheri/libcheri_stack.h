/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
 * Copyright (c) 2015 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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

#ifndef _LIBCHERI_STACK_H_
#define	_LIBCHERI_STACK_H_

#include <ucontext.h>  /* For ucontext_t argument to libcheri_stack_unwind(). */

/*
 * Definitions for libcheri's "trusted stack": Each frame describes the state
 * associated with a particular invocation of CCall, and contains the return
 * $pcc and $csp values to restore once the invoked object returns.  Frames
 * are pushed as invocations are made, and popped on safe return or if an
 * exception leads to an unwind (or if the trusted stack is manipulated
 * directly using privileged calls).
 *
 * Currently the same structures are used internally as are exposed via the
 * library API; we might wish to change this for reasons of ABI robustness.
 */
struct libcheri_stack_frame {
#if __has_feature(capabilities)
	void * __capability	lcsf_caller_pcc;   /* Caller return $pcc */
	void * __capability	lcsf_caller_csp;   /* Callee return $csp */
	void * __capability	lcsf_callee_sbop;  /* Callee sandbox object */
#else
	struct chericap	lcsf_caller_pcc;
	struct chericap	lcsf_caller_csp;
	struct chericap lcsf_callee_sbop;
#endif
};

/*
 * Currently, we have a maximum invocation depth that is low, and encoded in
 * the ABI.  We might want to revisit these choices to hide any limit from the
 * library consumer, to raise it, and perhaps to allow flexible per-thread
 * limits.  A lot will depend on eventual common usage patterns.
 */
#define	LIBCHERI_STACK_DEPTH	8	/* XXXRW: 8 is a nice round number. */
struct libcheri_stack {
	register_t	lcs_tsp;	/* Byte offset into lcs_frames,
					 * not frame index. */
	register_t	lcs_tsize;	/* Stack size, in bytes. */
	register_t	_lcs_pad0;
	register_t	_lcs_pad1;
	struct libcheri_stack_frame	lcs_frames[LIBCHERI_STACK_DEPTH];
} __aligned(CHERICAP_SIZE);

#define	LIBCHERI_STACKFRAME_SIZE	sizeof(struct libcheri_stack_frame)
#define	LIBCHERI_STACK_SIZE						\
			    (LIBCHERI_STACK_DEPTH * LIBCHERI_STACKFRAME_SIZE)

/*
 * Public libcheri APIs to interact with the trusted stack.
 */

int	libcheri_stack_get(struct libcheri_stack *csp);	/* XXXRW: TODO */
int	libcheri_stack_set(struct libcheri_stack *csp);	/* XXXRW: TODO */

/*
 * Unwind operations.
 */
#define	LIBCHERI_STACK_UNWIND_OP_N	1	/* Unwind (n) frames. */
#define	LIBCHERI_STACK_UNWIND_OP_ALL	2	/* Unwind all frames. */

int	libcheri_stack_numframes(int *numframesp);
int	libcheri_stack_unwind(ucontext_t *uap, register_t ret, u_int op,
	    u_int num_frames);

#endif /* !_LIBCHERI_STACK_H_ */
