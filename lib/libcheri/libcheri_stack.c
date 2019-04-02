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

#include <sys/types.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <ucontext.h>

#include "libcheri_stack.h"
#include "libcheri_stack_internal.h"
#include "libcheri_init.h"

/*
 * Implementation of trusted stacks for the libcheri compartmentalisation
 * model.  Each pthread has its own trusted stack that tracks calls between
 * libcheri objects; frames contain the information required to recover
 * contorl safely to the caller context (in another protection domain) both in
 * the event of a CReturn from the callee, and in the event of a trusted-stack
 * unwind due to an exception termination execution in an object prematurely.
 */

/*
 * Use linker/compiler-provided thread-local storage for the stack, to avoid
 * the need for explicit pthreads-based initialisation and management that
 * would otherwise need to incur inline in libcheri_invoke() -- although we
 * might want to change this functional simplification for performance reasons
 * in the future.
 *
 * XXX: Today we access this field lock-free, since it won't be accessed by
 * other threads (at least currently).  However, there is a question about
 * reentrancy and signal handlers, where some more care may be required, as
 * signal handlers may wish to rewrite the trusted stack -- and must be
 * careful in the event that the signal is delivered while the trusted stack
 * is already being used/manipulated.  One example would be if a domain
 * transition or other manipulation is taking place when a timer interrupt
 * fires.  This suggests the notion of a critical section protecting the
 * trusted stack, but we'd like to avoid the need for this in invocation path
 * as our goal is to avoid system calls there.  Some more thinking is required
 * here -- e.g., do we want to do a soft-interrupt-style thing along the lines
 * if interrupts taken during spl()s in the kernel, with the signal handler
 * "scheduling" the change to take place once the preempted code returns..?
 *
 * XXXAR: we use local-exec tls model here to ensure that we can load the
 * values without using the captable.
 */
__thread struct libcheri_stack __libcheri_stack_tls_storage
    __attribute__((__aligned__(32), tls_model("local-exec"))) = {
	.lcs_tsize = LIBCHERI_STACK_SIZE,
	.lcs_tsp = LIBCHERI_STACK_SIZE,
};

void
libcheri_stack_init(void)
{

	/*
	 * Ensure thread-local storage for the first thread's trusted stack is
	 * suitably aligned.
	 */
	assert(((vaddr_t)&__libcheri_stack_tls_storage % CHERICAP_SIZE) == 0);
}

/*
 * APIs to get and set the trusted stack, which currently encode the internal
 * stack structure, and assume a fixed-size trusted stack.
 *
 * Return success/failure on "get to allow for the possibility that trusted
 * stacks might be allocated on-demand in the future, and hence might not be
 * present if libcheri hasn't been used from a thread previously.
 */
int
libcheri_stack_get(struct libcheri_stack *lcsp)
{

	memcpy(lcsp, &__libcheri_stack_tls_storage, sizeof(*lcsp));
	return (0);
}

/*
 * Return the number of frames on the trusted stack; similarly, retain a
 * return value in case in the future we need to make this conditional on a
 * trusted stack being allocated.
 */
int
libcheri_stack_numframes(int *numframesp)
{

	*numframesp = (__libcheri_stack_tls_storage.lcs_tsize -
	    __libcheri_stack_tls_storage.lcs_tsp) / LIBCHERI_STACKFRAME_SIZE;
	return (0);
}

/*
 * Allow the trusted stack to be set, subject to various safety constraints.
 */
int
libcheri_stack_set(struct libcheri_stack *lcsp)
{

	if (lcsp->lcs_tsize != __libcheri_stack_tls_storage.lcs_tsize) {
		errno = EINVAL;
		return (-1);
	}
	if (lcsp->lcs_tsp < 0 || lcsp->lcs_tsp > LIBCHERI_STACK_SIZE ||
	    (lcsp->lcs_tsp % LIBCHERI_STACKFRAME_SIZE) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&__libcheri_stack_tls_storage, lcsp,
	    sizeof(__libcheri_stack_tls_storage));
	return (0);
}

/*
 * Unwind the trust stack the specified number of frames (or all) --
 * machine-independent portion.
 */
int
libcheri_stack_unwind(ucontext_t *uap, register_t ret, u_int op,
    u_int num_frames)
{
	struct libcheri_stack lcs;
	struct libcheri_stack_frame *lcsfp;
	u_int stack_size, stack_frames;

	if (op != LIBCHERI_STACK_UNWIND_OP_N &&
	    op != LIBCHERI_STACK_UNWIND_OP_ALL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Request to unwind zero frames is a no-op: no state transformation
	 * is needed.
	 */
	if ((op == LIBCHERI_STACK_UNWIND_OP_N) && (num_frames == 0))
		return (0);

	/*
	 * Retrieve trusted stack and validate before attempting to unwind.
	 */
	if (libcheri_stack_get(&lcs) != 0)
		return (-1);
	if ((lcs.lcs_tsize % LIBCHERI_STACKFRAME_SIZE) != 0 ||
	    (lcs.lcs_tsp > lcs.lcs_tsize) ||
	    (lcs.lcs_tsp % LIBCHERI_STACKFRAME_SIZE) != 0) {
		errno = ERANGE;
		return (-1);
	}

	/*
	 * See if there is room on the stack for that much unwinding.
	 */
	stack_size = lcs.lcs_tsize / LIBCHERI_STACKFRAME_SIZE;
	stack_frames = (lcs.lcs_tsize - lcs.lcs_tsp) /
	    LIBCHERI_STACKFRAME_SIZE;
	if (op == LIBCHERI_STACK_UNWIND_OP_ALL)
		num_frames = stack_frames;
	if ((num_frames < 0) || (stack_frames < num_frames)) {
		errno = ERANGE;
		return (-1);
	}

	/*
	 * Restore state from the last frame being unwound.
	 */
	lcsfp = &lcs.lcs_frames[stack_size - (stack_frames - num_frames) - 1];
#if 0
	/* Make sure we will be returning to ambient authority. */
	if (cheri_getbase(lcsfp->csf_caller_pcc) !=
	    cheri_getbase(cheri_getpcc()) ||
	    cheri_getlen(lcsfp->csf_caller_pcc) !=
	    cheri_getlen(cheri_getpcc()))
		return (-1);
#endif

	/*
	 * Pop stack desired number of frames.
	 */
	lcs.lcs_tsp += num_frames * LIBCHERI_STACKFRAME_SIZE;
	assert(lcs.lcs_tsp <= lcs.lcs_tsize);

	if (libcheri_stack_unwind_md(uap, lcsfp, ret) < 0)
		return (-1);
	if (libcheri_stack_set(&lcs) < 0)
		return (-1);
	return (0);
}
