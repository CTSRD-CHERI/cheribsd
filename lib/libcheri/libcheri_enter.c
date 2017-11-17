/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
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

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "libcheri_ccall.h"
#include "libcheri_enter.h"
#include "libcheri_system.h"
#include "libcheri_init.h"
#include "libcheri_sandbox.h"

/*
 * This file implements a stack landing pad for system classes provided by
 * libcheri.  The single stack is statically allocated -- meaning no
 * concurrent invocation from sandboxes in multiple threads (or reentrantly).
 * Currently, that is ensured by virtue of applications not themselves
 * invoking sandboxes concurrently.
 */

/*
 * Stack for use on entering from sandbox, supporting both hybrid ABI (in
 * which the stack capability is combined with $sp) and pure-capability ABI
 * (in which only the stack capability is used).
 */
#ifdef __CHERI_PURE_CAPABILITY__
extern __capability void	*__libcheri_enter_stack_csp; /* Pure cap. */
#else
extern __capability void	*__libcheri_enter_stack_cap; /* Hybrid cap. */
extern register_t		 __libcheri_enter_stack_sp;  /* Hybrid cap. */
#endif

#define	LIBCHERI_ENTER_STACK_SIZE	(PAGE_SIZE * 16)
static void		*__libcheri_enter_stack;	/* Stack itself. */
#ifdef __CHERI_PURE_CAPABILITY__
__capability void	*__libcheri_enter_stack_csp;	/* Pure cap. */
#else
__capability void	*__libcheri_enter_stack_cap;	/* Hybrid cap. */
register_t		 __libcheri_enter_stack_sp;	/* Hybrid cap. */
#endif

/*
 * Return capability to use from system objects.
 */
struct cheri_object	 __libcheri_object_creturn;

/*
 * Initialise landing-pad environment for system-object invocation.
 */
void
libcheri_enter_init(void)
{

	/* XXX: Should be MAP_STACK, but that is broken. */
	__libcheri_enter_stack = mmap(NULL, LIBCHERI_ENTER_STACK_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	assert(__libcheri_enter_stack != MAP_FAILED);

	/*
	 * In CheriABI, we use the capability returned by mmap(2), which $sp
	 * will be relative to, and implement solely $csp.  Otherwise, assume
	 * a global $sp and use $c0.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	__libcheri_enter_stack_csp = __libcheri_enter_stack +
	    LIBCHERI_ENTER_STACK_SIZE;
#else
	__libcheri_enter_stack_cap = cheri_getdefault();
	__libcheri_enter_stack_sp =
	    (register_t)((char *)__libcheri_enter_stack +
	    LIBCHERI_ENTER_STACK_SIZE);
#endif
	__libcheri_object_creturn = libcheri_make_sealed_return_object();
}
