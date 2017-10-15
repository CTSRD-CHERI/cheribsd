/*-
 * Copyright (c) 2017 Robert N. M. Watson
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
#include <sys/stat.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include "cheri_ccall.h"
#include "cheri_class.h"
#include "cheri_type.h"
#include "libcheri_init.h"
#include "sandbox_internal.h"

/*
 * This call provides the C implementation of the userspace CCall trampoline
 * for libcheri.  Three object types are used: CCall paths into rtld
 * initialisation, invocation, and CReturn.
 *
 * For CCall data capabilities, we use the sandbox object pointer, where we
 * can find any data required to perform the domain transition, including a
 * suitable capability for use with TLS.  Currently, this means deriving these
 * sealed data capabilities from DDC.
 *
 * For CReturn data capabilities, we use a pointer to a global data structure
 * that contains a suitable capability for use with TLS -- as with above, we
 * currently derive this capability from DDC.
 *
 * XXXRW: Will we also want to do something to provide per-thread execution
 * stacks to handle failures in CCall and CReturn.
 *
 * XXXRW: How to handle signal delivery during CCall and CReturn?
 */

/*
 * External assembly for CCall and CReturn vectors.  Ideally the rtld and
 * general invocation vectors might be shared, but userspace CCall cannot
 * currently reliable access the operand object type.
 */
extern void	libcheri_ccall_rtld_vector;
extern void	libcheri_ccall_invoke_vector;
extern void	libcheri_creturn_vector;

/*
 * Sealing capabilities used to seal invocation, rtld, and creturn
 * capabilities.
 */
static __capability void	*cheri_ccall_invoke_type;
static __capability void	*cheri_ccall_rtld_type;
static __capability void	*cheri_creturn_type;

/*
 * Sealed capabilities shared across all sandbox objects: code for invocation
 * and rtld; code and data for creturn.
 */
static __capability void	*cheri_ccall_invoke_sealed_code;
static __capability void	*cheri_ccall_rtld_sealed_code;
static struct cheri_object	 cheri_creturn_object;

static
#if _MIPS_SZCAP == 128
__attribute__ ((aligned(4096)))
#endif
void	*cheri_creturn_data;

/*
 * One-time initialisation of libcheri on startup: (1) Initialise sealing
 * capabilities for invocation, rtld, and creturn; and (2) Initialise sealed
 * capabilities where the values will be shared across many sandboxes.
 */
void
cheri_ccall_init(void)
{
	__capability void *cap;

	/*
	 * Initialise sealing capabilities for invocation, rtld, and creturn,
	 *
	 */
	cheri_ccall_invoke_type = cheri_type_alloc();
	cheri_ccall_rtld_type = cheri_type_alloc();
	cheri_creturn_type = cheri_type_alloc();

	/*
	 * Pointer to the invocation vector, with global bounds in order to
	 * provide access to the trusted stack (etc).
	 */
	cap = cheri_getpcc();
	cap = cheri_setoffset(cap, (vaddr_t)&libcheri_ccall_invoke_vector);
	cheri_ccall_invoke_sealed_code = cheri_seal(cap,
	    cheri_ccall_invoke_type);

	/*
	 * Pointer to the rtld vector, with global bounds in order to provide
	 * access to the trusted stack (etc).
	 */
	cap = cheri_getpcc();
	cap = cheri_setoffset(cap, (vaddr_t)&libcheri_ccall_rtld_vector);
	cheri_ccall_rtld_sealed_code = cheri_seal(cap, cheri_ccall_rtld_type);

	/*
	 * Pointer to the creturn vector, with global bounds in order to
	 * provide access to the trusted stack (etc).  There is no
	 * call-specific data, so use dummy data.
	 */
	cap = cheri_getpcc();
	cap = cheri_setoffset(cap, (vaddr_t)&libcheri_creturn_vector);
	cheri_creturn_object.co_codecap = cheri_seal(cap, cheri_creturn_type);

	cap = cheri_getdefault();
	cap = cheri_setoffset(cap, (vaddr_t)&cheri_creturn_data);
	cheri_creturn_object.co_datacap = cheri_seal(cap, cheri_creturn_type);
}

/*
 * Return various sealed capabilities for a sandbox object instance.
 */
struct cheri_object
cheri_sandbox_make_sealed_invoke_object(struct sandbox_object *sbop)
{
	struct cheri_object co;
	__capability void *cap;

	co.co_codecap = cheri_ccall_invoke_sealed_code;

	/*
	 * Pointer to sandbox description; global bounds so that we can derive
	 * a suitable $ddc from it.
	 */
	cap = cheri_getdefault();
	cap = cheri_setoffset(cap, (vaddr_t)sbop);
	co.co_datacap = cheri_seal(cap, cheri_ccall_invoke_type);
	return (co);
}

struct cheri_object
cheri_sandbox_make_sealed_rtld_object(struct sandbox_object *sbop)
{
	struct cheri_object co;
	__capability void *cap;

	co.co_codecap = cheri_ccall_rtld_sealed_code;

	/*
	 * Pointer to sandbox description; global bounds so that we can derive
	 * a suitable $ddc from it.
	 */
	cap = cheri_getdefault();
	cap = cheri_setoffset(cap, (vaddr_t)sbop);
	co.co_datacap = cheri_seal(cap, cheri_ccall_rtld_type);
	return (co);
}

struct cheri_object
cheri_make_sealed_return_object(void)
{

	return (cheri_creturn_object);
}
