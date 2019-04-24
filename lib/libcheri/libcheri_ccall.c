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

#include "libcheri_ccall.h"
#include "libcheri_class.h"
#include "libcheri_type.h"
#include "libcheri_init.h"
#include "libcheri_sandbox_internal.h"

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
static void * __capability	 libcheri_ccall_invoke_type;
static void * __capability	 libcheri_ccall_rtld_type;
static void * __capability	 libcheri_creturn_type;

/*
 * Sealed capabilities shared across all sandbox objects: code for invocation
 * and rtld; code and data for creturn.
 */
static void * __capability	 libcheri_ccall_invoke_sealed_code;
static void * __capability	 libcheri_ccall_rtld_sealed_code;
static struct cheri_object	 libcheri_creturn_object;

static
#if _MIPS_SZCAP == 128
__attribute__ ((aligned(4096)))
#endif
void * __capability	 libcheri_creturn_data;

/*
 * One-time initialisation of libcheri on startup: (1) Initialise sealing
 * capabilities for invocation, rtld, and creturn; and (2) Initialise sealed
 * capabilities where the values will be shared across many sandboxes.
 */
void
libcheri_ccall_init(void)
{
	void * __capability cap;

	/*
	 * Initialise sealing capabilities for invocation, rtld, and creturn,
	 *
	 */
	libcheri_ccall_invoke_type = libcheri_type_alloc();
	libcheri_ccall_rtld_type = libcheri_type_alloc();
	libcheri_creturn_type = libcheri_type_alloc();

	/*
	 * Pointer to the invocation vector.
	 */
	cap = cheri_getpcc();
	cap = cheri_setaddress(cap, (vaddr_t)&libcheri_ccall_invoke_vector);
	libcheri_ccall_invoke_sealed_code = cheri_seal(cap,
	    libcheri_ccall_invoke_type);

	/*
	 * Pointer to the rtld vector.
	 */
	cap = cheri_getpcc();
	cap = cheri_setaddress(cap, (vaddr_t)&libcheri_ccall_rtld_vector);
	libcheri_ccall_rtld_sealed_code =
	    cheri_seal(cap, libcheri_ccall_rtld_type);

	/*
	 * Pointer to the creturn vector, with global bounds in order to
	 * provide access to the trusted stack (etc).  There is no
	 * call-specific data, so use dummy data.
	 *
	 * XXXRW: Global bounds only for code, not data..?
	 */
	cap = cheri_getpcc();
	cap = cheri_setaddress(cap, (vaddr_t)&libcheri_creturn_vector);
	libcheri_creturn_object.co_codecap =
	    cheri_seal(cap, libcheri_creturn_type);

#ifdef __CHERI_PURE_CAPABILITY__
	cap = &libcheri_creturn_data;
#else
	cap = cheri_ptr(&libcheri_creturn_data, sizeof(libcheri_creturn_data));
#endif
	libcheri_creturn_object.co_datacap =
	    cheri_seal(cap, libcheri_creturn_type);
}

/*
 * Return various sealed capabilities for a sandbox object instance.
 */
struct cheri_object
libcheri_sandbox_make_sealed_invoke_object(
    struct sandbox_object * __capability sbop)
{
	struct cheri_object co;

	co.co_codecap = libcheri_ccall_invoke_sealed_code;

	/*
	 * Pointer to sandbox description; struct sandbox_object must itself
	 * provide indirect access to a suitable DDC (etc) for the trampoline.
	 */
	co.co_datacap = cheri_seal(sbop, libcheri_ccall_invoke_type);
	return (co);
}

struct cheri_object
libcheri_sandbox_make_sealed_rtld_object(
    struct sandbox_object * __capability sbop)
{
	struct cheri_object co;

	co.co_codecap = libcheri_ccall_rtld_sealed_code;

	/*
	 * Pointer to sandbox description; struct sandbox_object must itself
	 * provide indirect access to a suitable DDC (etc) for the trampoline.
	 */
	co.co_datacap = cheri_seal(sbop, libcheri_ccall_rtld_type);
	return (co);
}

struct cheri_object
libcheri_make_sealed_return_object(void)
{

	return (libcheri_creturn_object);
}
