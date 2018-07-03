/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
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

#ifndef _LIBCHERI_SANDBOX_H_
#define	_LIBCHERI_SANDBOX_H_

#ifdef __cplusplus
#include <exception>
#endif

/*
 * This section defines interfaces for setting up, invoking, resetting, and
 * destroying sandbox classes and objects.
 */

extern int sb_verbose;

#ifdef __cplusplus
#if __cplusplus >= 201103
#define LIBCHERI_OVERRIDE override
#else
#define LIBCHERI_OVERRIDE
#endif
namespace libcheri
{
	/**
	 * Sandbox exception class.  In C++ mode, error returns from
	 * cross-domain calls will be translated into exceptions.
	 */
	class sandbox_invoke_failure : public std::exception
	{
		/**
		 * The error code set on construction.
		 */
		int errno;
		public:
		sandbox_invoke_failure(int e) : errno(e) {}

		/**
		 * Returns the error code, which should be the `cher_ierrno`
		 * value from a failed ccall.
		 */
		int error_code() { return errno; }
		virtual const char* what() const _NOEXCEPT LIBCHERI_OVERRIDE;
		virtual ~sandbox_invoke_failure() _NOEXCEPT LIBCHERI_OVERRIDE;
	};
}
#undef LIBCHERI_OVERRIDE
#endif

void	libcheri_init(void);

struct sandbox_class;
int	sandbox_class_new(const char *path, size_t maxmapsize,
	    struct sandbox_class **sbcpp);
int	sandbox_class_method_declare(struct sandbox_class *sbcp,
	    u_int methodnum, const char *methodname);
void	sandbox_class_destroy(struct sandbox_class *sbcp);
int	sandbox_class_method_get_number(struct sandbox_class *sbcp,
	    const char *name);

struct sandbox_object;
int	sandbox_object_new(struct sandbox_class *sbcp, size_t heaplen,
	    struct sandbox_object **sbopp);
int	sandbox_object_new_flags(struct sandbox_class *sbcp, size_t heaplen,
	    uint flags, struct sandbox_object **sbopp);
int	sandbox_object_new_system_object(__capability void *private_data,
	    __capability void *invoke_pcc, __capability vm_offset_t *vtable,
	    struct sandbox_object **sbopp);

/**
 * Reset the stack of a sandbox.  This is a temporary API until libcheri
 * becomes responsible for managing a pool of stacks.
 */
int	sandbox_object_stack_reset(struct sandbox_object *sbop);
int	sandbox_object_reset(struct sandbox_object *sbop);
register_t	sandbox_object_invoke(struct sandbox_object *sbop,
		    register_t methodnum, register_t a1,
		    register_t a2, register_t a3, register_t a4,
		    register_t a5, register_t a6, register_t a7,
		    __capability void *c3, __capability void *c4,
		    __capability void *c5, __capability void *c6,
		    __capability void *c7, __capability void *c8,
		    __capability void *c9, __capability void *c10);
void	sandbox_object_destroy(struct sandbox_object *sbop);

/*
 * Flags for sandbox_object_new_flags():
 */
#define	SANDBOX_OBJECT_FLAG_CONSOLE	0x00000001	/* printf(), etc. */
#define	SANDBOX_OBJECT_FLAG_ALLOCFREE	0x00000002	/* calloc(), free(). */
#define	SANDBOX_OBJECT_FLAG_USERFN	0x00000004	/* User callbacks. */

/*
 * API to query the object-capability pair for the sandbox itself
 */
struct cheri_object	sandbox_object_getobject(struct sandbox_object *sbop);

/**
 * Get the sandbox's global data capability.
 */
__capability void *
sandbox_object_getsandboxdata(struct sandbox_object *sbop);

/**
 * Get the sandbox's stack.  This is a temporary API and should go away once
 * libcheri is responsible for managing a pool of stacks and clearing them.
 */
__capability void *
sandbox_object_getsandboxstack(struct sandbox_object *sbop);

/*
 * API to query system capabilities for use by sandboxes.
 */
struct cheri_object	sandbox_object_getsystemobject(
			    struct sandbox_object *sbop);

/*
 * API to get private data for system-class implementations.
 */
__capability void	*sandbox_object_private_get(
			    struct sandbox_object *sbop);
__capability void	*sandbox_object_private_get_idc(void);

#endif /* !_LIBCHERI_SANDBOX_H_ */
