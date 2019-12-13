/*-
 * Copyright (c) 1998-1999 Andrew Gallatin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _COMPAT_FREEBSD64_FREEBSD64_UTIL_H_
#define _COMPAT_FREEBSD64_FREEBSD64_UTIL_H_

#include <sys/cdefs.h>
#include <sys/exec.h>
#include <sys/sysent.h>
#include <sys/ucontext.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

struct mmap_req;

struct freebsd64_ps_strings {
	uint64_t	ps_argvstr;
	int		ps_nargvstr;
	uint64_t	ps_envstr;
	int		ps_nenvstr;
	uint64_t	ps_sbclasses;
	size_t		ps_sbclasseslen;
	uint64_t	ps_sbmethods;
	size_t		ps_sbmethodslen;
	uint64_t	ps_sbobjects;
	size_t		ps_sbobjectslen;
};

#define	FREEBSD64_PS_STRINGS	\
	(USRSTACK - sizeof(struct freebsd64_ps_strings))

typedef struct {	/* Auxiliary vector entry on initial stack */
	long	a_type;		/* Entry type. */
	union {
		long	a_val;		/* Integer value. */
		void	*a_ptr;		/* Address. */
		/* void	(*a_fcn)(void); */ /* Function pointer (not used). */
       } a_un;
} ElfFreeBSD64_Auxinfo;

extern struct sysent freebsd64_sysent[];

#define FREEBSD64_SYSCALL_INIT_HELPER(syscallname) {			\
	.new_sysent = {							\
	.sy_narg = (sizeof(struct syscallname ## _args )		\
		/ sizeof(syscallarg_t)),				\
	.sy_call = (sy_call_t *)& syscallname,				\
	},								\
	.syscall_no = FREEBSD64_SYS_##syscallname			\
}

#define FREEBSD64_SYSCALL_INIT_HELPER_COMPAT(syscallname) {		\
	.new_sysent = {							\
	.sy_narg = (sizeof(struct syscallname ## _args )		\
		/ sizeof(syscallarg_t)),				\
	.sy_call = (sy_call_t *)& sys_ ## syscallname,			\
	},								\
	.syscall_no = FREEBSD64_SYS_##syscallname			\
}

#define FREEBSD64_SYSCALL_NOT_PRESENT_GEN(SC)				\
int freebsd64_ ## SC (struct thread *td,				\
    struct freebsd64_##SC##_args *uap)					\
{									\
									\
	return syscall_not_present(td, #SC , (struct nosys_args *)uap); \
}

int    freebsd64_syscall_register(int *offset, struct sysent *new_sysent,
	    struct sysent *old_sysent, int flags);
int    freebsd64_syscall_deregister(int *offset, struct sysent *old_sysent);
int    freebsd64_syscall_helper_register(struct syscall_helper_data *sd, int flags);
int    freebsd64_syscall_helper_unregister(struct syscall_helper_data *sd);

struct iovec64;
int	freebsd64_copyout_strings(struct image_params *imgp,
	    uintptr_t *);
int	freebsd64_copyiniov(struct iovec64 * __capability iovp, u_int iovcnt,
	    struct iovec **iov, int error);
int	freebsd64_copyinuio(struct iovec64 * __capability iovp, u_int iovcnt,
	    struct uio **uiop);

int	freebsd64_get_mcontext(struct thread *td, mcontext64_t *mcp, int flags);
int	freebsd64_set_mcontext(struct thread *td, mcontext64_t *mcp);
int	freebsd64_set_user_tls(struct thread *td, void *tls_base);

#endif /* !_COMPAT_FREEBSD64_FREEBSD64_UTIL_H_ */
