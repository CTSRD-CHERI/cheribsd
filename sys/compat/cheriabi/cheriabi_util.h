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

#ifndef _COMPAT_CHERIABI_CHERIABI_UTIL_H_
#define _COMPAT_CHERIABI_CHERIABI_UTIL_H_

#include <sys/cdefs.h>
#include <sys/exec.h>
#include <sys/sysent.h>
#include <sys/ucontext.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

struct mmap_req;

struct cheriabi_ps_strings {
	void * __capability	ps_argvstr;
	int		ps_nargvstr;
	void * __capability	ps_envstr;
	int		ps_nenvstr;
	void * __capability	ps_sbclasses;
	size_t		ps_sbclasseslen;
	void * __capability	ps_sbmethods;
	size_t		ps_sbmethodslen;
	void * __capability	ps_sbobjects;
	size_t		ps_sbobjectslen;
};

#define	CHERIABI_PS_STRINGS	\
	(USRSTACK - sizeof(struct cheriabi_ps_strings))

typedef struct {	/* Auxiliary vector entry on initial stack */
	long	a_type;		/* Entry type. */
	/* long    pad[(CHERICAP_SIZE / 8) - 1]; */
	union {
		long	a_val;		/* Integer value. */
		void * __capability	a_ptr;	/* Address. */
		/* void	(*a_fcn)(void); */ /* Function pointer (not used). */
       } a_un;
} ElfCheriABI_Auxinfo;

extern struct sysent cheriabi_sysent[];

#define CHERIABI_SYSCALL_INIT_HELPER(syscallname) {			\
	.new_sysent = {							\
	.sy_narg = (sizeof(struct syscallname ## _args )		\
		/ sizeof(syscallarg_t)),				\
	.sy_call = (sy_call_t *)& syscallname,				\
	},								\
	.syscall_no = CHERIABI_SYS_##syscallname			\
}

#define CHERIABI_SYSCALL_INIT_HELPER_COMPAT(syscallname) {		\
	.new_sysent = {							\
	.sy_narg = (sizeof(struct syscallname ## _args )		\
		/ sizeof(syscallarg_t)),				\
	.sy_call = (sy_call_t *)& sys_ ## syscallname,			\
	},								\
	.syscall_no = CHERIABI_SYS_##syscallname			\
}

#define CHERIABI_SYSCALL_NOT_PRESENT_GEN(SC)				\
int cheriabi_ ## SC (struct thread *td,					\
    struct cheriabi_##SC##_args *uap)					\
{									\
									\
	return syscall_not_present(td, #SC , (struct nosys_args *)uap); \
}

int    cheriabi_syscall_register(int *offset, struct sysent *new_sysent,
	    struct sysent *old_sysent, int flags);
int    cheriabi_syscall_deregister(int *offset, struct sysent *old_sysent);
int    cheriabi_syscall_helper_register(struct syscall_helper_data *sd, int flags);
int    cheriabi_syscall_helper_unregister(struct syscall_helper_data *sd);

struct iovec_c;
int	cheriabi_copyout_auxargs(struct image_params *imgp, uintcap_t base);
int	cheriabi_copyout_strings(struct image_params *imgp,
	    uintptr_t *stack_base);
int	cheriabi_copyiniov(struct iovec_c * __capability iovp, u_int iovcnt,
	    struct iovec **iov, int error);
int	cheriabi_copyinuio(struct iovec_c * __capability iovp, u_int iovcnt,
	    struct uio **uiop);

int	cheriabi_elf_fixup(uintptr_t *stack_base, struct image_params *imgp);

void	cheriabi_fetch_syscall_arg(struct thread *td, void * __capability *arg,
	    int argnum, int ptrmask);

void * __capability	cheriabi_mmap_retcap(struct thread *td,
	    vm_offset_t addr, const struct mmap_req *mrp);

int	cheriabi_get_mcontext(struct thread *td, mcontext_c_t *mcp, int flags);
int	cheriabi_set_mcontext(struct thread *td, mcontext_c_t *mcp);
void	cheriabi_set_threadregs(struct thread *td, struct thr_param_c *param);

#endif /* !_COMPAT_CHERIABI_CHERIABI_UTIL_H_ */
