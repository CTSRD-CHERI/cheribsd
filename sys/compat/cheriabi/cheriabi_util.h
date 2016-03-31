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
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

struct cheriabi_ps_strings {
	struct chericap	ps_argvstr;
	int		ps_nargvstr;
	struct chericap	ps_envstr;
	int		ps_nenvstr;
	struct chericap	ps_sbclasses;
	size_t		ps_sbclasseslen;
	struct chericap	ps_sbmethods;
	size_t		ps_sbmethodslen;
	struct chericap	ps_sbobjects;
	size_t		ps_sbobjectslen;
};

#define	CHERIABI_PS_STRINGS	\
	(USRSTACK - sizeof(struct cheriabi_ps_strings))

typedef struct {	/* Auxiliary vector entry on initial stack */
	long	a_type;		/* Entry type. */
	/* long    pad[(CHERICAP_SIZE / 8) - 1]; */
	union {
		long	a_val;		/* Integer value. */
		struct chericap	a_ptr;	/* Address. */
		/* void	(*a_fcn)(void); */ /* Function pointer (not used). */
       } a_un;
} ElfCheriABI_Auxinfo;

extern struct sysent cheriabi_sysent[];

#if 0
#define SYSCALL32_MODULE(name, offset, new_sysent, evh, arg)   \
static struct syscall_module_data name##_syscall32_mod = {     \
       evh, arg, offset, new_sysent, { 0, NULL }               \
};                                                             \
                                                               \
static moduledata_t name##32_mod = {                           \
       "sys32/" #name,                                         \
       syscall32_module_handler,                               \
       &name##_syscall32_mod                                   \
};                                                             \
DECLARE_MODULE(name##32, name##32_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE)

#define SYSCALL32_MODULE_HELPER(syscallname)            \
static int syscallname##_syscall32 = CHERIABI_SYS_##syscallname; \
static struct sysent syscallname##_sysent32 = {         \
    (sizeof(struct syscallname ## _args )               \
     / sizeof(register_t)),                             \
    (sy_call_t *)& syscallname                          \
};                                                      \
SYSCALL32_MODULE(syscallname,                           \
    & syscallname##_syscall32, & syscallname##_sysent32,\
    NULL, NULL);

#define SYSCALL32_INIT_HELPER(syscallname) {			\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& syscallname,			\
    },								\
    .syscall_no = CHERIABI_SYS_##syscallname			\
}

#define SYSCALL32_INIT_HELPER_COMPAT(syscallname) {		\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& sys_ ## syscallname,		\
    },								\
    .syscall_no = CHERIABI_SYS_##syscallname			\
}

int    syscallcheri_register(int *offset, struct sysent *new_sysent,
	    struct sysent *old_sysent, int flags);
int    syscallcheri_deregister(int *offset, struct sysent *old_sysent);
int    syscallcheri_module_handler(struct module *mod, int what, void *arg);
int    syscallcheri_helper_register(struct syscall_helper_data *sd, int flags);
int    syscallcheri_helper_unregister(struct syscall_helper_data *sd);
#endif

struct iovec_c;
register_t *cheriabi_copyout_strings(struct image_params *imgp);
int	cheriabi_copyiniov(struct iovec_c *iovp, u_int iovcnt,
	    struct iovec **iov, int error);

struct image_args;
int	cheriabi_exec_copyin_args(struct image_args *args, char *fname,
	    enum uio_seg segflg, struct chericap *argv, struct chericap *envv);

int	cheriabi_elf_fixup(register_t **stack_base, struct image_params *imgp);

void	cheriabi_get_signal_stack_capability(struct thread *td,
	    struct chericap *csig);
void	cheriabi_set_signal_stack_capability(struct thread *td,
	    struct chericap *csig);

void	cheriabi_fetch_syscall_arg(struct thread *td, struct chericap *arg,
	    int syscall_no, int argnum);

void	cheriabi_mmap_set_retcap(struct thread *td, struct chericap *retcap,
	    struct chericap *addr, size_t len, int prot, int flags);

#endif /* !_COMPAT_CHERIABI_CHERIABI_UTIL_H_ */
