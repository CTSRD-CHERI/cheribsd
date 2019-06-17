/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
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

#ifndef _SYS_CHERI_H_
#define	_SYS_CHERI_H_

#ifdef _KERNEL
#include <sys/sysctl.h>		/* SYSCTL_DECL() */
#endif

#include <sys/types.h>

#include <machine/cherireg.h>	/* CHERICAP_SIZE. */

/*
 * Canonical C-language representation of a capability for compilers that
 * don't support capabilities directly.  The in-memory layout is sensitive to
 * the microarchitecture, and hence treated as opaque.  Fields must be
 * accessed via the ISA.
 */
struct chericap {
	uint8_t		c_data[CHERICAP_SIZE];
} __packed __aligned(CHERICAP_SIZE);

/*
 * Canonical C-language representation of a CHERI object capability -- code and
 * data capabilities in registers or memory.
 */
struct cheri_object {
#if !defined(_KERNEL) && __has_feature(capabilities)
	void * __capability	co_codecap;
	void * __capability	co_datacap;
#else
	struct chericap		 co_codecap;
	struct chericap		 co_datacap;
#endif
};

#if !defined(_KERNEL) && __has_feature(capabilities)
#define	CHERI_OBJECT_INIT_NULL	{NULL, NULL}
#define	CHERI_OBJECT_ISNULL(co)	\
    ((co).co_codecap == NULL && (co).co_datacap == NULL)
#endif

/*
 * Data structure describing CHERI's sigaltstack-like extensions to signal
 * delivery.  In the event that a thread takes a signal when $pcc doesn't hold
 * CHERI_PERM_SYSCALL, we will need to install new $pcc, $ddc, $csp, and $idc
 * state, and move execution to the per-thread alternative stack, whose
 * pointer should (presumably) be relative to the $ddc/$csp defined here.
 */
struct cheri_signal {
#if __has_feature(capabilities)
	void * __capability	csig_pcc;
	void * __capability	csig_ddc;
	void * __capability	csig_csp;
	void * __capability	csig_idc;
	void * __capability	csig_default_stack;
	void * __capability	csig_sigcode;
#else
	struct chericap		 csig_pcc;
	struct chericap		 csig_ddc;
	struct chericap		 csig_csp;
	struct chericap		 csig_idc;
	struct chericap		 csig_default_stack;
	struct chericap		 csig_sigcode;
#endif
};

/*
 * APIs that act on C language representations of capabilities -- but not
 * capabilities themselves.
 */
#ifdef _KERNEL
void * __capability	_cheri_capability_build_user_code(uint32_t perms,
			    vaddr_t basep, size_t length, off_t off,
			    const char* func, int line);
void * __capability	_cheri_capability_build_user_data(uint32_t perms,
			    vaddr_t basep, size_t length, off_t off,
			    const char* func, int line);
void * __capability	_cheri_capability_build_user_rwx(uint32_t perms,
			    vaddr_t basep, size_t length, off_t off,
			    const char* func, int line);
#define cheri_capability_build_user_code(perms, basep, length, off)	\
	_cheri_capability_build_user_code(perms, basep, length, off,	\
	    __func__, __LINE__)
#define cheri_capability_build_user_data(perms, basep, length, off)	\
	_cheri_capability_build_user_data(perms, basep, length, off,	\
	    __func__, __LINE__)
#define cheri_capability_build_user_rwx(perms, basep, length, off)	\
	_cheri_capability_build_user_rwx(perms, basep, length, off,	\
	    __func__, __LINE__)

/*
 * CHERI context management functions.
 */
struct cheri_frame;
struct thread;
struct trapframe;
const char	*cheri_exccode_string(uint8_t exccode);
void	cheri_exec_setregs(struct thread *td, u_long entry_addr);
void	cheri_log_cheri_frame(struct trapframe *frame);
void	cheri_log_exception(struct trapframe *frame, int trap_type);
void	cheri_log_exception_registers(struct trapframe *frame);
void	cheri_newthread_setregs(struct thread *td, u_long entry_addr);
int	cheri_syscall_authorize(struct thread *td, u_int code,
	    int nargs, syscallarg_t *args);
int	cheri_signal_sandboxed(struct thread *td);
void	cheri_trapframe_from_cheriframe(struct trapframe *frame,
	    struct cheri_frame *cfp);
void	_cheri_trapframe_to_cheriframe(struct trapframe *frame,
	    struct cheri_frame *cfp, bool strip_tags);
#define	cheri_trapframe_to_cheriframe(tf, cf)			\
	_cheri_trapframe_to_cheriframe((tf), (cf), false)
#define	cheri_trapframe_to_cheriframe_strip(tf, cf)		\
	_cheri_trapframe_to_cheriframe((tf), (cf), true)
void	hybridabi_sendsig(struct thread *td);

/*
 * Functions to set up and manipulate CHERI contexts and stacks.
 */
struct pcb;
struct proc;
struct sysarch_args;
void	cheri_sealcap_copy(struct proc *dst, struct proc *src);
void	cheri_signal_copy(struct pcb *dst, struct pcb *src);
int	cheri_sysarch_getsealcap(struct thread *td, void * __capability ucap);
int	cheri_sysarch_getstack(struct thread *td, struct sysarch_args *uap);
int	cheri_sysarch_setstack(struct thread *td, struct sysarch_args *uap);

/*
 * Functions to manage object types.
 */
otype_t	cheri_otype_alloc(void);
void	cheri_otype_free(otype_t);

/*
 * Global sysctl definitions.
 */
SYSCTL_DECL(_security_cheri);
SYSCTL_DECL(_security_cheri_stats);
extern u_int	security_cheri_debugger_on_sandbox_signal;
extern u_int	security_cheri_debugger_on_sandbox_syscall;
extern u_int	security_cheri_debugger_on_sandbox_unwind;
extern u_int	security_cheri_debugger_on_sigprot;
extern u_int	security_cheri_sandboxed_signals;
extern u_int	security_cheri_syscall_violations;
extern u_int	security_cheri_bound_legacy_capabilities;

/*
 * Functions exposed to machine-independent code that must interact with
 * CHERI-specific features; e.g., ktrace.
 */
struct ktr_ccall;
struct ktr_creturn;
struct ktr_cexception;
struct thr_param_c;
void	ktrccall_mdfill(struct pcb *pcb, struct ktr_ccall *kc);
void	ktrcreturn_mdfill(struct pcb *pcb, struct ktr_creturn *kr);
void	ktrcexception_mdfill(struct trapframe *frame,
	    struct ktr_cexception *ke);
#endif /* !_KERNEL */

/*
 * Nested include of machine-dependent definitions, which likely depend on
 * first having defined chericap.h.
 */
#include <machine/cheri.h>

#endif /* _SYS_CHERI_H_ */
