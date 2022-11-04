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
#include <cheri/cherireg.h>

/*
 * Canonical C-language representation of a CHERI object capability -- code and
 * data capabilities in registers or memory.
 */
struct cheri_object {
	void * __capability	co_codecap;
	void * __capability	co_datacap;
};

#if !defined(_KERNEL) && __has_feature(capabilities)
#define	CHERI_OBJECT_INIT_NULL	{NULL, NULL}
#define	CHERI_OBJECT_ISNULL(co)	\
    ((co).co_codecap == NULL && (co).co_datacap == NULL)
#endif

#ifdef _KERNEL
/*
 * Functions to construct userspace capabilities.
 */
void * __capability	_cheri_capability_build_user_code(struct thread *td,
			    uint32_t perms, ptraddr_t basep, size_t length,
			    off_t off, const char* func, int line);
void * __capability	_cheri_capability_build_user_data(uint32_t perms,
			    ptraddr_t basep, size_t length, off_t off,
			    const char* func, int line, bool exact);
void * __capability	_cheri_capability_build_user_rwx(uint32_t perms,
			    ptraddr_t basep, size_t length, off_t off,
			    const char* func, int line, bool exact);
void * __capability	_cheri_capability_build_user_rwx_unchecked(
			    uint32_t perms, ptraddr_t basep, size_t length,
			    off_t off, const char* func, int line, bool exact);
#define cheri_capability_build_user_code(td, perms, basep, length, off)	\
	_cheri_capability_build_user_code(td, perms, basep, length, off,\
	    __func__, __LINE__)
#define cheri_capability_build_user_data(perms, basep, length, off)	\
	_cheri_capability_build_user_data(perms, basep, length, off,	\
	    __func__, __LINE__, true)
#define cheri_capability_build_inexact_user_data(perms, basep, length, off) \
	_cheri_capability_build_user_data(perms, basep, length, off,	\
	    __func__, __LINE__, false)
#define cheri_capability_build_user_rwx(perms, basep, length, off)	\
	_cheri_capability_build_user_rwx(perms, basep, length, off,	\
	    __func__, __LINE__, true)
#define cheri_capability_build_user_rwx_unchecked(perms, basep, length, off) \
	_cheri_capability_build_user_rwx_unchecked(perms, basep, length, off, \
	    __func__, __LINE__, true)

/*
 * Global capabilities used to construct other capabilities.
 */

/* Root of all unsealed userspace capabilities. */
extern void * __capability userspace_root_cap;

/* Root of all sealed userspace capabilities. */
extern void * __capability userspace_root_sealcap;

/*
 * Omnipotent capability for restoring swapped capabilities.
 *
 * XXXBD: These should be a way to do this without storing such a potent
 * capability.  Splitting sealed and unsealed caps would be a start.
 */
extern void * __capability swap_restore_cap;

#ifdef __CHERI_PURE_CAPABILITY__
/* Root kernel capability */
extern void * __capability kernel_root_cap;
#endif

/* Root of all sealed kernel capabilities. */
extern void * __capability kernel_root_sealcap;

/*
 * Capabilities used for colocation.
 */
extern void * __capability switcher_sealcap;
extern void * __capability switcher_sealcap2;

/*
 * Functions to create capabilities used in exec.
 */
struct image_params;
struct thread;
void * __capability cheri_exec_pcc(struct thread *td,
	    struct image_params *imgp);
void * __capability cheri_sigcode_capability(struct thread *td);

/*
 * CHERI context management functions.
 */
const char	*cheri_exccode_string(uint8_t exccode);
int	cheri_syscall_authorize(struct thread *td, u_int code,
	    int nargs, syscallarg_t *args);

/*
 * Functions to manage object types.
 */
otype_t	cheri_otype_alloc(void);
void	cheri_otype_free(otype_t);

/*
 * Functions involving tagged memory.
 */
void	cheri_read_tags_page(const void *page, void *tagbuf, bool *hastagsp);

/*
 * Global sysctl definitions.
 */
SYSCTL_DECL(_security_cheri);
SYSCTL_DECL(_security_cheri_stats);
extern u_int	security_cheri_debugger_on_sandbox_signal;
extern u_int	security_cheri_debugger_on_sandbox_syscall;
extern u_int	security_cheri_debugger_on_sandbox_unwind;
extern u_int	security_cheri_sandboxed_signals;
extern u_int	security_cheri_syscall_violations;
extern u_int	security_cheri_bound_legacy_capabilities;
extern u_int	cheri_cloadtags_stride;

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * Used by the kernel linker to handle caprelocs in modules.
 */
typedef void (cap_relocs_cb)(void *arg, bool function, bool constant,
    ptraddr_t object, void **src);

void	init_linker_file_cap_relocs(const void *start_relocs,
	    const void *stop_relocs, void *data_cap, ptraddr_t base_addr,
	    cap_relocs_cb *cb, void *cb_arg);
#endif

/*
 * Functions to manage IPC between coprocesses.
 */
struct trapframe;
void	colocation_cleanup(struct thread *td);
void	colocation_get_peer(struct thread *td, struct thread **peertdp);
void	colocation_thread_exit(struct thread *td);
void	colocation_unborrow(struct thread *td);
bool	colocation_trap_in_switcher(struct thread *td,
	    struct trapframe *trapframe, const char *msg);
void	colocation_update_tls(struct thread *td);
void	db_print_scb_td(struct thread *td);
#endif /* !_KERNEL */

/*
 * Nested include of machine-dependent definitions.
 */
#include <machine/cheri.h>

#endif /* _SYS_CHERI_H_ */
// CHERI CHANGES START
// {
//   "updated": 20200803,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
