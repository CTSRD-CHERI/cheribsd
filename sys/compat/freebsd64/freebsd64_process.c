/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1994, Sean Eric Fagan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Sean Eric Fagan.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/abi_compat.h>
#include <sys/systm.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/ptrace.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/malloc.h>
#include <sys/signalvar.h>

#include <machine/reg.h>

#include <security/audit/audit.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include <compat/freebsd64/freebsd64.h>
#include <compat/freebsd64/freebsd64_proto.h>

struct ptrace_io_desc64 {
	int		piod_op;	/* I/O operation */
	uint64_t	piod_offs;	/* child offset */
	uint64_t	piod_addr;	/* parent offset */
	uint64_t	piod_len;	/* request length */
};

struct ptrace_sc_ret64 {
	uint64_t	sr_retval[2];	/* Only valid if sr_error == 0. */
	int		sr_error;
};

struct ptrace_vm_entry64 {
	int		pve_entry;	/* Entry number used for iteration. */
	int		pve_timestamp;	/* Generation number of VM map. */
	uint64_t	pve_start;	/* Start VA of range. */
	uint64_t	pve_end;	/* End VA of range (incl). */
	uint64_t	pve_offset;	/* Offset in backing object. */
	u_int		pve_prot;	/* Protection of memory range. */
	u_int		pve_pathlen;	/* Size of path. */
	int64_t		pve_fileid;	/* File ID. */
	uint32_t	pve_fsid;	/* File system ID. */
	uint64_t	pve_path;	/* Path name of object. */
};

static void
ptrace_lwpinfo_to64(const struct ptrace_lwpinfo *pl,
    struct ptrace_lwpinfo64 *pl64)
{

	bzero(pl64, sizeof(*pl64));
	pl64->pl_lwpid = pl->pl_lwpid;
	pl64->pl_event = pl->pl_event;
	pl64->pl_flags = pl->pl_flags;
	pl64->pl_sigmask = pl->pl_sigmask;
	pl64->pl_siglist = pl->pl_siglist;
	siginfo_to_siginfo64(&pl->pl_siginfo, &pl64->pl_siginfo);
	strcpy(pl64->pl_tdname, pl->pl_tdname);
	pl64->pl_child_pid = pl->pl_child_pid;
	pl64->pl_syscall_code = pl->pl_syscall_code;
	pl64->pl_syscall_narg = pl->pl_syscall_narg;
}

static void
ptrace_sc_ret_to64(const struct ptrace_sc_ret *psr,
    struct ptrace_sc_ret64 *psr64)
{

	bzero(psr64, sizeof(*psr64));
	psr64->sr_retval[0] = (__cheri_addr uint64_t)psr->sr_retval[0];
	psr64->sr_retval[1] = (__cheri_addr uint64_t)psr->sr_retval[1];
	psr64->sr_error = psr->sr_error;
}

/*
 * Process debugging system call.
 */
#ifndef _SYS_SYSPROTO_H_
struct ptrace_args {
	int	req;
	pid_t	pid;
	caddr_t	addr;
	int	data;
};
#endif

int
freebsd64_ptrace(struct thread *td, struct freebsd64_ptrace_args *uap)
{
	/*
	 * XXX this obfuscation is to reduce stack usage, but the register
	 * structs may be too large to put on the stack anyway.
	 */
	union {
		struct ptrace_io_desc piod;
		struct ptrace_lwpinfo pl;
		struct ptrace_vm_entry pve;
		struct ptrace_coredump pc;
#if __has_feature(capabilities)
		struct capreg capreg;
#endif
		struct dbreg dbreg;
		struct fpreg fpreg;
		struct reg reg;
		struct iovec vec;
		syscallarg_t args[nitems(td->td_sa.args)];
		struct ptrace_sc_ret psr;
		int ptevents;
	} r;
	union {
		struct ptrace_io_desc64 piod;
		struct ptrace_lwpinfo64 pl;
		struct ptrace_vm_entry64 pve;
		uint64_t args[nitems(td->td_sa.args)];
		struct ptrace_sc_ret64 psr;
		struct iovec64 vec;
	} r64;
	void * __capability addr;
	int data, error, i;

	if (!allow_ptrace)
		return (ENOSYS);
	error = 0;

	AUDIT_ARG_PID(uap->pid);
	AUDIT_ARG_CMD(uap->req);
	AUDIT_ARG_VALUE(uap->data);
	addr = &r;
	data = uap->data;
	switch (uap->req) {
	case PT_GET_EVENT_MASK:
	case PT_GET_SC_ARGS:
	case PT_GET_SC_RET:
		break;
	case PT_LWPINFO:
		if (uap->data > sizeof(r64.pl))
			return (EINVAL);

		/*
		 * Pass size of native structure in 'data'.  Truncate
		 * if necessary to avoid siginfo.
		 */
		data = sizeof(r.pl);
		if (uap->data < offsetof(struct ptrace_lwpinfo64, pl_siginfo) +
		    sizeof(struct siginfo64))
			data = offsetof(struct ptrace_lwpinfo, pl_siginfo);
		break;
	case PT_GETLWPLIST:
		if (uap->data <= 0) {
			error = EINVAL;
			break;
		}
		addr = __USER_CAP(uap->addr, uap->data * sizeof(lwpid_t));
		break;
	case PT_GETREGS:
		bzero(&r.reg, sizeof r.reg);
		break;
	case PT_GETFPREGS:
		bzero(&r.fpreg, sizeof r.fpreg);
		break;
#if __has_feature(capabilities)
	case PT_GETCAPREGS:
		bzero(&r.capreg, sizeof r.capreg);
		break;
#endif
	case PT_GETDBREGS:
		bzero(&r.dbreg, sizeof r.dbreg);
		break;
	case PT_SETREGS:
		error = copyin(__USER_CAP(uap->addr, sizeof(r.reg)), &r.reg,
		    sizeof r.reg);
		break;
	case PT_SETFPREGS:
		error = copyin(__USER_CAP(uap->addr, sizeof(r.fpreg)), &r.fpreg,
		    sizeof r.fpreg);
		break;
	case PT_SETDBREGS:
		error = copyin(__USER_CAP(uap->addr, sizeof(r.dbreg)), &r.dbreg,
		    sizeof r.dbreg);
		break;
#if __has_feature(capabilities)
	case PT_SETCAPREGS:
		error = copyin(__USER_CAP(uap->addr, sizeof(r.capreg)),
		    &r.capreg, sizeof r.capreg);
		break;
#endif
	case PT_GETREGSET:
	case PT_SETREGSET:
		error = copyin(__USER_CAP(uap->addr, sizeof(r64.vec)), &r64.vec,
		    sizeof(r64.vec));
		if (error != 0)
			break;
		IOVEC_INIT_C(&r.vec, __USER_CAP(r64.vec.iov_base,
		    r64.vec.iov_len), r64.vec.iov_len);
		break;
	case PT_SET_EVENT_MASK:
		if (uap->data != sizeof(r.ptevents))
			error = EINVAL;
		else
			error = copyin(__USER_CAP(uap->addr, uap->data),
			    &r.ptevents, uap->data);
		break;
	case PT_IO:
		error = copyin(__USER_CAP(uap->addr, sizeof(r64.piod)),
		    &r64.piod, sizeof(r64.piod));
		if (error)
			break;
		CP(r64.piod, r.piod, piod_op);
		r.piod.piod_offs =
		    (void * __capability)(uintcap_t)r64.piod.piod_offs;
		r.piod.piod_addr = __USER_CAP(r64.piod.piod_addr,
		    r64.piod.piod_len);
		CP(r64.piod, r.piod, piod_len);
		break;
	case PT_VM_ENTRY:
		error = copyin(__USER_CAP(uap->addr, sizeof(r64.pve)),
		    &r64.pve, sizeof(r64.pve));
		if (error)
			break;

		CP(r64.pve, r.pve, pve_entry);
		CP(r64.pve, r.pve, pve_timestamp);
		CP(r64.pve, r.pve, pve_start);
		CP(r64.pve, r.pve, pve_end);
		CP(r64.pve, r.pve, pve_offset);
		CP(r64.pve, r.pve, pve_prot);
		CP(r64.pve, r.pve, pve_pathlen);
		CP(r64.pve, r.pve, pve_fileid);
		CP(r64.pve, r.pve, pve_fsid);
		r.pve.pve_path = __USER_CAP(r64.pve.pve_path,
		    r64.pve.pve_pathlen);
		break;
	case PT_COREDUMP:
		if (uap->data != sizeof(r.pc))
			error = EINVAL;
		else
			error = copyin(__USER_CAP(uap->addr, uap->data), &r.pc,
			    uap->data);
		break;
	default:
		addr = __USER_CAP_UNBOUND(uap->addr);
		break;
	}
	if (error)
		return (error);

	error = kern_ptrace(td, uap->req, uap->pid, addr, data);
	if (error)
		return (error);

	switch (uap->req) {
	case PT_VM_ENTRY:
		CP(r.pve, r64.pve, pve_entry);
		CP(r.pve, r64.pve, pve_timestamp);
		CP(r.pve, r64.pve, pve_start);
		CP(r.pve, r64.pve, pve_end);
		CP(r.pve, r64.pve, pve_offset);
		CP(r.pve, r64.pve, pve_prot);
		CP(r.pve, r64.pve, pve_pathlen);
		CP(r.pve, r64.pve, pve_fileid);
		CP(r.pve, r64.pve, pve_fsid);
		error = copyout(&r64.pve, __USER_CAP(uap->addr, sizeof(r64.pve)),
		    sizeof(r64.pve));
		break;
	case PT_IO:
		CP(r.piod, r64.piod, piod_len);
		error = copyout(&r64.piod,
		    __USER_CAP(uap->addr, sizeof(r64.piod)), sizeof(r64.piod));
		break;
	case PT_GETREGS:
		error = copyout(&r.reg, __USER_CAP(uap->addr, sizeof(r.reg)),
		    sizeof r.reg);
		break;
	case PT_GETFPREGS:
		error = copyout(&r.fpreg, __USER_CAP(uap->addr, sizeof(r.fpreg)),
		    sizeof r.fpreg);
		break;
	case PT_GETDBREGS:
		error = copyout(&r.dbreg, __USER_CAP(uap->addr, sizeof(r.dbreg)),
		    sizeof r.dbreg);
		break;
#if __has_feature(capabilities)
	case PT_GETCAPREGS:
		error = copyout(&r.capreg, __USER_CAP(uap->addr,
		    sizeof(r.capreg)), sizeof r.capreg);
		break;
#endif
	case PT_GETREGSET:
		r64.vec.iov_len = r.vec.iov_len;
		error = copyout(&r64.vec, __USER_CAP(uap->addr,
		    sizeof(r64.vec)), sizeof(r64.vec));
		break;
	case PT_GET_EVENT_MASK:
		/* NB: The size in uap->data is validated in kern_ptrace(). */
		error = copyout(&r.ptevents, __USER_CAP(uap->addr, uap->data),
		    uap->data);
		break;
	case PT_LWPINFO:
		ptrace_lwpinfo_to64(&r.pl, &r64.pl);
		error = copyout(&r64.pl, __USER_CAP(uap->addr, uap->data),
		    uap->data);
		break;
	case PT_GET_SC_ARGS:
		for (i = 0; i < nitems(r.args); i++)
			r64.args[i] = (__cheri_addr uint64_t)r.args[i];
		error = copyout(r64.args, __USER_CAP(uap->addr, uap->data),
		    MIN(uap->data, sizeof(r64.args)));
		break;
	case PT_GET_SC_RET:
		ptrace_sc_ret_to64(&r.psr, &r64.psr);
		error = copyout(&r64.psr, __USER_CAP(uap->addr, uap->data),
		    MIN(uap->data, sizeof(r64.psr)));
		break;
	}

	return (error);
}
