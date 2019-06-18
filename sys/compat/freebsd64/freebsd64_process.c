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
#include <sys/systm.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/pioctl.h>
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

#include <compat/freebsd64/freebsd64_proto.h>

static ssize_t
proc_iop(struct thread *td, struct proc *p, vm_offset_t va, void *buf,
    size_t len, enum uio_rw rw)
{
	kiovec_t iov;
	struct uio uio;
	ssize_t slen;

	MPASS(len < SSIZE_MAX);
	slen = (ssize_t)len;

	IOVEC_INIT(&iov, buf, len);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = va;
	uio.uio_resid = slen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = rw;
	uio.uio_td = td;
	proc_rwmem(p, &uio);
	if (uio.uio_resid == slen)
		return (-1);
	return (slen - uio.uio_resid);
}

static int
ptrace_vm_entry(struct thread *td, struct proc *p,
		kptrace_vm_entry_t * __capability pve)
{
	struct vattr vattr;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t obj, tobj, lobj;
	struct vmspace *vm;
	struct vnode *vp;
	char *freepath, *fullpath;
	u_int pathlen;
	int error, index;

	error = 0;
	obj = NULL;

	vm = vmspace_acquire_ref(p);
	map = &vm->vm_map;
	vm_map_lock_read(map);

	do {
		entry = map->header.next;
		index = 0;
		while (index < pve->pve_entry && entry != &map->header) {
			entry = entry->next;
			index++;
		}
		if (index != pve->pve_entry) {
			error = EINVAL;
			break;
		}
		KASSERT((map->header.eflags & MAP_ENTRY_IS_SUB_MAP) == 0,
		    ("Submap in map header"));
		while ((entry->eflags & MAP_ENTRY_IS_SUB_MAP) != 0) {
			entry = entry->next;
			index++;
		}
		if (entry == &map->header) {
			error = ENOENT;
			break;
		}

		/* We got an entry. */
		pve->pve_entry = index + 1;
		pve->pve_timestamp = map->timestamp;
		pve->pve_start = entry->start;
		pve->pve_end = entry->end - 1;
		pve->pve_offset = entry->offset;
		pve->pve_prot = entry->protection;

		/* Backing object's path needed? */
		if (pve->pve_pathlen == 0)
			break;

		pathlen = pve->pve_pathlen;
		pve->pve_pathlen = 0;

		obj = entry->object.vm_object;
		if (obj != NULL)
			VM_OBJECT_RLOCK(obj);
	} while (0);

	vm_map_unlock_read(map);

	pve->pve_fsid = VNOVAL;
	pve->pve_fileid = VNOVAL;

	if (error == 0 && obj != NULL) {
		lobj = obj;
		for (tobj = obj; tobj != NULL; tobj = tobj->backing_object) {
			if (tobj != obj)
				VM_OBJECT_RLOCK(tobj);
			if (lobj != obj)
				VM_OBJECT_RUNLOCK(lobj);
			lobj = tobj;
			pve->pve_offset += tobj->backing_object_offset;
		}
		vp = vm_object_vnode(lobj);
		if (vp != NULL)
			vref(vp);
		if (lobj != obj)
			VM_OBJECT_RUNLOCK(lobj);
		VM_OBJECT_RUNLOCK(obj);

		if (vp != NULL) {
			freepath = NULL;
			fullpath = NULL;
			vn_fullpath(td, vp, &fullpath, &freepath);
			vn_lock(vp, LK_SHARED | LK_RETRY);
			if (VOP_GETATTR(vp, &vattr, td->td_ucred) == 0) {
				pve->pve_fileid = vattr.va_fileid;
				pve->pve_fsid = vattr.va_fsid;
			}
			vput(vp);

			if (fullpath != NULL) {
				pve->pve_pathlen = strlen(fullpath) + 1;
				if (pve->pve_pathlen <= pathlen) {
#if __has_feature(capabilities)
					error = copyout_c(fullpath,
						pve->pve_path,
						pve->pve_pathlen);
#else
					error = copyout(fullpath, pve->pve_path,
					    pve->pve_pathlen);
#endif
				} else
					error = ENAMETOOLONG;
			}
			if (freepath != NULL)
				free(freepath, M_TEMP);
		}
	}
	vmspace_free(vm);
	if (error == 0)
		CTR3(KTR_PTRACE, "PT_VM_ENTRY: pid %d, entry %d, start %p",
		    p->p_pid, pve->pve_entry, pve->pve_start);

	return (error);
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

#define	BZERO(a, s)		bzero(a, s)
#define	COPYIN(u, k, s)		copyin(u, k, s)
#define	COPYOUT(k, u, s)	copyout(k, u, s)
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
		kptrace_vm_entry_t pve;
#ifdef CPU_CHERI
		struct capreg capreg;
#endif
		struct dbreg dbreg;
		struct fpreg fpreg;
		struct reg reg;
		char args[sizeof(td->td_sa.args)];
		int ptevents;
	} r;
	void * __capability addr;
	int error = 0;
	AUDIT_ARG_PID(uap->pid);
	AUDIT_ARG_CMD(uap->req);
	AUDIT_ARG_VALUE(uap->data);
	addr = &r;
	switch (uap->req) {
	case PT_GET_EVENT_MASK:
	case PT_LWPINFO:
	case PT_GET_SC_ARGS:
		break;
	case PT_GETREGS:
		BZERO(&r.reg, sizeof r.reg);
		break;
	case PT_GETFPREGS:
		BZERO(&r.fpreg, sizeof r.fpreg);
		break;
#ifdef CPU_CHERI
	case PT_GETCAPREGS:
		BZERO(&r.capreg, sizeof r.capreg);
		break;
#endif
	case PT_GETDBREGS:
		BZERO(&r.dbreg, sizeof r.dbreg);
		break;
	case PT_SETREGS:
		error = COPYIN(uap->addr, &r.reg, sizeof r.reg);
		break;
	case PT_SETFPREGS:
		error = COPYIN(uap->addr, &r.fpreg, sizeof r.fpreg);
		break;
	case PT_SETDBREGS:
		error = COPYIN(uap->addr, &r.dbreg, sizeof r.dbreg);
		break;
#ifdef CPU_CHERI
	case PT_SETCAPREGS:
		error = COPYIN(uap->addr, &r.capreg, sizeof r.capreg);
		break;
#endif
	case PT_SET_EVENT_MASK:
		if (uap->data != sizeof(r.ptevents))
			error = EINVAL;
		else
			error = copyin(uap->addr, &r.ptevents, uap->data);
		break;
	case PT_IO:
		error = COPYIN(uap->addr, &r.piod, sizeof r.piod);
		break;
	case PT_VM_ENTRY:
#if __has_feature(capabilities)
	{
		struct ptrace_vm_entry pve;
		error = COPYIN(uap->addr, &pve, sizeof pve);
		if (error)
			break;

		r.pve.pve_entry     = pve.pve_entry;
		r.pve.pve_timestamp = pve.pve_timestamp;
		r.pve.pve_start     = pve.pve_start;
		r.pve.pve_end       = pve.pve_end;
		r.pve.pve_offset    = pve.pve_offset;
		r.pve.pve_prot      = pve.pve_prot;
		r.pve.pve_pathlen   = pve.pve_pathlen;
		r.pve.pve_fileid    = pve.pve_fileid;
		r.pve.pve_fsid      = pve.pve_fsid;
		r.pve.pve_path      = (void * __capability)(intcap_t)pve.pve_path;
	}
#else
		error = COPYIN(uap->addr, &r.pve, sizeof r.pve);
#endif
		break;
	default:
		addr = (__cheri_tocap void * __capability)uap->addr;
		break;
	}
	if (error)
		return (error);

	error = kern_ptrace(td, uap->req, uap->pid, addr, uap->data);
	if (error)
		return (error);

	switch (uap->req) {
	case PT_VM_ENTRY:
		error = COPYOUT(&r.pve, uap->addr, sizeof r.pve);
		break;
	case PT_IO:
		error = COPYOUT(&r.piod, uap->addr, sizeof r.piod);
		break;
	case PT_GETREGS:
		error = COPYOUT(&r.reg, uap->addr, sizeof r.reg);
		break;
	case PT_GETFPREGS:
		error = COPYOUT(&r.fpreg, uap->addr, sizeof r.fpreg);
		break;
	case PT_GETDBREGS:
		error = COPYOUT(&r.dbreg, uap->addr, sizeof r.dbreg);
		break;
#ifdef CPU_CHERI
	case PT_GETCAPREGS:
		error = COPYOUT(&r.capreg, uap->addr, sizeof r.capreg);
		break;
#endif
	case PT_GET_EVENT_MASK:
		/* NB: The size in uap->data is validated in kern_ptrace(). */
		error = copyout(&r.ptevents, uap->addr, uap->data);
		break;
	case PT_LWPINFO:
		/* NB: The size in uap->data is validated in kern_ptrace(). */
		error = copyout(&r.pl, uap->addr, uap->data);
		break;
	case PT_GET_SC_ARGS:
		error = copyout(r.args, uap->addr, MIN(uap->data,
		    sizeof(r.args)));
		break;
	}

	return (error);
}
#undef COPYIN
#undef COPYOUT
#undef BZERO

