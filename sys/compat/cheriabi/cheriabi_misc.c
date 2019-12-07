/*-
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2002 Marcel Moolenaar
 * Copyright (c) 2015-2018 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ktrace.h"
#include "opt_posix.h"
#include "opt_capsicum.h"

#define	EXPLICIT_USER_ACCESS

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/capsicum.h>
#include <sys/clock.h>
#include <sys/exec.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/file.h>		/* Must come after sys/malloc.h */
#include <sys/imgact.h>
#include <sys/mbuf.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/procctl.h>
#include <sys/posix4.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/selinfo.h>
#include <sys/eventvar.h>	/* Must come after sys/selinfo.h */
#include <sys/pipe.h>		/* Must come after sys/selinfo.h */
#include <sys/signal.h>
#include <sys/ktrace.h>		/* Must come after sys/signal.h */
#include <sys/signalvar.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/thr.h>
#include <sys/unistd.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/umtx.h>
#include <sys/uuid.h>
#include <sys/vnode.h>
#include <sys/vdso.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#ifdef INET
#include <netinet/in.h>
#endif

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>

#include <machine/cpu.h>
#include <machine/elf.h>

#include <security/audit/audit.h>

#include <cheri/cheri.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_util.h>
#if 0
#include <compat/cheriabi/cheriabi_ipc.h>
#endif
#include <compat/cheriabi/cheriabi_misc.h>
#include <compat/cheriabi/cheriabi_signal.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_syscall.h>

MALLOC_DECLARE(M_KQUEUE);

FEATURE(compat_cheri_abi, "Compatible CHERI system call ABI");

struct sf_hdtr_c {
	struct iovec_c * __capability headers;	/* pointer to an array of header struct iovec's */
	int hdr_cnt;		/* number of header iovec's */
	struct iovec_c * __capability trailers;	/* pointer to an array of trailer struct iovec's */
	int trl_cnt;		/* number of trailer iovec's */
};

#ifdef CHERIABI_NEEDS_UPDATE
CTASSERT(sizeof(struct kevent32) == 20);
CTASSERT(sizeof(struct iovec32) == 8);
#endif

static int cheriabi_kevent_copyout(void *arg, kkevent_t *kevp, int count);
static int cheriabi_kevent_copyin(void *arg, kkevent_t *kevp, int count);

int
cheriabi_wait4(struct thread *td, struct cheriabi_wait4_args *uap)
{

	return (kern_wait4(td, uap->pid, uap->status, uap->options,
	    uap->rusage));
}

int
cheriabi_wait6(struct thread *td, struct cheriabi_wait6_args *uap)
{
	_siginfo_t si, *sip;
	int error;

	if (uap->info != NULL) {
		sip = &si;
		bzero(sip, sizeof(*sip));
	} else
		sip = NULL;
	error = user_wait6(td, uap->idtype, uap->id, uap->status,
	    uap->options, uap->wrusage, sip);
	if (uap->info != NULL && error == 0)
		error = copyout(sip, uap->info, sizeof(*sip));
	return (error);
}

int
cheriabi_execve(struct thread *td, struct cheriabi_execve_args *uap)
{
	struct image_args eargs;
	struct vmspace *oldvmspace;
	int error;

	error = pre_execve(td, &oldvmspace);
	if (error != 0)
		return (error);
	error = exec_copyin_args(&eargs, uap->fname, UIO_USERSPACE,
	    uap->argv, uap->envv);
	if (error == 0)
		error = kern_execve(td, &eargs, NULL);
	post_execve(td, error, oldvmspace);
	return (error);
}

int
cheriabi_fexecve(struct thread *td, struct cheriabi_fexecve_args *uap)
{
	struct image_args eargs;
	struct vmspace *oldvmspace;
	int error;

	error = pre_execve(td, &oldvmspace);
	if (error != 0)
		return (error);
	error = exec_copyin_args(&eargs, NULL, UIO_SYSSPACE,
	    uap->argv, uap->envv);
	if (error == 0) {
		eargs.fd = uap->fd;
		error = kern_execve(td, &eargs, NULL);
	}
	post_execve(td, error, oldvmspace);
	return (error);
}

/*
 * Copy 'count' items into the destination list pointed to by uap->eventlist.
 */
static int
cheriabi_kevent_copyout(void *arg, kkevent_t *kevp, int count)
{
	struct cheriabi_kevent_args *uap;
	int error;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct cheriabi_kevent_args *)arg;

	error = copyoutcap(kevp, uap->eventlist, count * sizeof(*kevp));
	if (error == 0)
		uap->eventlist += count;
	return (error);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
cheriabi_kevent_copyin(void *arg, kkevent_t *kevp, int count)
{
	struct cheriabi_kevent_args *uap;
	int error;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct cheriabi_kevent_args *)arg;

	error = copyincap(uap->changelist, kevp, count * sizeof(*kevp));
	if (error == 0)
		uap->changelist += count;
	return (error);
}

int
cheriabi_kevent(struct thread *td, struct cheriabi_kevent_args *uap)
{
	struct timespec ts, *tsp;
	struct kevent_copyops k_ops = { uap,
					cheriabi_kevent_copyout,
					cheriabi_kevent_copyin};
	int error;


	if (uap->timeout) {
		error = copyin(uap->timeout, &ts, sizeof(ts));
		if (error)
			return (error);
		tsp = &ts;
	} else
		tsp = NULL;
	error = kern_kevent(td, uap->fd, uap->nchanges, uap->nevents,
	    &k_ops, tsp);
	return (error);
}

int
cheriabi_copyinuio(struct iovec_c * __capability iovp, u_int iovcnt,
    struct uio **uiop)
{
	struct iovec *iov;
	struct uio *uio;
	size_t iovlen;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	iovlen = iovcnt * sizeof(struct iovec);
	uio = malloc(iovlen + sizeof(*uio), M_IOV, M_WAITOK);
	iov = (struct iovec *)(uio + 1);
	error = copyincap(iovp, iov, iovlen);
	if (error) {
		free(uio, M_IOV);
		return (error);
	}
	uio->uio_iov = iov;
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > SIZE_MAX - uio->uio_resid) {
			free(uio, M_IOV);
			return (EINVAL);
		}
		uio->uio_resid += iov[i].iov_len;
	}
	*uiop = uio;
	return (0);
}

int
cheriabi_copyiniov(struct iovec_c * __capability iovp_c, u_int iovcnt,
    struct iovec **iovp, int error)
{
	struct iovec *iov;
	u_int iovlen;

	*iovp = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(struct iovec);
	iov = malloc(iovlen, M_IOV, M_WAITOK);
	error = copyincap(iovp_c, iov, iovlen);
	if (error) {
		free(iov, M_IOV);
		return (error);
	}
	*iovp = iov;
	return (0);
}

static int
cheriabi_copyin_hdtr(const struct sf_hdtr_c * __capability uhdtr,
    struct sf_hdtr *hdtr)
{

	return(copyincap(uhdtr, hdtr, sizeof(*hdtr)));
}

int cheriabi_sendfile(struct thread *td, struct cheriabi_sendfile_args *uap)
{

	return (kern_sendfile(td, uap->fd, uap->s, uap->offset, uap->nbytes,
	    uap->hdtr, uap->sbytes, uap->flags, 0,
	    (copyin_hdtr_t *)cheriabi_copyin_hdtr,
	    (copyinuio_t *)cheriabi_copyinuio));
}

int
cheriabi_jail(struct thread *td, struct cheriabi_jail_args *uap)
{
	unsigned int version;
	int error;

	error = copyin(&uap->jailp->version, &version, sizeof(version));
	if (error)
		return (error);

	switch (version) {
	case 0:
	case 1:
		/* These were never supported for CHERI */
		return (EINVAL);

	case 2:	/* JAIL_API_VERSION */
	{
		struct jail_c j;
		/* FreeBSD multi-IPv4/IPv6,noIP jails. */

		error = copyincap(uap->jailp, &j, sizeof(j));
		if (error != 0)
			return (error);
		return (kern_jail(td, j.path, j.hostname, j.jailname,
		    j.ip4, j.ip4s, j.ip6, j.ip6s, UIO_USERSPACE));
	}

	default:
		/* Sci-Fi jails are not supported, sorry. */
		return (EINVAL);
	}
}

int
cheriabi_jail_set(struct thread *td, struct cheriabi_jail_set_args *uap)
{

	return (user_jail_set(td, uap->iovp, uap->iovcnt, uap->flags,
	    (copyinuio_t *)cheriabi_copyinuio));
}

static int
cheriabi_updateiov(const struct uio *uiop, struct iovec_c * __capability iovp)
{
	int i, error;

	for (i = 0; i < uiop->uio_iovcnt; i++) {
		error = suword(&iovp[i].iov_len, uiop->uio_iov[i].iov_len);
		if (error != 0)
			return (error);
	}
	return (0);
}

int
cheriabi_jail_get(struct thread *td, struct cheriabi_jail_get_args *uap)
{

	return (user_jail_get(td, uap->iovp, uap->iovcnt, uap->flags,
	    (copyinuio_t *)cheriabi_copyinuio,
	    (updateiov_t *)cheriabi_updateiov));
}

int
cheriabi_sigreturn(struct thread *td, struct cheriabi_sigreturn_args *uap)
{
	ucontext_c_t uc;
	int error;

	error = copyincap(uap->sigcntxp, &uc, sizeof(uc));
	if (error != 0)
		return (error);

	error = cheriabi_set_mcontext(td, &uc.uc_mcontext);
	if (error != 0)
		return (error);

	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

#define UCC_COPY_SIZE	offsetof(ucontext_c_t, uc_link)

int
cheriabi_getcontext(struct thread *td, struct cheriabi_getcontext_args *uap)
{

	ucontext_c_t uc;

	if (uap->ucp == NULL)
		return (EINVAL);

	bzero(&uc, sizeof(uc));
	cheriabi_get_mcontext(td, &uc.uc_mcontext, GET_MC_CLEAR_RET);
	PROC_LOCK(td->td_proc);
	uc.uc_sigmask = td->td_sigmask;
	PROC_UNLOCK(td->td_proc);
	return (copyoutcap(&uc, uap->ucp, UCC_COPY_SIZE));
}

int
cheriabi_setcontext(struct thread *td, struct cheriabi_setcontext_args *uap)
{
	ucontext_c_t uc;
	int ret;

	if (uap->ucp == NULL)
		return (EINVAL);
	if ((ret = copyincap(uap->ucp, &uc, UCC_COPY_SIZE)) != 0)
		return (ret);
	if ((ret = cheriabi_set_mcontext(td, &uc.uc_mcontext)) != 0)
		return (ret);
	kern_sigprocmask(td, SIG_SETMASK,
	    &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

int
cheriabi_swapcontext(struct thread *td, struct cheriabi_swapcontext_args *uap)
{
	ucontext_c_t uc;
	int ret;

	if (uap->oucp == NULL || uap->ucp == NULL)
		return (EINVAL);

	bzero(&uc, sizeof(uc));
	cheriabi_get_mcontext(td, &uc.uc_mcontext, GET_MC_CLEAR_RET);
	PROC_LOCK(td->td_proc);
	uc.uc_sigmask = td->td_sigmask;
	PROC_UNLOCK(td->td_proc);
	if ((ret = copyoutcap(&uc, uap->oucp, UCC_COPY_SIZE)) != 0)
		return (ret);
	if ((ret = copyincap(uap->ucp, &uc, UCC_COPY_SIZE)) != 0)
		return (ret);
	if ((ret = cheriabi_set_mcontext(td, &uc.uc_mcontext)) != 0)
		return (ret);
	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

int
cheriabi_procctl(struct thread *td, struct cheriabi_procctl_args *uap)
{

	return (user_procctl(td, uap->idtype, uap->id, uap->com, uap->data));
}

int
cheriabi_nmount(struct thread *td, struct cheriabi_nmount_args *uap)
{

	return (kern_nmount(td, uap->iovp, uap->iovcnt, uap->flags,
	    (copyinuio_t *)cheriabi_copyinuio));
}

int
cheriabi_syscall_register(int *offset, struct sysent *new_sysent,
    struct sysent *old_sysent, int flags)
{

	if ((flags & ~SY_THR_STATIC) != 0)
		return (EINVAL);

	if (*offset == NO_SYSCALL) {
		/*
		 * XXX-BD: Supporting dynamic syscalls requires handling
		 * argument registers and uap filling.  Don't allow for now.
		 *
		 * NB: cheriabi_syscall_helper_register() doesn't support
		 * NO_SYSCALL at all.
		 */
		return (EINVAL);
	} else if (*offset < 0 || *offset >= SYS_MAXSYSCALL)
		return (EINVAL);
	else if (cheriabi_sysent[*offset].sy_call != (sy_call_t *)lkmnosys &&
	    cheriabi_sysent[*offset].sy_call != (sy_call_t *)lkmressys)
		return (EEXIST);

	*old_sysent = cheriabi_sysent[*offset];
	cheriabi_sysent[*offset] = *new_sysent;
	atomic_store_rel_32(&cheriabi_sysent[*offset].sy_thrcnt, flags);
	return (0);
}

int
cheriabi_syscall_deregister(int *offset, struct sysent *old_sysent)
{

	if (*offset == 0)
		return (0);

	cheriabi_sysent[*offset] = *old_sysent;
	return (0);
}

int
cheriabi_syscall_helper_register(struct syscall_helper_data *sd, int flags)
{
	struct syscall_helper_data *sd1;
	int error;

	for (sd1 = sd; sd1->syscall_no != NO_SYSCALL; sd1++) {
		error = cheriabi_syscall_register(&sd1->syscall_no, &sd1->new_sysent,
		    &sd1->old_sysent, flags);
		if (error != 0) {
			cheriabi_syscall_helper_unregister(sd);
			return (error);
		}
		sd1->registered = 1;
	}
	return (0);
}

int
cheriabi_syscall_helper_unregister(struct syscall_helper_data *sd)
{
	struct syscall_helper_data *sd1;

	for (sd1 = sd; sd1->registered != 0; sd1++) {
		cheriabi_syscall_deregister(&sd1->syscall_no, &sd1->old_sysent);
		sd1->registered = 0;
	}
	return (0);
}

#define	builducap(base, offset, length, what, perms)            \
    _builducap((base), (offset), (length), (perms), what, __func__, __LINE__)

static void * __capability
_builducap(vaddr_t base, ssize_t offset, size_t length, uint64_t perms,
    const char *what, const char *func, int line)
{
	void *__capability _tmpcap;
	size_t rounded_length = CHERI_REPRESENTABLE_LENGTH(length);
	vaddr_t rounded_base = CHERI_REPRESENTABLE_BASE(base, length);

	if (rounded_length != length)
		printf("%s:%d rounding size of unrepresentable %s from %zd to "
		    "%zd\n", func, line, what, length, rounded_length);
	if (rounded_base != base) {
		printf("%s:%d aligning base of unrepresentable %s from"
		       " 0x%zx to 0x%zx and adjusting offset by %zd\n", func,
		       line, what, base, rounded_base, base - rounded_base);
		/* We have to adjust the offset by the difference */
		offset += base - rounded_base;
	}
	_tmpcap = cheri_capability_build_user_rwx(
	    perms, rounded_base, rounded_length, offset);
	KASSERT(cheri_gettag(_tmpcap),("%s:%d: Created invalid cap "
	     "from base=%zx, offset=%#zx, length=%#zx, perms=%#zx", func,
	     line, base, offset, length, (size_t)(perms)));
	return (_tmpcap);
}

/*
 * XXX: We may want a wrapper of cheri_csetbounds() that warns about
 * capabilities that are overly broad similar to builducap()
 */

static int
sucap(void * __capability uaddr, void * __capability cap)
{

	return (copyoutcap(&cap, uaddr, sizeof(cap)) == 0 ? 0 : -1);
}

/*
 * XXXBD: should check copyout/su* for errors, but punt for now as this
 * function shouldn't be long for the world.
 */
int
cheriabi_copyout_strings(struct image_params *imgp, uintptr_t *stack_base)
{
	int argc, envc;
	void * __capability * __capability vectp;
	char *stringp;
	char * __capability destp;
	struct cheriabi_ps_strings * __capability arginfo;
	char canary[sizeof(long) * 8];
	size_t execpath_len;
	int szsigcode, szps;

	KASSERT(imgp->auxargs != NULL, ("CheriABI requires auxargs"));

	szps = sizeof(pagesizes[0]) * MAXPAGESIZES;
	/*
	 * Calculate string base and vector table pointers.
	 * Also deal with signal trampoline code for this exec type.
	 */
	if (imgp->execpath != NULL)
		execpath_len = strlen(imgp->execpath) + 1;
	else
		execpath_len = 0;
	/* XXX: should be derived from a capability to the strings region */
	arginfo = cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, CHERI_CAP_USER_DATA_BASE,
	    CHERI_CAP_USER_DATA_LENGTH,
	    curproc->p_sysent->sv_psstrings);

	if (imgp->proc->p_sysent->sv_sigcode_base == 0)
		szsigcode = *(imgp->proc->p_sysent->sv_szsigcode);
	else
		szsigcode = 0;
	destp =	(char * __capability)arginfo;

	/*
	 * install sigcode
	 */
	if (szsigcode != 0) {
		destp -= szsigcode;
		destp = __builtin_align_down(destp,
		    sizeof(void * __capability));
		copyout(imgp->proc->p_sysent->sv_sigcode, destp, szsigcode);
	}

	/*
	 * Copy the image path for the rtld.
	 */
	if (execpath_len != 0) {
		destp -= execpath_len;
		imgp->execpathp = cheri_csetbounds(destp, execpath_len);
		copyout(imgp->execpath, destp, execpath_len);
	}

	/*
	 * Prepare the canary for SSP.
	 */
	arc4rand(canary, sizeof(canary), 0);
	destp -= sizeof(canary);
	imgp->canary = cheri_csetbounds(destp, sizeof(canary));
	copyout(canary, destp, sizeof(canary));
	imgp->canarylen = sizeof(canary);

	/*
	 * Prepare the pagesizes array.
	 */
	destp -= szps;
	destp = __builtin_align_down(destp, sizeof(void * __capability));
	imgp->pagesizes = cheri_csetbounds(destp, szps);
	copyout(pagesizes, destp, szps);
	imgp->pagesizeslen = szps;

	destp -= ARG_MAX - imgp->args->stringspace;
	destp = __builtin_align_down(destp, sizeof(void * __capability));

	vectp = (void * __capability * __capability)destp;
	/*
	 * Allocate room on the stack for the ELF auxargs array.  It has
	 * up to AT_COUNT entries.
	 */
	vectp -= AT_COUNT * 2;

	/*
	 * Allocate room for the argv[] and env vectors including the
	 * terminating NULL pointers.
	 */
	vectp -= imgp->args->argc + 1 + imgp->args->envc +1;

	/*
	 * vectp also becomes our initial stack base
	 */
	*stack_base = (__cheri_addr uintptr_t)vectp;

	stringp = imgp->args->begin_argv;
	argc = imgp->args->argc;
	envc = imgp->args->envc;
	/*
	 * Copy out strings - arguments and environment.
	 */
	copyout(stringp, destp, ARG_MAX - imgp->args->stringspace);

	/*
	 * Fill in "ps_strings" struct for ps, w, etc.
	 */
	imgp->argv = cheri_csetbounds(vectp, (argc + 1) * sizeof(*vectp));
	sucap(&arginfo->ps_argvstr, imgp->argv);
	suword32(&arginfo->ps_nargvstr, argc);

	/*
	 * Fill in argument portion of vector table.
	 */
	for (; argc > 0; --argc) {
		sucap(vectp++, cheri_csetbounds(destp, strlen(stringp) + 1));
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* a null vector table pointer separates the argp's from the envp's */
	/* XXX: suword clears the tag */
	suword(vectp++, 0);

	imgp->envv = cheri_csetbounds(vectp, (envc + 1) * sizeof(*vectp));
	sucap(&arginfo->ps_envstr, imgp->envv);
	suword32(&arginfo->ps_nenvstr, envc);

	/*
	 * Fill in environment portion of vector table.
	 */
	for (; envc > 0; --envc) {
		sucap(vectp++, cheri_csetbounds(destp, strlen(stringp) + 1));
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* end of vector table is a null pointer */
	/* XXX: suword clears the tag */
	suword(vectp++, 0);

	if (imgp->auxargs) {
		vectp++;
		imgp->sysent->sv_copyout_auxargs(imgp, (uintcap_t)vectp);
	}

	return (0);
}

#define	AUXARGS_ENTRY_CAP(pos, id, base, offset, len, perm)		\
	AUXARGS_ENTRY_PTR(pos, id, builducap(base, offset, len, #id, perm))

int
cheriabi_copyout_auxargs(struct image_params *imgp, uintcap_t base)
{
	Elf_Auxargs *args = (Elf_Auxargs *)imgp->auxargs;
	Elf_Auxinfo *argarray, *pos;
	unsigned long prog_base, prog_len;
	unsigned long rtld_base, rtld_len;
	int error;

	argarray = pos = malloc(AT_COUNT * sizeof(*pos), M_TEMP,
	    M_WAITOK | M_ZERO);

	/* printf("%s: start=%#lx, end=%#lx, base=%#lx, interp_end=%#lx\n", __func__,
		imgp->start_addr, imgp->end_addr, args->base, imgp->interp_end); */
	prog_base = imgp->start_addr;
	prog_len = imgp->end_addr - prog_base;
	/* Ensure program base and length are representable: */
	prog_base = CHERI_REPRESENTABLE_BASE(prog_base, prog_len);
	prog_len = CHERI_REPRESENTABLE_LENGTH(prog_len);
	KASSERT(prog_len != 0, ("prog_len overflowed: %ld",
	    (long)(imgp->end_addr - imgp->start_addr)));

	if (!imgp->interp_end) {
		imgp->interp_end = imgp->end_addr;
	}
	rtld_base = args->base;
	rtld_len = imgp->interp_end - rtld_base;
	/* Ensure rtld base and length are representable: */
	rtld_base = CHERI_REPRESENTABLE_BASE(rtld_base, rtld_len);
	rtld_len = CHERI_REPRESENTABLE_LENGTH(rtld_len);
	KASSERT(rtld_len != 0, ("rtld_len overflowed: %ld",
	    (long)(imgp->interp_end - args->base)));

	if (args->execfd != -1)
		AUXARGS_ENTRY(pos, AT_EXECFD, args->execfd);
	CTASSERT(CHERI_CAP_USER_CODE_BASE == 0);
	/*
	 * AT_ENTRY gives an executable cap for the whole program and
	 * AT_PHDR a writable one. RTLD is reposible for seting bounds.
	 */
	AUXARGS_ENTRY_CAP(pos, AT_PHDR, prog_base, args->phdr - prog_base,
	    prog_len, CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY(pos, AT_PHENT, args->phent);
	AUXARGS_ENTRY(pos, AT_PHNUM, args->phnum);
	AUXARGS_ENTRY(pos, AT_PAGESZ, args->pagesz);
	AUXARGS_ENTRY(pos, AT_FLAGS, args->flags);
	AUXARGS_ENTRY_CAP(pos, AT_ENTRY, prog_base, args->entry - prog_base,
	    prog_len, CHERI_CAP_USER_CODE_PERMS);
	/*
	 * XXX-BD: grant code and data perms to allow textrel fixups.
	 */
	AUXARGS_ENTRY_CAP(pos, AT_BASE, rtld_base, args->base - rtld_base,
	    rtld_len, CHERI_CAP_USER_DATA_PERMS | CHERI_CAP_USER_CODE_PERMS);
	AUXARGS_ENTRY(pos, AT_EHDRFLAGS, args->hdr_eflags);
	if (imgp->execpathp != 0)
		AUXARGS_ENTRY_PTR(pos, AT_EXECPATH, imgp->execpathp);
	AUXARGS_ENTRY(pos, AT_OSRELDATE,
	    imgp->proc->p_ucred->cr_prison->pr_osreldate);
	if (imgp->canary != 0) {
		AUXARGS_ENTRY_PTR(pos, AT_CANARY, imgp->canary);
		AUXARGS_ENTRY(pos, AT_CANARYLEN, imgp->canarylen);
	}
	AUXARGS_ENTRY(pos, AT_NCPUS, mp_ncpus);
	if (imgp->pagesizes != 0) {
		AUXARGS_ENTRY_PTR(pos, AT_PAGESIZES, imgp->pagesizes);
		AUXARGS_ENTRY(pos, AT_PAGESIZESLEN, imgp->pagesizeslen);
	}
	if (imgp->sysent->sv_timekeep_base != 0) {
		AUXARGS_ENTRY_CAP(pos, AT_TIMEKEEP,
		    imgp->sysent->sv_timekeep_base, 0,
		    sizeof(struct vdso_timekeep) +
		    sizeof(struct vdso_timehands) * VDSO_TH_NUM,
		    CHERI_CAP_USER_DATA_PERMS); /* XXX: readonly? */
	}
	AUXARGS_ENTRY(pos, AT_STACKPROT, imgp->sysent->sv_shared_page_obj
	    != NULL && imgp->stack_prot != 0 ? imgp->stack_prot :
	    imgp->sysent->sv_stackprot);

	AUXARGS_ENTRY(pos, AT_ARGC, imgp->args->argc);
	AUXARGS_ENTRY_PTR(pos, AT_ARGV, imgp->argv);
	AUXARGS_ENTRY(pos, AT_ENVC, imgp->args->envc);
	AUXARGS_ENTRY_PTR(pos, AT_ENVV, imgp->envv);

	AUXARGS_ENTRY_CAP(pos, AT_PS_STRINGS, imgp->sysent->sv_psstrings, 0,
	    sizeof(struct cheriabi_ps_strings), CHERI_CAP_USER_DATA_PERMS);

	AUXARGS_ENTRY(pos, AT_NULL, 0);

	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;

	KASSERT(pos - argarray <= AT_COUNT, ("Too many auxargs"));

	error = copyoutcap(argarray, (void * __capability)base,
	    sizeof(*argarray) * AT_COUNT);
	free(argarray, M_TEMP);
	return (error);
}

int
cheriabi_elf_fixup(uintptr_t *stack_base, struct image_params *imgp)
{

	KASSERT(((vaddr_t)*stack_base & (sizeof(void * __capability) - 1)) == 0,
	    ("*stack_base (%#lx) is not capability aligned", *stack_base));

	return (0);
}

int
cheriabi_mount(struct thread *td, struct cheriabi_mount_args *uap)
{

	return (ENOSYS);
}

int
cheriabi_kenv(struct thread *td, struct cheriabi_kenv_args *uap)
{

	return (kern_kenv(td, uap->what, uap->name, uap->value, uap->len));
}

int
cheriabi_kbounce(struct thread *td, struct cheriabi_kbounce_args *uap)
{
	void * bounce;
	void * __capability dst = uap->dst;
	const void * __capability src = uap->src;
	size_t len = uap->len;
	int flags = uap->flags;
	int error;

	if (len > IOSIZE_MAX)
		return (EINVAL);
	if (flags != 0)
		return (EINVAL);
	if (src == NULL || dst == NULL)
		return (EINVAL);

	bounce = malloc(len, M_TEMP, M_WAITOK | M_ZERO);
	error = copyin(src, bounce, len);
	if (error != 0) {
		printf("%s: error in copyin %d\n", __func__, error);
		goto error;
	}
	error = copyout(bounce, dst, len);
	if (error != 0)
		printf("%s: error in copyout %d\n", __func__, error);
error:
	free(bounce, M_TEMP);
	return (error);
}

/*
 * audit_syscalls.c
 */
int
cheriabi_audit(struct thread *td, struct cheriabi_audit_args *uap)
{

#ifdef	AUDIT
	return (kern_audit(td, uap->record, uap->length));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_auditon(struct thread *td, struct cheriabi_auditon_args *uap)
{

#ifdef	AUDIT
	return (kern_auditon(td, uap->cmd, uap->data, uap->length));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_getauid(struct thread *td, struct cheriabi_getauid_args *uap)
{

#ifdef	AUDIT
	return (kern_getauid(td, uap->auid));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_setauid(struct thread *td, struct cheriabi_setauid_args *uap)
{

#ifdef	AUDIT
	return (kern_setauid(td, uap->auid));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_getaudit(struct thread *td, struct cheriabi_getaudit_args *uap)
{

#ifdef	AUDIT
	return (kern_getaudit(td, uap->auditinfo));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_setaudit(struct thread *td, struct cheriabi_setaudit_args *uap)
{

#ifdef	AUDIT
	return (kern_setaudit(td, uap->auditinfo));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_getaudit_addr(struct thread *td,
    struct cheriabi_getaudit_addr_args *uap)
{

#ifdef	AUDIT
	return (kern_getaudit_addr(td, uap->auditinfo_addr, uap->length));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_setaudit_addr(struct thread *td,
    struct cheriabi_setaudit_addr_args *uap)
{

#ifdef	AUDIT
	return (kern_setaudit_addr(td, uap->auditinfo_addr, uap->length));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_auditctl(struct thread *td, struct cheriabi_auditctl_args *uap)
{

#ifdef	AUDIT
	return (kern_auditctl(td, uap->path));
#else
	return (ENOSYS);
#endif
}


/*
 * kern_acct.c
 */

int
cheriabi_acct(struct thread *td, struct cheriabi_acct_args *uap)
{

	return (kern_acct(td, uap->path));
}

/*
 * kern_fork.c
 */
int
cheriabi_pdfork(struct thread *td, struct cheriabi_pdfork_args *uap)
{

	return (kern_pdfork(td, uap->fdp, uap->flags));
}

/*
 * kern_cpuset.c
 */
int
cheriabi_cpuset(struct thread *td, struct cheriabi_cpuset_args *uap)
{

	return (kern_cpuset(td, uap->setid));
}

int
cheriabi_cpuset_getid(struct thread *td,
    struct cheriabi_cpuset_getid_args *uap)
{

	return (kern_cpuset_getid(td, uap->level, uap->which, uap->id,
	    uap->setid));
}

int
cheriabi_cpuset_getaffinity(struct thread *td,
    struct cheriabi_cpuset_getaffinity_args *uap)
{

	return (kern_cpuset_getaffinity(td, uap->level, uap->which,
	    uap->id, uap->cpusetsize, uap->mask));
}

int
cheriabi_cpuset_setaffinity(struct thread *td,
    struct cheriabi_cpuset_setaffinity_args *uap)
{

	return (kern_cpuset_setaffinity(td, uap->level, uap->which, uap->id,
	    uap->cpusetsize, uap->mask));
}

int
cheriabi_cpuset_getdomain(struct thread *td,
    struct cheriabi_cpuset_getdomain_args *uap)
{

	return (kern_cpuset_getdomain(td, uap->level, uap->which,
	    uap->id, uap->domainsetsize, uap->mask, uap->policy));
}

int
cheriabi_cpuset_setdomain(struct thread *td,
    struct cheriabi_cpuset_setdomain_args *uap)
{

	return (kern_cpuset_setdomain(td, uap->level, uap->which,
	    uap->id, uap->domainsetsize, uap->mask, uap->policy));
}

/*
 * kern_descrip.c
 */
int
cheriabi_fcntl(struct thread *td, struct cheriabi_fcntl_args *uap)
{

	return (kern_fcntl_freebsd(td, uap->fd, uap->cmd, uap->arg));
}

int
cheriabi_fstat(struct thread *td, struct cheriabi_fstat_args *uap)
{

	return (user_fstat(td, uap->fd, uap->sb));
}

/*
 * kern_ktrace.c
 */

int
cheriabi_ktrace(struct thread *td, struct cheriabi_ktrace_args *uap)
{

	return (kern_ktrace(td, uap->fname, uap->ops, uap->facs, uap->pid));
}

int
cheriabi_utrace(struct thread *td, struct cheriabi_utrace_args *uap)
{

	return (kern_utrace(td, uap->addr, uap->len));
}

/*
 * kern_linker.c
 */

int
cheriabi_kldload(struct thread *td, struct cheriabi_kldload_args *uap)
{

	return (user_kldload(td, uap->file));
}

int
cheriabi_kldfind(struct thread *td, struct cheriabi_kldfind_args *uap)
{

	return (kern_kldfind(td, uap->file));
}

int
cheriabi_kldstat(struct thread *td, struct cheriabi_kldstat_args *uap)
{
        struct kld_file_stat stat;
        struct kld_file_stat_c stat_c;
        int error, version;

        error = copyin(&uap->stat->version, &version, sizeof(version));
	if (error != 0)
                return (error);
        if (version != sizeof(struct kld_file_stat_c))
                return (EINVAL);

        error = kern_kldstat(td, uap->fileid, &stat);
        if (error != 0)
                return (error);

        bcopy(&stat.name[0], &stat_c.name[0], sizeof(stat.name));
        CP(stat, stat_c, refs);
        CP(stat, stat_c, id);
	stat_c.address = (void * __capability)(intcap_t)stat.address;
        CP(stat, stat_c, size);
        bcopy(&stat.pathname[0], &stat_c.pathname[0], sizeof(stat.pathname));
        return (copyout(&stat_c, uap->stat, version));
}

int
cheriabi_kldsym(struct thread *td, struct cheriabi_kldsym_args *uap)
{
	struct kld_sym_lookup_c lookup;
	int error;

	error = copyincap(uap->data, &lookup, sizeof(lookup));
	if (error != 0)
		return (error);
	if (lookup.version != sizeof(lookup) ||
	    uap->cmd != KLDSYM_LOOKUP)
		return (EINVAL);
	error = kern_kldsym(td, uap->fileid, uap->cmd, lookup.symname,
	    &lookup.symvalue, &lookup.symsize);
	if (error != 0)
		return (error);
	error = copyoutcap(&lookup, uap->data, sizeof(lookup));

	return (error);
}

/*
 * kern_loginclass.c
 */
int
cheriabi_getloginclass(struct thread *td,
    struct cheriabi_getloginclass_args *uap)
{

	return (kern_getloginclass(td, uap->namebuf, uap->namelen));
}

int
cheriabi_setloginclass(struct thread *td,
    struct cheriabi_setloginclass_args *uap)
{

	return (kern_setloginclass(td, uap->namebuf));
}

int
cheriabi_uuidgen(struct thread *td, struct cheriabi_uuidgen_args *uap)
{

	return (user_uuidgen(td, uap->store, uap->count));
}

/*
 * kern_module.c
 */
int
cheriabi_modfind(struct thread *td, struct cheriabi_modfind_args *uap)
{

	return (kern_modfind(td, uap->name));
}

int
cheriabi_modstat(struct thread *td, struct cheriabi_modstat_args *uap)
{

	return (kern_modstat(td, uap->modid, uap->stat));
}

/*
 * kern_prot.c
 */
int
cheriabi_getgroups(struct thread *td, struct cheriabi_getgroups_args *uap)
{

	return (kern_getgroups(td, uap->gidsetsize, uap->gidset));
}

int
cheriabi_setgroups(struct thread *td, struct cheriabi_setgroups_args *uap)
{

	return (user_setgroups(td, uap->gidsetsize, uap->gidset));
}

int
cheriabi_getresuid(struct thread *td, struct cheriabi_getresuid_args *uap)
{

	return (kern_getresuid(td, uap->ruid, uap->euid, uap->suid));
}

int
cheriabi_getresgid(struct thread *td, struct cheriabi_getresgid_args *uap)
{

	return (kern_getresgid(td, uap->rgid, uap->egid, uap->sgid));
}

int
cheriabi_getlogin(struct thread *td, struct cheriabi_getlogin_args *uap)
{

	return (kern_getlogin(td, uap->namebuf, uap->namelen));
}

int
cheriabi_setlogin(struct thread *td, struct cheriabi_setlogin_args *uap)
{

	return (kern_setlogin(td, uap->namebuf));
}

/*
 * kern_rctl.h
 */
int
cheriabi_rctl_get_racct(struct thread *td,
    struct cheriabi_rctl_get_racct_args *uap)
{

#ifdef RCTL
	return (kern_rctl_get_racct(td, uap->inbufp, uap->inbuflen,
	    uap->outbufp, uap->outbuflen));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_rctl_get_rules(struct thread *td,
    struct cheriabi_rctl_get_rules_args *uap)
{

#ifdef RCTL
	return (kern_rctl_get_rules(td, uap->inbufp, uap->inbuflen,
	    uap->outbufp, uap->outbuflen));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_rctl_get_limits(struct thread *td,
    struct cheriabi_rctl_get_limits_args *uap)
{

#ifdef RCTL
	return (kern_rctl_get_limits(td, uap->inbufp, uap->inbuflen,
	    uap->outbufp, uap->outbuflen));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_rctl_add_rule(struct thread *td,
    struct cheriabi_rctl_add_rule_args *uap)
{

#ifdef RCTL
	return (kern_rctl_add_rule(td, uap->inbufp, uap->inbuflen,
	    uap->outbufp, uap->outbuflen));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_rctl_remove_rule(struct thread *td,
    struct cheriabi_rctl_remove_rule_args *uap)
{

#ifdef RCTL
	return (kern_rctl_remove_rule(td, uap->inbufp, uap->inbuflen,
	    uap->outbufp, uap->outbuflen));
#else
	return (ENOSYS);
#endif
}

/*
 * kern_resource.h
 */
int
cheriabi_rtprio_thread(struct thread *td,
    struct cheriabi_rtprio_thread_args *uap)
{

	return (kern_rtprio_thread(td, uap->function, uap->lwpid,
	    uap->rtp));
}

int
cheriabi_rtprio(struct thread *td, struct cheriabi_rtprio_args *uap)
{

	return (kern_rtprio(td, uap->function, uap->pid, uap->rtp));
}

int
cheriabi_setrlimit(struct thread *td, struct cheriabi___setrlimit_args *uap)
{
	struct rlimit alim;
	int error;

	error = copyin(uap->rlp, &alim, sizeof(struct rlimit));
	if (error != 0)
		return (error);
	return (kern_setrlimit(td, uap->which, &alim));
}

int
cheriabi_getrlimit(struct thread *td, struct cheriabi___getrlimit_args *uap)
{
	struct rlimit rlim;
	int error;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	lim_rlimit(td, uap->which, &rlim);
	error = copyout(&rlim, uap->rlp, sizeof(struct rlimit));
	return (error);
}

int
cheriabi_getrusage(struct thread *td, struct cheriabi_getrusage_args *uap)
{
	struct rusage ru;
	int error;

	error = kern_getrusage(td, uap->who, &ru);
	if (error == 0)
		error = copyout(&ru, uap->rusage, sizeof(struct rusage));
	return (error);
}

/*
 * kern_sysctl.c
 */

int
cheriabi___sysctl(struct thread *td, struct cheriabi___sysctl_args *uap)
{

	return (kern_sysctl(td, uap->name, uap->namelen, uap->old,
	    uap->oldlenp, uap->new, uap->newlen, SCTL_CHERIABI));
}

int
cheriabi___sysctlbyname(struct thread *td,
    struct cheriabi___sysctlbyname_args *uap)
{
	size_t rv;
	int error;

	error = kern___sysctlbyname(td, uap->name, uap->namelen, uap->old,
	    uap->oldlenp, uap->new, uap->newlen, &rv, 0, 0);
	if (error != 0)
		return (error);
	if (uap->oldlenp != NULL)
		error = copyout(&rv, uap->oldlenp, sizeof(rv));

	return (error);
}

/*
 * kern_thr.c
 */

struct thr_create_initthr_args_c {
	ucontext_c_t ctx;
	long * __capability tid;
};

static int
cheriabi_thr_create_initthr(struct thread *td, void *thunk)
{
	struct thr_create_initthr_args_c *args;

	args = thunk;
	if (args->tid != NULL && suword(args->tid, td->td_tid) != 0)
		return (EFAULT);

	return (cheriabi_set_mcontext(td, &args->ctx.uc_mcontext));
}

int
cheriabi_thr_create(struct thread *td, struct cheriabi_thr_create_args *uap)
{
	struct thr_create_initthr_args_c args;
	int error;

	if ((error = copyincap(uap->ctx, &args.ctx, sizeof(args.ctx))))
		return (error);
	args.tid = uap->id;
	return (thread_create(td, NULL, cheriabi_thr_create_initthr, &args));
}

static int
cheriabi_thr_new_initthr(struct thread *td, void *thunk)
{
	struct thr_param_c *param = thunk;

	if ((param->child_tid != NULL &&
	    suword(param->child_tid, td->td_tid)) ||
	    (param->parent_tid != NULL &&
	    suword(param->parent_tid, td->td_tid)))
		return (EFAULT);
	cheriabi_set_threadregs(td, param);
	return (cheriabi_set_user_tls(td, param->tls_base));
}

int
cheriabi_thr_self(struct thread *td, struct cheriabi_thr_self_args *uap)
{
	int error;

	error = suword(uap->id, td->td_tid);
	if (error == -1)
		return (EFAULT);
	return (0);
}

int
cheriabi_thr_exit(struct thread *td, struct cheriabi_thr_exit_args *uap)
{

	umtx_thread_exit(td);

	/* Signal userland that it can free the stack. */
	if (uap->state != NULL) {
		suword(uap->state, 1);
		kern_umtx_wake(td, uap->state, INT_MAX, 0);
	}

	return (kern_thr_exit(td));
}

int
cheriabi_thr_suspend(struct thread *td, struct cheriabi_thr_suspend_args *uap)
{
	struct timespec ts, *tsp;
	int error;

	tsp = NULL;
	if (uap->timeout != NULL) {
		error = umtx_copyin_timeout(uap->timeout, &ts);
		if (error != 0)
			return (error);
		tsp = &ts;
	}

	return (kern_thr_suspend(td, tsp));
}

int
cheriabi_thr_set_name(struct thread *td, struct cheriabi_thr_set_name_args *uap)
{

	return (kern_thr_set_name(td, uap->id, uap->name));
}

int
cheriabi_thr_new(struct thread *td, struct cheriabi_thr_new_args *uap)
{
	struct thr_param_c param_c;
	struct rtprio rtp, *rtpp;
	int error;

	if (uap->param_size != sizeof(struct thr_param_c))
		return (EINVAL);

	error = copyincap(uap->param, &param_c, uap->param_size);
	if (error != 0)
		return (error);

	if (param_c.rtp != NULL) {
		error = copyin(param_c.rtp, &rtp, sizeof(struct rtprio));
		if (error)
			return (error);
		rtpp = &rtp;
	} else
		rtpp = NULL;
	return (thread_create(td, rtpp, cheriabi_thr_new_initthr, &param_c));
}

#ifdef _KPOSIX_PRIORITY_SCHEDULING
/*
 * p1003_1b.c
 */
int
cheriabi_sched_setparam(struct thread *td,
    struct cheriabi_sched_setparam_args * uap)
{

	return (user_sched_setparam(td, uap->pid, uap->param));
}

int
cheriabi_sched_getparam(struct thread *td,
    struct cheriabi_sched_getparam_args *uap)
{

	return (user_sched_getparam(td, uap->pid, uap->param));
}

int
cheriabi_sched_setscheduler(struct thread *td,
    struct cheriabi_sched_setscheduler_args *uap)
{

	return (user_sched_setscheduler(td, uap->pid, uap->policy, uap->param));
}

int
cheriabi_sched_rr_get_interval(struct thread *td,
    struct cheriabi_sched_rr_get_interval_args *uap)
{

	return (user_sched_rr_get_interval(td, uap->pid, uap->interval));
}

#else /* !_KPOSIX_PRIORITY_SCHEDULING */
CHERIABI_SYSCALL_NOT_PRESENT_GEN(sched_setparam)
CHERIABI_SYSCALL_NOT_PRESENT_GEN(sched_getparam)
CHERIABI_SYSCALL_NOT_PRESENT_GEN(sched_setscheduler)
CHERIABI_SYSCALL_NOT_PRESENT_GEN(sched_rr_get_interval)
#endif /* !_KPOSIX_PRIORITY_SCHEDULING */

/*
 * subr_profil.c
 */

int
cheriabi_profil(struct thread *td, struct cheriabi_profil_args *uap)
{

	return (kern_profil(td, uap->samples, uap->size, uap->offset,
	    uap->scale));
}

/*
 * vm/swap_pager.c
 */

int
cheriabi_swapon(struct thread *td, struct cheriabi_swapon_args *uap)
{

	return (kern_swapon(td, uap->name));
}

int
cheriabi_swapoff(struct thread *td, struct cheriabi_swapoff_args *uap)
{

	return (kern_swapoff(td, uap->name));
}

/*
 * sys_capability.c
 */
#ifdef CAPABILITIES
int
cheriabi_cap_getmode(struct thread *td, struct cheriabi_cap_getmode_args *uap)
{

	return (kern_cap_getmode(td, uap->modep));
}

int
cheriabi_cap_rights_limit(struct thread *td,
   struct cheriabi_cap_rights_limit_args *uap)
{

	return (user_cap_rights_limit(td, uap->fd, uap->rightsp));
}

int
cheriabi___cap_rights_get(struct thread *td,
    struct cheriabi___cap_rights_get_args *uap)
{

	return (kern_cap_rights_get(td, uap->version, uap->fd, uap->rightsp));
}

int
cheriabi_cap_ioctls_limit(struct thread *td,
    struct cheriabi_cap_ioctls_limit_args *uap)
{

	return (user_cap_ioctls_limit(td, uap->fd, uap->cmds, uap->ncmds));
}

int
cheriabi_cap_ioctls_get(struct thread *td,
    struct cheriabi_cap_ioctls_get_args *uap)
{

	return (kern_cap_ioctls_get(td, uap->fd, uap->cmds, uap->maxcmds));
}

int
cheriabi_cap_fcntls_get(struct thread *td,
   struct cheriabi_cap_fcntls_get_args *uap)
{

	return (kern_cap_fcntls_get(td, uap->fd, uap->fcntlrightsp));
}
#else /* !CAPABILITIES */
int
cheriabi_cap_getmode(struct thread *td, struct cheriabi_cap_getmode_args *uap)
{

	return (ENOSYS);
}

int
cheriabi_cap_rights_limit(struct thread *td,
   struct cheriabi_cap_rights_limit_args *uap)
{

	return (ENOSYS);
}

int
cheriabi___cap_rights_get(struct thread *td,
    struct cheriabi___cap_rights_get_args *uap)
{

	return (ENOSYS);
}

int
cheriabi_cap_ioctls_limit(struct thread *td,
    struct cheriabi_cap_ioctls_limit_args *uap)
{

	return (ENOSYS);
}

int
cheriabi_cap_ioctls_get(struct thread *td,
    struct cheriabi_cap_ioctls_get_args *uap)
{

	return (ENOSYS);
}

int
cheriabi_cap_fcntls_get(struct thread *td,
   struct cheriabi_cap_fcntls_get_args *uap)
{

	return (ENOSYS);
}
#endif /* !CAPABILITIES */

/*
 * sys_getrandom.c
 */
int
cheriabi_getrandom(struct thread *td, struct cheriabi_getrandom_args *uap)
{

	return (kern_getrandom(td, uap->buf, uap->buflen, uap->flags));
}

/*
 * sys_pipe.c
 */
int
cheriabi_pipe2(struct thread *td, struct cheriabi_pipe2_args *uap)
{

	return (kern_pipe2(td, uap->fildes, uap->flags));
}

/*
 * sys_procdesc.c
 */

int
cheriabi_pdgetpid(struct thread *td, struct cheriabi_pdgetpid_args *uap)
{

	return (user_pdgetpid(td, uap->fd, uap->pidp));
}

/*
 * sys_process.c
 */
int
cheriabi_ptrace(struct thread *td, struct cheriabi_ptrace_args *uap)
{
	union {
		struct ptrace_io_desc_c piod;
		struct ptrace_lwpinfo pl;
		struct ptrace_vm_entry_c pve;
#if __has_feature(capabilities)
		struct capreg capreg;
#endif
		struct dbreg dbreg;
		struct fpreg fpreg;
		struct reg reg;
		syscallarg_t args[nitems(td->td_sa.args)];
		struct ptrace_sc_ret psr;
		int ptevents;
	} r = { 0 };

	union {
		struct ptrace_lwpinfo_c pl;
	} c = { 0 };

	int error = 0, data;
	void * __capability addr = &r;

	AUDIT_ARG_PID(uap->pid);
	AUDIT_ARG_CMD(uap->req);
	AUDIT_ARG_VALUE(uap->data);

	(void)c;
	data = uap->data;

	switch (uap->req) {
	/* If we're supposed to ignore user parameters... */
	case PT_ATTACH:
	case PT_DETACH:
	case PT_KILL:
	case PT_TRACE_ME:
	case PT_FOLLOW_FORK:
		addr = NULL;
		break;

	/* No preparatory work to do for most fetch operations */
	case PT_GET_EVENT_MASK:
	case PT_GETREGS:
	case PT_GETFPREGS:
	case PT_GETDBREGS:
#if __has_feature(capabilities)
	case PT_GETCAPREGS:
#endif
	case PT_GETNUMLWPS:
	case PT_GET_SC_ARGS:
	case PT_GET_SC_RET:
	case PT_LWP_EVENTS:
	case PT_SUSPEND:
		break;

	case PT_LWPINFO:
		if (uap->data > sizeof(c.pl))
			error = EINVAL;
		else
			data = sizeof(r.pl);
		break;

	/* Pass along an untagged virtual address for the desired PC. */
	case PT_CONTINUE:
	case PT_STEP:
	case PT_TO_SCE:
	case PT_TO_SCX:
	case PT_SYSCALL:
		addr = cheri_cleartag(uap->addr);
		break;

	/* Pass along 'addr' unmodified. */
	case PT_GETLWPLIST:
		addr = uap->addr;
		break;

#if __has_feature(capabilities)
	/*
	 * XXXNWF Prohibited at the moment, because we have no sane way of
	 * conveying tags through the kernel.
	 */
	case PT_SETCAPREGS:
		error = EINVAL;
		break;
#endif

	/* Several set operations just move data through the kernel */
	case PT_SETREGS:
		error = copyin(uap->addr, &r.reg, sizeof r.reg);
		break;
	case PT_SETFPREGS:
		error = copyin(uap->addr, &r.fpreg, sizeof r.fpreg);
		break;
	case PT_SETDBREGS:
		error = copyin(uap->addr, &r.dbreg, sizeof r.dbreg);
		break;
	case PT_SET_EVENT_MASK:
		if (uap->data != sizeof(r.ptevents))
			error = EINVAL;
		else
			error = copyin(uap->addr, &r.ptevents, uap->data);
		break;

	case PT_IO:
		error = copyincap(uap->addr, (char *)&r.piod, sizeof(r.piod));
		break;
	case PT_VM_ENTRY:
		error = copyincap(uap->addr, (char *)&r.pve, sizeof r.pve);
		break;

#if 0
	case PT_READ_I:
	case PT_READ_D:
	case PT_WRITE_I:
	case PT_WRITE_D:
		// XXX TODO
		break;
	default:
		addr = uap->addr;
		break;
#endif
	default:
		/* XXXNWF */
		error = EINVAL;
		break;
	}

	if (error)
		return (error);

	error = kern_ptrace(td, uap->req, uap->pid, addr, data);
	if (error)
		return (error);

	switch (uap->req) {
#if 0
	case PT_VM_ENTRY:
		error = COPYOUT(&r.pve, uap->addr, sizeof r.pve);
		break;
#endif
	case PT_IO:
		/*
		 * Only copy out the updated piod_len to avoid the use
		 * of copyoutcap.
		 */
		error = copyout(&r.piod.piod_len, uap->addr +
		    offsetof(struct ptrace_io_desc_c, piod_len),
		    sizeof(r.piod.piod_len));
		break;
#if 0
	case PT_GETREGS:
		error = COPYOUT(&r.reg, uap->addr, sizeof r.reg);
		break;
	case PT_GETFPREGS:
		error = COPYOUT(&r.fpreg, uap->addr, sizeof r.fpreg);
		break;
	case PT_GETDBREGS:
		error = COPYOUT(&r.dbreg, uap->addr, sizeof r.dbreg);
		break;
#if __has_feature(capabilities)
	case PT_GETCAPREGS:
		error = COPYOUT(&r.capreg, uap->addr, sizeof r.capreg);
		break;
#endif
#endif
	case PT_GET_EVENT_MASK:
		/* NB: The size in uap->data is validated in kern_ptrace(). */
		error = copyout(&r.ptevents, uap->addr, uap->data);
		break;
	case PT_LWPINFO:
		memset(&c.pl, 0, sizeof(c.pl));
		c.pl.pl_lwpid = r.pl.pl_lwpid;
		c.pl.pl_event = r.pl.pl_event;
		c.pl.pl_flags = r.pl.pl_flags;
		c.pl.pl_sigmask = r.pl.pl_sigmask;
		c.pl.pl_siglist = r.pl.pl_siglist;
		c.pl.pl_child_pid = r.pl.pl_child_pid;
		c.pl.pl_syscall_code = r.pl.pl_syscall_code;
		c.pl.pl_syscall_narg = r.pl.pl_syscall_narg;
		memcpy(c.pl.pl_tdname, r.pl.pl_tdname, sizeof(c.pl.pl_tdname));
		siginfo_native_to_siginfo(&r.pl.pl_siginfo,
		    (_siginfo_t *)&c.pl.pl_siginfo);

		error = copyout(&c.pl, uap->addr, uap->data);
		break;
	case PT_GET_SC_ARGS:
		error = copyout(r.args, uap->addr, MIN(uap->data,
		    sizeof(r.args)));
		break;
	case PT_GET_SC_RET:
		error = copyout(&r.psr, uap->addr, MIN(uap->data,
		    sizeof(r.psr)));
		break;
	default:
		break;
	}

	return (error);
}
