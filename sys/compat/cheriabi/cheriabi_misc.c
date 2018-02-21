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

#include "opt_compat.h"
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ktrace.h"
#include "opt_posix.h"

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
#include <compat/cheriabi/cheriabi_misc.h>
#endif
#include <compat/cheriabi/cheriabi_signal.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_syscall.h>
#include <compat/cheriabi/cheriabi_sysargmap.h>

#include <sys/cheriabi.h>

MALLOC_DECLARE(M_KQUEUE);

FEATURE(compat_cheri_abi, "Compatible CHERI system call ABI");

#ifdef CHERIABI_NEEDS_UPDATE
CTASSERT(sizeof(struct kevent32) == 20);
CTASSERT(sizeof(struct iovec32) == 8);
#endif

SYSCTL_NODE(_compat, OID_AUTO, cheriabi, CTLFLAG_RW, 0, "CheriABI mode");
static SYSCTL_NODE(_compat_cheriabi, OID_AUTO, mmap, CTLFLAG_RW, 0, "mmap");

static int	cheriabi_mmap_honor_prot = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, honor_prot,
    CTLFLAG_RWTUN, &cheriabi_mmap_honor_prot, 0,
    "Reduce returned permissions to those requested by the prot argument.");
static int	cheriabi_mmap_setbounds = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, setbounds,
    CTLFLAG_RWTUN, &cheriabi_mmap_setbounds, 0,
    "Set bounds on returned capabilities.");
int	cheriabi_mmap_precise_bounds = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, precise_bounds,
    CTLFLAG_RWTUN, &cheriabi_mmap_precise_bounds, 0,
    "Require that bounds on returned capabilities be precise.");

static int cheriabi_kevent_copyout(void *arg, struct kevent *kevp, int count);
static int cheriabi_kevent_copyin(void *arg, struct kevent *kevp, int count);
static register_t cheriabi_mmap_prot2perms(int prot);

int
cheriabi_syscall(struct thread *td, struct cheriabi_syscall_args *uap)
{

	/*
	 * With generated uap fill functions, we'd have to alter the pcb
	 * to support syscalls with integer arguments.  In practice, it
	 * looks like we only really need fork (for libthr).
	 */
	switch (uap->number) {
	case CHERIABI_SYS_fork:
		return (sys_fork(td, NULL));
	default:
		return (EINVAL);
	}
}

int
cheriabi_wait4(struct thread *td, struct cheriabi_wait4_args *uap)
{

	return (kern_wait4(td, uap->pid, uap->status, uap->options,
	    uap->rusage));
}

int
cheriabi_wait6(struct thread *td, struct cheriabi_wait6_args *uap)
{
	struct __wrusage wru, *wrup;
	struct siginfo_c si_c;
	struct __siginfo si, *sip;
	int error, status;

	if (uap->wrusage != NULL)
		wrup = &wru;
	else
		wrup = NULL;
	if (uap->info != NULL) {
		sip = &si;
		bzero(sip, sizeof(*sip));
	} else
		sip = NULL;
	error = kern_wait6(td, uap->idtype, uap->id, &status, uap->options,
	    wrup, sip);
	if (error != 0)
		return (error);
	if (uap->status != NULL)
		error = copyout_c(&status, uap->status, sizeof(status));
	if (uap->wrusage != NULL && error == 0)
		error = copyout_c(&wru, uap->wrusage, sizeof(wru));
	if (uap->info != NULL && error == 0) {
		siginfo_to_siginfo_c (&si, &si_c);
		error = copyout_c(&si_c, uap->info, sizeof(si_c));
	}
	return (error);
}

/*
 * Custom version of exec_copyin_args() so that we can translate
 * the pointers.
 */
int
cheriabi_exec_copyin_args(struct image_args *args, const char *fname,
    enum uio_seg segflg, void * __capability *argv, void * __capability *envv)
{
	char *argp, *envp;
	void * __capability *pcap;
	void * __capability *argcap;
	size_t length;
	int error, tag;

	argcap = NULL;

	bzero(args, sizeof(*args));
	if (argv == NULL)
		return (EFAULT);

	/*
	 * Allocate demand-paged memory for the file name, argument, and
	 * environment strings.
	 */
	error = exec_alloc_args(args);
	if (error != 0)
		return (error);

	/*
	 * XXX: Work around not being able to store capabilities to the stack
	 * and use the allocated buffer instead.
	 */
	argcap = (void * __capability *)args->buf;
	/*
	 * Copy the file name.
	 */
	if (fname != NULL) {
		args->fname = args->buf + sizeof(void * __capability);
		error = (segflg == UIO_SYSSPACE) ?
		    copystr(fname, args->fname, PATH_MAX, &length) :
		    copyinstr(fname, args->fname, PATH_MAX, &length);
		if (error != 0)
			goto err_exit;
	} else
		length = 0;

	args->begin_argv = args->buf + sizeof(void * __capability) + length;
	args->endp = args->begin_argv;
	args->stringspace = ARG_MAX;

	/*
	 * extract arguments first
	 */
	pcap = argv;
	for (;;) {
		error = copyincap(pcap++, argcap, sizeof(*argcap));
		if (error)
			goto err_exit;
		tag = cheri_gettag(*argcap);
		if (!tag)
			break;
		error = cheriabi_strcap_to_ptr(&argp, *argcap, 0);
		if (error)
			goto err_exit;
		/* Lose any stray caps in arg strings. */
		error = copyinstr(argp, args->endp, args->stringspace, &length);
		if (error) {
			if (error == ENAMETOOLONG)
				error = E2BIG;
			goto err_exit;
		}
		args->stringspace -= length;
		args->endp += length;
		args->argc++;
	}

	args->begin_envv = args->endp;

	/*
	 * extract environment strings
	 */
	if (envv) {
		pcap = envv;
		for (;;) {
			error = copyincap(pcap++, argcap, sizeof(*argcap));
			if (error)
				goto err_exit;
			tag = cheri_gettag(*argcap);
			if (!tag)
				break;
			error = cheriabi_strcap_to_ptr(&envp, *argcap, 0);
			if (error)
				goto err_exit;
			/* Lose any stray caps in env strings. */
			error = copyinstr(envp, args->endp, args->stringspace,
			    &length);
			if (error) {
				if (error == ENAMETOOLONG)
					error = E2BIG;
				goto err_exit;
			}
			args->stringspace -= length;
			args->endp += length;
			args->envc++;
		}
	}

	return (0);

err_exit:
	exec_free_args(args);
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
	error = cheriabi_exec_copyin_args(&eargs, uap->fname, UIO_USERSPACE,
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
	error = cheriabi_exec_copyin_args(&eargs, NULL, UIO_SYSSPACE,
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
cheriabi_kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct cheriabi_kevent_args *uap;
	struct kevent_c	ks_c[KQ_NEVENTS];
	int i, j, error = 0;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct cheriabi_kevent_args *)arg;

	for (i = 0; i < count; i++) {
		CP(kevp[i], ks_c[i], filter);
		CP(kevp[i], ks_c[i], flags);
		CP(kevp[i], ks_c[i], fflags);
		CP(kevp[i], ks_c[i], data);
		for (j = 0; j < nitems(kevp->ext); j++)
			CP(kevp[i], ks_c[i], ext[j]);

		/*
		 * Retrieve the ident and udata capabilities stashed by
		 * cheriabi_kevent_copyin().
		 */
		void * __capability * udata = kevp[i].udata;
		ks_c[i].ident = (__intcap_t)udata[0];
		ks_c[i].udata = udata[1];
	}
	error = copyoutcap_c(&ks_c[0], uap->eventlist, count * sizeof(*ks_c));
	if (error == 0)
		uap->eventlist += count;
	return (error);
}

void *
cheriabi_build_kevent_udata(__intcap_t ident, void * __capability udata)
{
	void * __capability * newudata;

	newudata = malloc(2*sizeof(void * __capability), M_KQUEUE, M_WAITOK);
	newudata[0] = (void * __capability)ident;
	newudata[1] = udata;

	return (newudata);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
cheriabi_kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct cheriabi_kevent_args *uap;
	struct kevent_c	ks_c[KQ_NEVENTS];
	int error, i, j;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct cheriabi_kevent_args *)arg;

	error = copyincap_c(uap->changelist, &ks_c[0], count * sizeof(*ks_c));
	if (error)
		goto done;
	uap->changelist += count;

	for (i = 0; i < count; i++) {
		/*
		 * XXX-BD: this is quite awkward.  ident could be anything.
		 * If it's a capabilty, we'll hang on to it in udata.
		 */
		if (cheri_gettag((void * __capability)ks_c[i].ident)) {
			if (!(cheri_getperm((void * __capability)ks_c[i].ident)
			    | CHERI_PERM_GLOBAL))
				return (EPROT);
		}
		kevp[i].ident = (uintptr_t)(__uintcap_t)ks_c[i].ident;
		CP(ks_c[i], kevp[i], filter);
		CP(ks_c[i], kevp[i], flags);
		CP(ks_c[i], kevp[i], fflags);
		CP(ks_c[i], kevp[i], data);
		for (j = 0; j < nitems(kevp->ext); j++)
			CP(ks_c[i], kevp[i], ext[j]);

		if (ks_c[i].flags & EV_DELETE)
			continue;

		if (cheri_gettag(ks_c[i].udata)) {
			if (!(cheri_getperm(ks_c[i].udata) & CHERI_PERM_GLOBAL))
				return (EPROT);
		}
		/*
		 * We stash the real ident and udata capabilities in
		 * a malloced array in udata.
		 */
		kevp[i].udata = cheriabi_build_kevent_udata(ks_c[i].ident,
		    ks_c[i].udata);
	}
done:
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
		error = copyin_c(uap->timeout, &ts, sizeof(ts));
		if (error)
			return (error);
		tsp = &ts;
	} else
		tsp = NULL;
	error = kern_kevent(td, uap->fd, uap->nchanges, uap->nevents,
	    &k_ops, tsp);
	return (error);
}

static int
cheriabi_copyinuio(struct iovec_c * __capability iovp, u_int iovcnt,
    struct uio **uiop)
{
	kiovec_t * __capability iov;
	struct uio *uio;
	size_t iovlen;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	iovlen = iovcnt * sizeof(kiovec_t);
	uio = malloc(iovlen + sizeof(*uio), M_IOV, M_WAITOK);
	iov = (__cheri_tocap kiovec_t * __capability)(kiovec_t *)(uio + 1);
	error = copyincap_c(iovp, iov, iovlen);
	if (error) {
		free(uio, M_IOV);
		return (error);
	}
	uio->uio_iov = (__cheri_fromcap kiovec_t *)iov;
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
cheriabi_readv(struct thread *td, struct cheriabi_readv_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_readv(td, uap->fd, auio);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_writev(struct thread *td, struct cheriabi_writev_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_writev(td, uap->fd, auio);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_preadv(struct thread *td, struct cheriabi_preadv_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_preadv(td, uap->fd, auio, uap->offset);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_pwritev(struct thread *td, struct cheriabi_pwritev_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_pwritev(td, uap->fd, auio, uap->offset);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_copyiniov(struct iovec_c * __capability iovp_c, u_int iovcnt,
    kiovec_t **iovp, int error)
{
	kiovec_t *iov;
	u_int iovlen;

	*iovp = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(kiovec_t);
	iov = malloc(iovlen, M_IOV, M_WAITOK);
	error = copyincap_c(iovp_c,
	    (__cheri_tocap kiovec_t * __capability)iov, iovlen);
	if (error) {
		free(iov, M_IOV);
		return (error);
	}
	*iovp = iov;
	return (0);
}

static int
cheriabi_do_sendfile(struct thread *td,
    struct cheriabi_sendfile_args *uap)
{
	struct sf_hdtr_c hdtr_c;
	struct uio *hdr_uio, *trl_uio;
	struct file *fp;
	cap_rights_t rights;
	off_t offset, sbytes;
	int error;

	offset = uap->offset;
	if (offset < 0)
		return (EINVAL);

	hdr_uio = trl_uio = NULL;

	if (uap->hdtr != NULL) {
		error = copyincap(uap->hdtr, &hdtr_c, sizeof(hdtr_c));
		if (error)
			goto out;

		if (hdtr_c.headers != NULL) {
			error = cheriabi_copyinuio(hdtr_c.headers,
			    hdtr_c.hdr_cnt, &hdr_uio);
			if (error)
				goto out;
		}
		if (hdtr_c.trailers != NULL) {
			error = cheriabi_copyinuio(hdtr_c.trailers,
			    hdtr_c.trl_cnt, &trl_uio);
			if (error)
				goto out;
		}
	}

	AUDIT_ARG_FD(uap->fd);

	if ((error = fget_read(td, uap->fd,
	    cap_rights_init(&rights, CAP_PREAD), &fp)) != 0)
		goto out;

	error = fo_sendfile(fp, uap->s, hdr_uio, trl_uio, offset,
	    uap->nbytes, &sbytes, uap->flags, td);
	fdrop(fp, td);

	if (uap->sbytes != NULL)
		copyout(&sbytes, uap->sbytes, sizeof(off_t));

out:
	if (hdr_uio)
		free(hdr_uio, M_IOV);
	if (trl_uio)
		free(trl_uio, M_IOV);
	return (error);
}

int
cheriabi_sendfile(struct thread *td, struct cheriabi_sendfile_args *uap)
{

	return (cheriabi_do_sendfile(td, uap));
}

int
cheriabi_jail(struct thread *td, struct cheriabi_jail_args *uap)
{
	unsigned int version;
	int error;

	error = copyin_c(&uap->jailp->version, &version, sizeof(version));
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

		error = copyincap_c(uap->jailp, &j, sizeof(j));
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
	struct uio *auio;
	int error;

	/* Check that we have an even number of iovecs. */
	if (uap->iovcnt & 1)
		return (EINVAL);

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_jail_set(td, auio, uap->flags);
	free(auio, M_IOV);
	return (error);
}

static int
cheriabi_updateiov(const struct uio * uiop, struct iovec_c * __capability iovp)
{
	int i, error;

	for (i = 0; i < uiop->uio_iovcnt; i++) {
		error = copyout_c(
		    (__cheri_tocap size_t * __capability)
		    &uiop->uio_iov[i].iov_len, &iovp[i].iov_len,
		    sizeof(uiop->uio_iov[i].iov_len));
		if (error != 0)
			return (error);
	}
	return (0);
}

int
cheriabi_jail_get(struct thread *td, struct cheriabi_jail_get_args *uap)
{
	struct uio *auio;
	int error;

	/* Check that we have an even number of iovecs. */
	if (uap->iovcnt & 1)
		return (EINVAL);

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_jail_get(td, auio, uap->flags);
	if (error == 0)
		error = cheriabi_updateiov(auio, uap->iovp);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_sigreturn(struct thread *td, struct cheriabi_sigreturn_args *uap)
{
	ucontext_c_t uc;
	int error;

	error = copyincap_c(uap->sigcntxp, &uc, sizeof(uc));
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
cheriabi_thr_create(struct thread *td, struct cheriabi_thr_create_args *uap)
{

	return (ENOSYS);
}

static int
cheriabi_thr_new_initthr(struct thread *td, void *thunk)
{
	struct thr_param_c *param;
	long *child_tidp, *parent_tidp;
	int error;

	param = thunk;
	error = cheriabi_cap_to_ptr((caddr_t *)&child_tidp,
	    param->child_tid, sizeof(*child_tidp),
	    CHERI_PERM_GLOBAL | CHERI_PERM_STORE, 1);
	if (error)
		return (error);
	error = cheriabi_cap_to_ptr((caddr_t *)&parent_tidp,
	    param->parent_tid, sizeof(*parent_tidp),
	    CHERI_PERM_GLOBAL | CHERI_PERM_STORE, 1);
	if (error)
		return (error);
	if ((child_tidp != NULL && suword(child_tidp, td->td_tid)) ||
	    (parent_tidp != NULL && suword(parent_tidp, td->td_tid)))
		return (EFAULT);
	cheriabi_set_threadregs(td, param);
	return (cheriabi_set_user_tls(td, param->tls_base));
}

int
cheriabi_thr_new(struct thread *td, struct cheriabi_thr_new_args *uap)
{
	struct thr_param_c param_c;
	struct rtprio rtp, *rtpp, *rtpup;
	int error;

	if (uap->param_size != sizeof(struct thr_param_c))
		return (EINVAL);

	error = copyincap(uap->param, &param_c, uap->param_size);
	if (error != 0)
		return (error);

	/*
	 * Opportunity for machine-dependent code to provide a DDC if the
	 * caller didn't provide one.
	 *
	 * XXXRW: But should only do so if a suitable flag is set?
	 */
	cheriabi_thr_new_md(td, &param_c);
	rtpp = NULL;
	error = cheriabi_cap_to_ptr((caddr_t *)&rtpup, param_c.rtp,
	    sizeof(rtp), CHERI_PERM_GLOBAL | CHERI_PERM_LOAD, 1);
	if (error)
		return (error);
	if (rtpup != 0) {
		error = copyin(rtpup, &rtp, sizeof(struct rtprio));
		if (error)
			return (error);
		rtpp = &rtp;
	}
	return (thread_create(td, rtpp, cheriabi_thr_new_initthr, &param_c));
}

int
cheriabi_procctl(struct thread *td, struct cheriabi_procctl_args *uap)
{

	return (user_procctl(td, uap->idtype, uap->id, uap->com, uap->data));
}

void
siginfo_to_siginfo_c(const siginfo_t *src, struct siginfo_c *dst)
{
	bzero(dst, sizeof(*dst));
	dst->si_signo = src->si_signo;
	dst->si_errno = src->si_errno;
	dst->si_code = src->si_code;
	dst->si_pid = src->si_pid;
	dst->si_uid = src->si_uid;
	dst->si_status = src->si_status;
	/*
	 * XXX: should copy out something related to src->si_addr, but
	 * what?  Presumably not a valid pointer to a faulting address.
	 */
	dst->si_value.sival_int = src->si_value.sival_int;
	dst->si_timerid = src->si_timerid;
	dst->si_overrun = src->si_overrun;
}

int
cheriabi_nmount(struct thread *td,
    struct cheriabi_nmount_args /* {
	struct iovec_c * __capability iovp;
	unsigned int iovcnt;
	int flags;
    } */ *uap)
{
	struct uio *auio;
	uint64_t flags;
	int error;

	/*
	 * Mount flags are now 64-bits. On 32-bit archtectures only
	 * 32-bits are passed in, but from here on everything handles
	 * 64-bit flags correctly.
	 */
	flags = uap->flags;

	AUDIT_ARG_FFLAGS(flags);

	/*
	 * Filter out MNT_ROOTFS.  We do not want clients of nmount() in
	 * userspace to set this flag, but we must filter it out if we want
	 * MNT_UPDATE on the root file system to work.
	 * MNT_ROOTFS should only be set by the kernel when mounting its
	 * root file system.
	 */
	flags &= ~MNT_ROOTFS;

	/*
	 * check that we have an even number of iovec's
	 * and that we have at least two options.
	 */
	if ((uap->iovcnt & 1) || (uap->iovcnt < 4))
		return (EINVAL);

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = vfs_donmount(td, flags, auio);

	free(auio, M_IOV);
	return (error);
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

#ifdef NOTYET
int
cheriabi_syscall_module_handler(struct module *mod, int what, void *arg)
{
}
#endif

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

#define sucap(uaddr, base, offset, length, perms)			\
	do {								\
		void * __capability _tmpcap;				\
		cheri_capability_set(&_tmpcap, (perms), (vaddr_t)(base),\
		    (length), (offset));				\
		copyoutcap(&_tmpcap, uaddr, sizeof(_tmpcap));		\
	} while(0)

register_t *
cheriabi_copyout_strings(struct image_params *imgp)
{
	int argc, envc;
	void * __capability *vectp;
	char *stringp;
	uintptr_t destp;
	void * __capability *stack_base;
	struct cheriabi_ps_strings *arginfo;
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
	arginfo = (struct cheriabi_ps_strings *)curproc->p_sysent->sv_psstrings;
	if (imgp->proc->p_sysent->sv_sigcode_base == 0)
		szsigcode = *(imgp->proc->p_sysent->sv_szsigcode);
	else
		szsigcode = 0;
	destp =	(uintptr_t)arginfo;

	/*
	 * install sigcode
	 */
	if (szsigcode != 0) {
		destp -= szsigcode;
		destp = rounddown2(destp, sizeof(void * __capability));
		copyout(imgp->proc->p_sysent->sv_sigcode, (void *)destp,
		    szsigcode);
	}

	/*
	 * Copy the image path for the rtld.
	 */
	if (execpath_len != 0) {
		destp -= execpath_len;
		imgp->execpathp = destp;
		copyout(imgp->execpath, (void *)destp, execpath_len);
	}

	/*
	 * Prepare the canary for SSP.
	 */
	arc4rand(canary, sizeof(canary), 0);
	destp -= sizeof(canary);
	imgp->canary = destp;
	copyout(canary, (void *)destp, sizeof(canary));
	imgp->canarylen = sizeof(canary);

	/*
	 * Prepare the pagesizes array.
	 */
	destp -= szps;
	destp = rounddown2(destp, sizeof(void * __capability));
	imgp->pagesizes = destp;
	copyout(pagesizes, (void *)destp, szps);
	imgp->pagesizeslen = szps;

	destp -= ARG_MAX - imgp->args->stringspace;
	destp = rounddown2(destp, sizeof(void * __capability));

	/*
	 * Prepare some room * on the stack for auxargs.
	 */
	/*
	 * 'AT_COUNT*2' is size for the ELF Auxargs data. This is for
	 * lower compatibility.
	 */
	imgp->auxarg_size = (imgp->auxarg_size) ? imgp->auxarg_size
		: (AT_COUNT * 2);
	/*
	 * The '+ 2' is for the null pointers at the end of each of
	 * the arg and env vector sets, and imgp->auxarg_size is room
	 * for argument of runtime loader if any.
	 */
	vectp = (void * __capability *)(destp - (imgp->args->argc +
	    imgp->args->envc + 2 + imgp->auxarg_size) *
	    sizeof(void * __capability));

	/*
	 * vectp also becomes our initial stack base
	 */
	stack_base = vectp;

	stringp = imgp->args->begin_argv;
	argc = imgp->args->argc;
	envc = imgp->args->envc;
	/*
	 * Copy out strings - arguments and environment.
	 */
	copyout(stringp, (void *)destp, ARG_MAX - imgp->args->stringspace);

	/*
	 * Fill in "ps_strings" struct for ps, w, etc.
	 */
	sucap(&arginfo->ps_argvstr, vectp, 0, argc * sizeof(void * __capability),
	    CHERI_CAP_USER_DATA_PERMS);
	suword32(&arginfo->ps_nargvstr, argc);

	/*
	 * Fill in argument portion of vector table.
	 */
	imgp->args->argv = (void *)vectp;
	for (; argc > 0; --argc) {
		sucap(vectp++, destp, 0, strlen(stringp) + 1,
		    CHERI_CAP_USER_DATA_PERMS);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* a null vector table pointer separates the argp's from the envp's */
	/* XXX: suword clears the tag */
	suword(vectp++, 0);

	sucap(&arginfo->ps_envstr, vectp, 0,
	    arginfo->ps_nenvstr * sizeof(void * __capability),
	    CHERI_CAP_USER_DATA_PERMS);
	suword32(&arginfo->ps_nenvstr, envc);

	/*
	 * Fill in environment portion of vector table.
	 */
	imgp->args->envv = (void *)vectp;
	for (; envc > 0; --envc) {
		sucap(vectp++, destp, 0, strlen(stringp) + 1,
		    CHERI_CAP_USER_DATA_PERMS);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* end of vector table is a null pointer */
	/* XXX: suword clears the tag */
	suword(vectp++, 0);

	return ((register_t *)stack_base);
}

int
convert_sigevent_c(struct sigevent_c *sig_c, struct sigevent *sig)
{

	CP(*sig_c, *sig, sigev_notify);
	switch (sig->sigev_notify) {
	case SIGEV_NONE:
		break;
	case SIGEV_THREAD_ID:
		CP(*sig_c, *sig, sigev_notify_thread_id);
		/* FALLTHROUGH */
	case SIGEV_SIGNAL:
		CP(*sig_c, *sig, sigev_signo);
		sig->sigev_value.sival_ptr = malloc(sizeof(sig_c->sigev_value),
		    M_TEMP, M_WAITOK);
		*((void * __capability *)sig->sigev_value.sival_ptr) =
		    sig_c->sigev_value.sival_ptr;
		break;
	case SIGEV_KEVENT:
		CP(*sig_c, *sig, sigev_notify_kqueue);
		CP(*sig_c, *sig, sigev_notify_kevent_flags);
		sig->sigev_value.sival_ptr = malloc(sizeof(sig_c->sigev_value),
		    M_TEMP, M_WAITOK);
		*((void * __capability *)sig->sigev_value.sival_ptr) = 
		    sig_c->sigev_value.sival_ptr;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

void * __capability
cheriabi_extract_sival(union sigval *sival)
{

	return (*((void * __capability *)sival->sival_ptr));
}

void
cheriabi_free_sival(union sigval *sival)
{

	free(sival->sival_ptr, M_TEMP);
}

#define	AUXARGS_ENTRY_CAP(pos, id, base, offset, len, perm)		\
	do {								\
		suword(pos++, id); sucap(pos++, base,	\
		    offset, len, perm);					\
	} while(0)

/*
 * Write out ELF auxilery arguments.  In CheriABI, Elf64_Auxinfo pads out to:
 * typedef struct {
 *	uint64_t	a_type;
 *	uint64_t	[(sizeof(struct chericap)/sizeof(uint64_t)) - 1];
 *	union {
 *		long		a_val;
 *		struct chericap	a_ptr;
 *		struct chericap	a_fcn;
 *	};
 * } Elf64_Auxinfo;
 *
 * As a result, the AUXARGS_ENTRY macro works so long as "pos" is
 * a pointer to something capability sized.
 */
static void
cheriabi_set_auxargs(void * __capability *pos, struct image_params *imgp)
{
	Elf_Auxargs *args = (Elf_Auxargs *)imgp->auxargs;

	if (args->execfd != -1)
		AUXARGS_ENTRY(pos, AT_EXECFD, args->execfd);
	CTASSERT(CHERI_CAP_USER_CODE_BASE == 0);
	AUXARGS_ENTRY_CAP(pos, AT_PHDR, CHERI_CAP_USER_DATA_BASE, args->phdr,
	    CHERI_CAP_USER_DATA_LENGTH, CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY(pos, AT_PHENT, args->phent);
	AUXARGS_ENTRY(pos, AT_PHNUM, args->phnum);
	AUXARGS_ENTRY(pos, AT_PAGESZ, args->pagesz);
	AUXARGS_ENTRY(pos, AT_FLAGS, args->flags);
	/*
	 * XXX-BD: the should be bounded to the mapping, but for now
	 * they aren't as struct image_params doesn't contain the
	 * mapping and we're not ensuring a representable capability.
	 */
	AUXARGS_ENTRY_CAP(pos, AT_ENTRY, CHERI_CAP_USER_CODE_BASE, args->entry,
	    CHERI_CAP_USER_CODE_LENGTH, CHERI_CAP_USER_CODE_PERMS);
	/*
	 * XXX-BD: grant code and data perms to allow textrel fixups.
	 */
	AUXARGS_ENTRY_CAP(pos, AT_BASE, CHERI_CAP_USER_DATA_BASE, args->base,
	    CHERI_CAP_USER_DATA_LENGTH,
	    CHERI_CAP_USER_DATA_PERMS | CHERI_CAP_USER_CODE_PERMS);
#ifdef AT_EHDRFLAGS
	AUXARGS_ENTRY(pos, AT_EHDRFLAGS, args->hdr_eflags);
#endif
	if (imgp->execpathp != 0)
		AUXARGS_ENTRY_CAP(pos, AT_EXECPATH, imgp->execpathp, 0,
		    strlen(imgp->execpath) + 1,
		    CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY(pos, AT_OSRELDATE,
	    imgp->proc->p_ucred->cr_prison->pr_osreldate);
	if (imgp->canary != 0) {
		AUXARGS_ENTRY_CAP(pos, AT_CANARY, imgp->canary, 0,
		    imgp->canarylen, CHERI_CAP_USER_DATA_PERMS);
		AUXARGS_ENTRY(pos, AT_CANARYLEN, imgp->canarylen);
	}
	AUXARGS_ENTRY(pos, AT_NCPUS, mp_ncpus);
	if (imgp->pagesizes != 0) {
		AUXARGS_ENTRY_CAP(pos, AT_PAGESIZES, imgp->pagesizes, 0,
		   imgp->pagesizeslen, CHERI_CAP_USER_DATA_PERMS);
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
	/* XXX-BD: Includes terminating NULL.  Should it? */
	AUXARGS_ENTRY_CAP(pos, AT_ARGV, imgp->args->argv, 0,
	   sizeof(void * __capability) * (imgp->args->argc + 1),
	   CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY(pos, AT_ENVC, imgp->args->envc);
	AUXARGS_ENTRY_CAP(pos, AT_ENVV, imgp->args->envv, 0,
	   sizeof(void * __capability) * (imgp->args->envc + 1),
	   CHERI_CAP_USER_DATA_PERMS);

	AUXARGS_ENTRY(pos, AT_NULL, 0);

	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;
}

int
cheriabi_elf_fixup(register_t **stack_base, struct image_params *imgp)
{
	void * __capability *base;

	KASSERT(((vaddr_t)*stack_base & (sizeof(void * __capability) - 1)) == 0,
	    ("*stack_base (%p) is not capability aligned", *stack_base));

	base = (void * __capability *)
	    __builtin_assume_aligned(*stack_base, sizeof(void * __capability));
	base += imgp->args->argc + imgp->args->envc + 2;

	cheriabi_set_auxargs(base, imgp);

	return (0);
}

int
cheriabi_madvise(struct thread *td, struct cheriabi_madvise_args *uap)
{
	void * __capability addr_cap;
	register_t perms;

	/*
	 * MADV_FREE may change the page contents so require
	 * CHERI_PERM_CHERIABI_VMMAP.
	 */
	if (uap->behav == MADV_FREE) {
		cheriabi_fetch_syscall_arg(td, &addr_cap,
		    0, CHERIABI_SYS_cheriabi_madvise_PTRMASK);
		perms = cheri_getperm(addr_cap);
		if ((perms & CHERI_PERM_CHERIABI_VMMAP) == 0)
			return (EPROT);
	}

	return (kern_madvise(td, (uintptr_t)uap->addr, uap->len, uap->behav));
}

int
cheriabi_mmap(struct thread *td, struct cheriabi_mmap_args *uap)
{
	int flags = uap->flags;
	int usertag;
	size_t cap_base, cap_len, cap_offset;
	void * __capability addr_cap;
	register_t perms, reqperms;
	vm_offset_t reqaddr;

	if (flags & MAP_32BIT) {
		SYSERRCAUSE("MAP_32BIT not supported in CheriABI");
		return (EINVAL);
	}

	cheriabi_fetch_syscall_arg(td, &addr_cap,
	    0, CHERIABI_SYS_cheriabi_mmap_PTRMASK);
	usertag = cheri_gettag(addr_cap);
	if (!usertag) {
		if (flags & MAP_FIXED) {
			SYSERRCAUSE(
			    "MAP_FIXED without a valid addr capability");
			return (EINVAL);
		}
		if (flags & MAP_CHERI_NOSETBOUNDS) {
			SYSERRCAUSE("MAP_CHERI_NOSETBOUNDS without a valid"
			    "addr capability");
			return (EINVAL);
		}

		/* User didn't provide a capability so get one. */
		if (flags & MAP_CHERI_DDC) {
			if ((cheri_getperm(td->td_pcb->pcb_regs.ddc) &
			    CHERI_PERM_CHERIABI_VMMAP) == 0) {
				SYSERRCAUSE("DDC lacks "
				    "CHERI_PERM_CHERIABI_VMMAP");
				return (EPROT);
			}
			addr_cap = td->td_pcb->pcb_regs.ddc;
		} else {
			/* Use the per-thread one */
			addr_cap = td->td_md.md_cheri_mmap_cap;
			KASSERT(cheri_gettag(addr_cap),
			    ("td->td_md.md_cheri_mmap_cap is untagged!"));
		}
	} else {
		if (flags & MAP_CHERI_DDC) {
			SYSERRCAUSE("MAP_CHERI_DDC with non-NULL addr");
			return (EINVAL);
		}
	}
	cap_base = cheri_getbase(addr_cap);
	cap_len = cheri_getlen(addr_cap);
	if (usertag) {
		cap_offset = cheri_getoffset(addr_cap);
	} else {
		/*
		 * Ignore offset of default cap, it's only used to set bounds.
		 */
		cap_offset = 0;
	}
	if (cap_offset >= cap_len) {
		SYSERRCAUSE("capability has out of range offset");
		return (EPROT);
	}
	reqaddr = cap_base + cap_offset;
	if (reqaddr == 0)
		reqaddr = PAGE_SIZE;
	perms = cheri_getperm(addr_cap);
	reqperms = cheriabi_mmap_prot2perms(uap->prot);
	if ((perms & reqperms) != reqperms) {
		SYSERRCAUSE("capability has insufficient perms (0x%lx)"
		    "for request (0x%lx)", perms, reqperms);
		return (EPROT);
	}

	/*
	 * If alignment is specified, check that it is sufficent and
	 * increase as required.  If not, assume data alignment.
	 */
	switch (flags & MAP_ALIGNMENT_MASK) {
	case MAP_ALIGNED(0):
		/*
		 * Request CHERI data alignment when no other request
		 * is made.
		 */
		flags &= ~MAP_ALIGNMENT_MASK;
		flags |= MAP_ALIGNED_CHERI;
		break;
	case MAP_ALIGNED_CHERI:
	case MAP_ALIGNED_CHERI_SEAL:
		break;
	case MAP_ALIGNED_SUPER:
#ifdef __mips_n64
		/*
		 * pmap_align_superpage() is a no-op for allocations
		 * less than a super page so request data alignment
		 * in that case.
		 *
		 * In practice this is a no-op as super-pages are
		 * precisely representable.
		 */
		if (uap->len < PDRSIZE &&
		    CHERI_ALIGN_SHIFT(uap->len) > PAGE_SHIFT) {
			flags &= ~MAP_ALIGNMENT_MASK;
			flags |= MAP_ALIGNED_CHERI;
		}
#else
#error	MAP_ALIGNED_SUPER handling unimplemented for this architecture
#endif
		break;
	default:
		/* Reject nonsensical sub-page alignment requests */
		if ((flags >> MAP_ALIGNMENT_SHIFT) < PAGE_SHIFT) {
			SYSERRCAUSE("subpage alignment request");
			return (EINVAL);
		}

		/*
		 * Honor the caller's alignment request, if any unless
		 * it is too small.  If is, promote the request to
		 * MAP_ALIGNED_CHERI.
		 *
		 * XXX: It seems likely a user passing too small an
		 * alignment will have also passed an invalid length,
		 * but upgrading the alignment is always safe and
		 * we'll catch the length later.
		 */
		if ((flags >> MAP_ALIGNMENT_SHIFT) <
		    CHERI_ALIGN_SHIFT(uap->len)) {
			flags &= ~MAP_ALIGNMENT_MASK;
			flags |= MAP_ALIGNED_CHERI;
		}
		break;
	}
	/*
	 * NOTE: If this architecture requires an alignment constraint, it is
	 * set at this point.  A simple assert is not easy to contruct...
	 */

	if (flags & MAP_FIXED) {
		if (cap_len - cap_offset <
		    roundup2(uap->len, PAGE_SIZE)) {
			SYSERRCAUSE("MAP_FIXED and too little space in "
			    "capablity (0x%zx < 0x%zx)", cap_len - cap_offset,
			    roundup2(uap->len, PAGE_SIZE));
			return (EPROT);
		}

		/*
		 * If our address is under aligned, make sure
		 * we have room to shift it down to the page
		 * boundary.
		 */
		if ((reqaddr & PAGE_MASK) > cap_offset) {
			SYSERRCAUSE("insufficent space to shift addr (0x%lx) "
			    "down in capability (offset 0x%zx)",
			    reqaddr, cap_offset);
			return (EPROT);
		}

		/*
		 * NB: We defer alignment checks to kern_vm_mmap where we
		 * can account for file mapping with oddly aligned
		 * that match the offset alignment.
		 */

	}

	return (kern_mmap(td, reqaddr, cap_base + cap_len, uap->len,
	    uap->prot, flags, uap->fd, uap->pos));
}


int
cheriabi_mprotect(struct thread *td, struct cheriabi_mprotect_args *uap)
{
	void * __capability addr_cap;
	register_t perms, reqperms;

	cheriabi_fetch_syscall_arg(td, &addr_cap,
	    0, CHERIABI_SYS_cheriabi_mprotect_PTRMASK);
	perms = cheri_getperm(addr_cap);
	/*
	 * Requested prot much be allowed by capability.
	 *
	 * XXX-BD: An argument could be made for allowing a union of the
	 * current page permissions with the capability permissions (e.g.
	 * allowing a writable cap to add write permissions to an RX
	 * region as required to match up objects with textrel sections.
	 */
	reqperms = cheriabi_mmap_prot2perms(uap->prot);
	if ((perms & reqperms) != reqperms)
		return (EPROT);

	return (kern_mprotect(td, (vm_offset_t)uap->addr, uap->len,
	    uap->prot));
}

#define	PERM_READ	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define	PERM_WRITE	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
			    CHERI_PERM_STORE_LOCAL_CAP)
#define	PERM_EXEC	CHERI_PERM_EXECUTE
#define	PERM_RWX	(PERM_READ | PERM_WRITE | PERM_EXEC)
/*
 * Given a starting set of CHERI permissions (operms), set (not AND) the load,
 * store, and execute permissions based on the mmap permissions (prot).
 *
 * This function is intended to be used when creating a capability to a
 * new region or rederiving a capability when upgrading a sub-region.
 */
static register_t
cheriabi_mmap_prot2perms(int prot)
{
	register_t perms = 0;

	if (prot & PROT_READ)
		perms |= CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP;
	if (prot & PROT_WRITE)
		perms |= CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		CHERI_PERM_STORE_LOCAL_CAP;
	if (prot & PROT_EXEC)
		perms |= CHERI_PERM_EXECUTE;

	return (perms);
}

int
cheriabi_mmap_set_retcap(struct thread *td, void * __capability *retcap,
   void * __capability *addrp, size_t len, int prot, int flags)
{
	register_t ret;
	size_t mmap_cap_base, mmap_cap_len;
	vm_map_t map;
	register_t perms;
	size_t addr_base;
	void * __capability addr;

	ret = td->td_retval[0];
	/* On failure, return a NULL capability with an offset of -1. */
	if ((void *)ret == MAP_FAILED) {
		/* XXX-BD: the return of -1 is in userspace, not here. */
		*retcap = (void * __capability)-1;
		return (0);
	}

	/*
	 * In the strong case (cheriabi_mmap_setbounds), leave addr untouched
	 * when MAP_CHERI_NOSETBOUNDS is set.
	 *
	 * In the weak case (!cheriabi_mmap_setbounds), return addr untouched
	 * for *all* fixed requests.
	 *
	 * NB: This means no permission changes.
	 * The assumption is that the larger capability has the correct
	 * permissions and we're only intrested in adjusting page mappings.
	 */
	if (flags & MAP_CHERI_NOSETBOUNDS ||
	    (!cheriabi_mmap_setbounds && flags & MAP_FIXED)) {
		*retcap = *addrp;
		return (0);
	}

	if (flags & MAP_FIXED) {
		addr = *addrp;
	} else if (flags & MAP_CHERI_DDC) {
		addr = td->td_pcb->pcb_regs.ddc;
	} else {
		addr = td->td_md.md_cheri_mmap_cap;
	}

	if (cheriabi_mmap_honor_prot) {
		perms = cheri_getperm(addr);
		/*
		 * Set the permissions to PROT_MAX to allow a full
		 * range of access subject to page permissions.
		 */
		addr = cheri_andperm(addr, ~PERM_RWX |
		    cheriabi_mmap_prot2perms(EXTRACT_PROT_MAX(prot)));
	}

	if (flags & MAP_FIXED) {
		KASSERT(cheriabi_mmap_setbounds,
		    ("%s: trying to set bounds on fixed map when disabled",
		    __func__));
		/*
		 * If addr was under aligned, we need to return a
		 * capability to the whole, properly aligned region
		 * with the offset pointing to addr.
		 */
		addr_base = cheri_getbase(addr);
		/* Set offset to vaddr of page */
		addr = cheri_setoffset(addr,
		    rounddown2(ret, PAGE_SIZE) - addr_base);
		addr = cheri_csetbounds(addr,
		    roundup2(len + (ret - rounddown2(ret, PAGE_SIZE)),
		    PAGE_SIZE));
		/* Shift offset up if required */
		addr_base = cheri_getbase(addr);
		addr = cheri_setoffset(addr, addr_base - ret);
	} else {
		mmap_cap_base = cheri_getbase(addr);
		mmap_cap_len = cheri_getlen(addr);
		if (ret < mmap_cap_base ||
		    ret + len > mmap_cap_base + mmap_cap_len) {
			map = &td->td_proc->p_vmspace->vm_map;
			vm_map_lock(map);
			vm_map_remove(map, ret, ret + len);
			vm_map_unlock(map);

			return (EPERM);
		}
		addr = cheri_setoffset(addr, ret - mmap_cap_base);
		if (cheriabi_mmap_setbounds)
			addr = cheri_csetbounds(addr, roundup2(len, PAGE_SIZE));
	}
	*retcap = addr;

	return (0);
}

int
cheriabi_mount(struct thread *td, struct cheriabi_mount_args *uap)
{

	return (ENOSYS);
}

int
cheriabi_mac_syscall(struct thread *td, struct cheriabi_mac_syscall_args *uap)
{

	return (ENOSYS);
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
cheriabi_kenv(struct thread *td, struct cheriabi_kenv_args *uap)
{

	return (kern_kenv(td, uap->what, uap->name, uap->value, uap->len));
}

int
cheriabi_kbounce(struct thread *td, struct cheriabi_kbounce_args *uap)
{
	void * __capability bounce;
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

	bounce = (__cheri_tocap void * __capability )malloc(len,
	    M_TEMP, M_WAITOK | M_ZERO);
	error = copyin_c(src, bounce, len);
	if (error != 0) {
		printf("%s: error in copyin_c %d\n", __func__, error);
		goto error;
	}
	error = copyout_c(bounce, dst, len);
	if (error != 0)
		printf("%s: error in copyout_c %d\n", __func__, error);
error:
	free((__cheri_fromcap void *)bounce, M_TEMP);
	return (error);
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

/*
 * kern_descrip.c
 */
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
	char *pathname = NULL;
	int error, fileid;

	td->td_retval[0] = -1;

	pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr_c(uap->file, &pathname[0], MAXPATHLEN, NULL);
	if (error != 0)
		goto error;
	error = kern_kldload(td, pathname, &fileid);
	if (error == 0)
		td->td_retval[0] = fileid;
error:
	free(pathname, M_TEMP);
	return (error);
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

        error = copyin_c(&uap->stat->version, &version, sizeof(version));
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
        return (copyout_c(&stat_c, uap->stat, version));
}

int
cheriabi_kldsym(struct thread *td, struct cheriabi_kldsym_args *uap)
{
	struct kld_sym_lookup_c lookup;
	char *symstr;
	int error;

	error = copyincap_c(uap->data, &lookup, sizeof(lookup));
	if (error != 0)
		return (error);
	if (lookup.version != sizeof(lookup) ||
	    uap->cmd != KLDSYM_LOOKUP)
		return (EINVAL);
	symstr = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr_c(lookup.symname,
	    (__cheri_tocap char * __capability)symstr, MAXPATHLEN, NULL);
	if (error != 0)
		goto done;
	error = kern_kldsym(td, uap->fileid, uap->cmd, symstr,
	    &lookup.symvalue, &lookup.symsize);
	if (error != 0)
		goto done;
	error = copyoutcap_c(&lookup, uap->data, sizeof(lookup));

done:
	free(symstr, M_TEMP);
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
	struct uuid *store;
	size_t count;
	int error;

	/*
	 * Limit the number of UUIDs that can be created at the same time
	 * to some arbitrary number. This isn't really necessary, but I
	 * like to have some sort of upper-bound that's less than 2G :-)
	 * XXX probably needs to be tunable.
	 */
	if (uap->count < 1 || uap->count > 2048)
		return (EINVAL);

	count = uap->count;
	store = malloc(count * sizeof(struct uuid), M_TEMP, M_WAITOK);
	kern_uuidgen(store, count);
	error = copyout_c((__cheri_tocap struct uuid * __capability)store,
	    uap->store, count * sizeof(struct uuid));
	free(store, M_TEMP);
	return (error);
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
	gid_t smallgroups[XU_NGROUPS];
	gid_t *groups;
	u_int gidsetsize;
	int error;

	gidsetsize = uap->gidsetsize;
	if (gidsetsize > ngroups_max + 1)
		return (EINVAL);

	if (gidsetsize > XU_NGROUPS)
		groups = malloc(gidsetsize * sizeof(gid_t), M_TEMP, M_WAITOK);
	else
		/* XXX: CTSRD-CHERI/clang#179 */
		groups = &smallgroups[0];

	error = copyin_c(uap->gidset,
	    (__cheri_tocap gid_t * __capability)groups,
	    gidsetsize * sizeof(gid_t));
	if (error == 0)
		error = kern_setgroups(td, gidsetsize, groups);

	if (gidsetsize > XU_NGROUPS)
		free(groups, M_TEMP);
	return (error);
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
cheriabi_setrlimit(struct thread *td, struct cheriabi_setrlimit_args *uap)
{
	struct rlimit alim;
	int error;

	error = copyin_c(uap->rlp, &alim, sizeof(struct rlimit));
	if (error != 0)
		return (error);
	return (kern_setrlimit(td, uap->which, &alim));
}

int
cheriabi_getrlimit(struct thread *td, struct cheriabi_getrlimit_args *uap)
{
	struct rlimit rlim;
	int error;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	lim_rlimit(td, uap->which, &rlim);
	error = copyout_c(&rlim, uap->rlp, sizeof(struct rlimit));
	return (error);
}

int
cheriabi_getrusage(struct thread *td, struct cheriabi_getrusage_args *uap)
{
	struct rusage ru;
	int error;

	error = kern_getrusage(td, uap->who, &ru);
	if (error == 0)
		error = copyout_c(&ru, uap->rusage, sizeof(struct rusage));
	return (error);
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
#define CHERIABI_SYSCALL_NOT_PRESENT_GEN(SC) \
int cheriabi_ ## SC (struct thread *td, struct cheriabi_##SC##_args *uap) \
{ \
	return syscall_not_present(td, #SC , (struct nosys_args *)uap); \
}

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
 * vm_mmap.c
 */
int
cheriabi_mincore(struct thread *td, struct cheriabi_mincore_args *uap)
{

	/* XXX: check range of cap */
	return (kern_mincore(td, (__cheri_addr uintptr_t)uap->addr, uap->len,
	    uap->vec));
}
