/*-
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2015-2016 SRI International
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

#include <sys/cheriabi.h>

MALLOC_DECLARE(M_KQUEUE);

FEATURE(compat_cheri_abi, "Compatible CHERI system call ABI");

#ifdef CHERIABI_NEEDS_UPDATE
CTASSERT(sizeof(struct sigaltstack32) == 12);
CTASSERT(sizeof(struct kevent32) == 20);
CTASSERT(sizeof(struct iovec32) == 8);
CTASSERT(sizeof(struct msghdr32) == 28);
CTASSERT(sizeof(struct sigaction32) == 24);
#endif

static int cheriabi_kevent_copyout(void *arg, struct kevent *kevp, int count);
static int cheriabi_kevent_copyin(void *arg, struct kevent *kevp, int count);
static register_t cheriabi_mmap_prot2perms(int prot);

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
		error = copyout(&status, uap->status, sizeof(status));
	if (uap->wrusage != NULL && error == 0)
		error = copyout(&wru, uap->wrusage, sizeof(wru));
	if (uap->info != NULL && error == 0) {
		siginfo_to_siginfo_c (&si, &si_c);
		error = copyout(&si_c, uap->info, sizeof(si_c));
	}
	return (error);
}

int
cheriabi_sigaltstack(struct thread *td,
    struct cheriabi_sigaltstack_args *uap)
{
	struct chericap old_ss_sp;
	struct sigaltstack_c s_c;
	struct sigaltstack ss, oss, *ssp;
	int error;

	if (uap->ss != NULL) {
		error = copyincap(uap->ss, &s_c, sizeof(s_c));
		if (error)
			return (error);
		CP(s_c, ss, ss_size);
		CP(s_c, ss, ss_flags);
		/* XXX-BD: what perms to enforce? */
		error = cheriabi_cap_to_ptr((caddr_t *)&ss.ss_sp, &s_c.ss_sp,
		    s_c.ss_size, CHERI_PERM_GLOBAL, 1);
		if (error)
			return (error);
		ssp = &ss;
	} else
		ssp = NULL;
	error = kern_sigaltstack(td, ssp, &oss);
	if (error == 0) {
		cheriabi_get_signal_stack_capability(td, &old_ss_sp);
		if (uap->ss != NULL) {
			/*
			 * Install the new signal capability or restore the
			 * thread's default one.
			 */
			cheriabi_set_signal_stack_capability(td,
			    (ss.ss_flags & SS_DISABLE) ? NULL : &s_c.ss_sp);
		}
		if (uap->oss != NULL) {
			cheriabi_get_signal_stack_capability(td, &s_c.ss_sp);
			CP(oss, s_c, ss_size);
			CP(oss, s_c, ss_flags);
			error = copyoutcap(&s_c, uap->oss, sizeof(s_c));
		}
	}
	return (error);
}

/*
 * Custom version of exec_copyin_args() so that we can translate
 * the pointers.
 */
int
cheriabi_exec_copyin_args(struct image_args *args, char *fname,
    enum uio_seg segflg, struct chericap *argv, struct chericap *envv)
{
	char *argp, *envp;
	struct chericap *pcap, arg;
	size_t length;
	int error, tag;

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
	 * Copy the file name.
	 */
	if (fname != NULL) {
		args->fname = args->buf;
		error = (segflg == UIO_SYSSPACE) ?
		    copystr(fname, args->fname, PATH_MAX, &length) :
		    copyinstr(fname, args->fname, PATH_MAX, &length);
		if (error != 0)
			goto err_exit;
	} else
		length = 0;

	args->begin_argv = args->buf + length;
	args->endp = args->begin_argv;
	args->stringspace = ARG_MAX;

	/*
	 * extract arguments first
	 */
	pcap = argv;
	for (;;) {
		error = copyincap(pcap++, &arg, sizeof(arg));
		if (error)
			goto err_exit;
		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &arg, 0);
		CHERI_CGETTAG(tag, CHERI_CR_CTEMP0);
		if (!tag)
			break;
		error = cheriabi_strcap_to_ptr((const char **)&argp,
		    &arg, 0);
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
			error = copyincap(pcap++, &arg, sizeof(arg));
			if (error)
				goto err_exit;
			CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &arg, 0);
			CHERI_CGETTAG(tag, CHERI_CR_CTEMP0);
			if (!tag)
				break;
			error = cheriabi_strcap_to_ptr((const char **)&envp,
			    &arg, 0);
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
	int i, error = 0;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct cheriabi_kevent_args *)arg;

	for (i = 0; i < count; i++) {
		CP(kevp[i], ks_c[i], filter);
		CP(kevp[i], ks_c[i], flags);
		CP(kevp[i], ks_c[i], fflags);
		CP(kevp[i], ks_c[i], data);

		/*
		 * Retrieve the ident and udata capabilities stashed by
		 * cheriabi_kevent_copyin().
		 */
		cheri_capability_copy(&ks_c[i].ident, kevp[i].udata);
		cheri_capability_copy(&ks_c[i].udata,
		    (struct chericap *)kevp[i].udata + 1);
	}
	error = copyoutcap(ks_c, uap->eventlist, count * sizeof(*ks_c));
	if (error == 0)
		uap->eventlist += count;
	return (error);
}

/*
 * Copy 'count' items from the list pointed to by uap->changelist.
 */
static int
cheriabi_kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct cheriabi_kevent_args *uap;
	struct kevent_c	ks_c[KQ_NEVENTS];
	int error, i, tag;
	register_t perms;

	KASSERT(count <= KQ_NEVENTS, ("count (%d) > KQ_NEVENTS", count));
	uap = (struct cheriabi_kevent_args *)arg;

	error = copyincap(uap->changelist, ks_c, count * sizeof *ks_c);
	if (error)
		goto done;
	uap->changelist += count;

	for (i = 0; i < count; i++) {
		/*
		 * XXX-BD: this is quite awkward.  ident could be anything.
		 * If it's a capabilty, we'll hang on to it in udata.
		 */
		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &ks_c[i].ident, 0);
		CHERI_CGETTAG(tag, CHERI_CR_CTEMP0);
		if (!tag)
			CHERI_CTOINT(kevp[i].ident, CHERI_CR_CTEMP0);
		else {
			CHERI_CGETPERM(perms, CHERI_CR_CTEMP0);
			if (!(perms | CHERI_PERM_GLOBAL))
				return (EPROT);
			CHERI_CTOPTR(kevp[i].ident, CHERI_CR_CTEMP0, CHERI_CR_KDC);
		}
		CP(ks_c[i], kevp[i], filter);
		CP(ks_c[i], kevp[i], flags);
		CP(ks_c[i], kevp[i], fflags);
		CP(ks_c[i], kevp[i], data);

		if (ks_c[i].flags & EV_DELETE)
			continue;

		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &ks_c[i].udata, 0);
		CHERI_CGETTAG(tag, CHERI_CR_CTEMP0);
		if (tag) {
			CHERI_CGETPERM(perms, CHERI_CR_CTEMP0);
			if (!(perms & CHERI_PERM_GLOBAL))
				return (EPROT);
		}
		/*
		 * We stash the real ident and udata capabilities in
		 * a malloced array in udata.
		 */
		kevp[i].udata = malloc(2*sizeof(struct chericap), M_KQUEUE,
		    M_WAITOK);
		kevp[i].flags |= EV_FREEUDATA;
		cheri_capability_copy(kevp[i].udata, &ks_c[i].ident);
		cheri_capability_copy((struct chericap *)kevp[i].udata + 1,
		    &ks_c[i].udata);
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

static int
cheriabi_copyinuio(struct iovec_c *iovp, u_int iovcnt, struct uio **uiop)
{
	struct iovec_c iov_c;
	struct iovec *iov;
	struct uio *uio;
	u_int iovlen;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	iovlen = iovcnt * sizeof(struct iovec);
	uio = malloc(iovlen + sizeof(*uio), M_IOV, M_WAITOK);
	iov = (struct iovec *)(uio + 1);
	for (i = 0; i < iovcnt; i++) {
		error = copyincap(&iovp[i], &iov_c, sizeof(struct iovec_c));
		if (error) {
			free(uio, M_IOV);
			return (error);
		}
		iov[i].iov_len = iov_c.iov_len;
		error = cheriabi_cap_to_ptr((caddr_t *)&iov[i].iov_base,
		    &iov_c.iov_base, iov[i].iov_len,
		    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD, 0);
		if (error) {
			free(uio, M_IOV);
			return (error);
		}
	}
	uio->uio_iov = iov;
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov->iov_len > INT_MAX - uio->uio_resid) {
			free(uio, M_IOV);
			return (EINVAL);
		}
		uio->uio_resid += iov->iov_len;
		iov++;
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
cheriabi_copyiniov(struct iovec_c *iovp_c, u_int iovcnt, struct iovec **iovp,
    int error)
{
	struct iovec_c iov_c;
	struct iovec *iov;
	u_int iovlen;
	int i;

	*iovp = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(struct iovec);
	iov = malloc(iovlen, M_IOV, M_WAITOK);
	for (i = 0; i < iovcnt; i++) {
		error = copyincap(&iovp_c[i], &iov_c, sizeof(struct iovec_c));
		if (error) {
			free(iov, M_IOV);
			return (error);
		}
		iov[i].iov_len = iov_c.iov_len;
		error = cheriabi_cap_to_ptr((caddr_t *)&iov[i].iov_base,
		    &iov_c.iov_base, iov[i].iov_len,
		    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD, 0);
		if (error) {
			free(iov, M_IOV);
			return (error);
		}
	}
	*iovp = iov;
	return (0);
}

static int
cheriabi_copyinmsghdr(struct msghdr_c *msg_cp, struct msghdr *msg, int out)
{
	struct msghdr_c msg_c;
	int error;

	error = copyincap(msg_cp, &msg_c, sizeof(msg_c));
	if (error)
		return (error);
	error = cheriabi_cap_to_ptr((caddr_t *)&msg->msg_name, &msg_c.msg_name,
	    msg_c.msg_namelen, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD, 1);
	if (error)
		return (error);
	msg->msg_namelen = msg_c.msg_namelen;
	error = cheriabi_cap_to_ptr((caddr_t *)&msg->msg_iov, &msg_c.msg_iov,
	    sizeof(struct iovec_c) * msg_c.msg_iovlen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP, 0);
	if (error)
		return (error);
	msg->msg_iovlen = msg_c.msg_iovlen;
	error = cheriabi_cap_to_ptr((caddr_t *)&msg->msg_control,
	    &msg_c.msg_control, msg_c.msg_controllen,
	    CHERI_PERM_GLOBAL | (out ? CHERI_PERM_STORE : CHERI_PERM_LOAD), 1);
	if (error)
		return (error);
	msg->msg_controllen = msg_c.msg_controllen;
	msg->msg_flags = msg_c.msg_flags;
	return (0);
}

static int
cheriabi_copyoutmsghdr(struct msghdr *msg, struct msghdr_c *msg_c)
{
	struct copy_map cm[3];
	int error;

	cm[0].koffset = offsetof(struct msghdr, msg_namelen);
	cm[0].uoffset = offsetof(struct msghdr_c, msg_namelen);
	cm[0].len = sizeof(msg_c->msg_namelen);
	cm[1].koffset = offsetof(struct msghdr, msg_iovlen);
	cm[1].uoffset = offsetof(struct msghdr_c, msg_iovlen);
	cm[1].len = sizeof(msg_c->msg_iovlen);
	/* Copy out msg_controllen and msg_flags */
	cm[2].koffset = offsetof(struct msghdr, msg_controllen);
	cm[2].uoffset = offsetof(struct msghdr_c, msg_controllen);
	cm[2].len = sizeof(struct msghdr_c) -
	    offsetof(struct msghdr_c, msg_controllen);

	error = copyout_part(msg, msg_c, cm, 3);
	return (error);
}

int
cheriabi_recvmsg(struct thread *td,
	struct cheriabi_recvmsg_args /* {
		int	s;
		struct	msghdr_c *msg;
		int	flags;
	} */ *uap)
{
	struct msghdr msg;
	struct iovec *uiov, *iov;

	int error;

	error = cheriabi_copyinmsghdr(uap->msg, &msg, 1);
	if (error)
		return (error);
	error = cheriabi_copyiniov((struct iovec_c *)msg.msg_iov, msg.msg_iovlen,
	    &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_flags = uap->flags;
	uiov = msg.msg_iov;
	msg.msg_iov = iov;

	error = kern_recvit(td, uap->s, &msg, UIO_USERSPACE, NULL);
	if (error == 0) {
		msg.msg_iov = uiov;
		
		/*
		 * Message contents have already been copied out, update
		 * lengths.
		 */
		error = cheriabi_copyoutmsghdr(&msg, uap->msg);
	}
	free(iov, M_IOV);

	return (error);
}

int
cheriabi_sendmsg(struct thread *td,
		  struct cheriabi_sendmsg_args *uap)
{
	struct msghdr msg;
	struct iovec *iov;
	struct mbuf *control = NULL;
	struct sockaddr *to = NULL;
	int error;

	error = cheriabi_copyinmsghdr(uap->msg, &msg, 0);
	if (error)
		return (error);
	error = cheriabi_copyiniov((struct iovec_c *)msg.msg_iov, msg.msg_iovlen,
	    &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_iov = iov;
	if (msg.msg_name != NULL) {
		error = getsockaddr(&to, msg.msg_name, msg.msg_namelen);
		if (error) {
			to = NULL;
			goto out;
		}
		msg.msg_name = to;
	}

	if (msg.msg_control) {
		if (msg.msg_controllen < sizeof(struct cmsghdr)) {
			error = EINVAL;
			goto out;
		}

		/*
		 * Control messages are currently assumed to be free of
		 * capabilities.  One could imagine passing capabilities
		 * (most likely sealed) to another socket with the
		 * expectation of receiving them back once some work is
		 * performed, but that would be harder to implement and
		 * easy to get wrong.  Lots of code likely assumes 64-bit
		 * alignment of mbufs is sufficent as well.
		 */
		/* XXX: No support for COMPAT_OLDSOCK path */
		error = sockargs(&control, msg.msg_control, msg.msg_controllen,
		    MT_CONTROL);
		if (error)
			goto out;

		/* XXXBD: sys_sendmsg doesn't do this */
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	error = kern_sendit(td, uap->s, &msg, uap->flags, control,
	    UIO_USERSPACE);

out:
	free(iov, M_IOV);
	if (to)
		free(to, M_SONAME);
	return (error);
}

static int
cheriabi_do_sendfile(struct thread *td,
    struct cheriabi_sendfile_args *uap, int compat)
{
	struct sf_hdtr_c hdtr_c;
	struct iovec_c *headers, *trailers;
	struct uio *hdr_uio, *trl_uio;
	struct file *fp;
	cap_rights_t rights;
	off_t offset, sbytes;
	int error;
	static register_t reqperms = CHERI_PERM_GLOBAL |
	    CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP;

	offset = uap->offset;
	if (offset < 0)
		return (EINVAL);

	hdr_uio = trl_uio = NULL;

	if (uap->hdtr != NULL) {
		error = copyincap(uap->hdtr, &hdtr_c, sizeof(hdtr_c));
		if (error)
			goto out;
		error = cheriabi_cap_to_ptr((caddr_t *)&headers,
		    &hdtr_c.headers, sizeof(struct iovec_c) * hdtr_c.hdr_cnt,
		    reqperms, 1);
		if (error)
			goto out;
		error = cheriabi_cap_to_ptr((caddr_t *)&trailers,
		    &hdtr_c.trailers, sizeof(struct iovec_c) * hdtr_c.trl_cnt,
		    reqperms, 1);
		if (error)
			goto out;

		if (headers != NULL) {
			error = cheriabi_copyinuio(headers, hdtr_c.hdr_cnt,
			    &hdr_uio);
			if (error)
				goto out;
		}
		if (trailers != NULL) {
			error = cheriabi_copyinuio(trailers, hdtr_c.trl_cnt,
			    &trl_uio);
			if (error)
				goto out;
		}
	}

	AUDIT_ARG_FD(uap->fd);

	if ((error = fget_read(td, uap->fd,
	    cap_rights_init(&rights, CAP_PREAD), &fp)) != 0)
		goto out;

	error = fo_sendfile(fp, uap->s, hdr_uio, trl_uio, offset,
	    uap->nbytes, &sbytes, uap->flags, compat ? SFK_COMPAT : 0, td);
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

	return (cheriabi_do_sendfile(td, uap, 0));
}

int
cheriabi_jail(struct thread *td, struct cheriabi_jail_args *uap)
{
	uint32_t version;
	int error;
	struct jail j;

	error = copyin(uap->jail, &version, sizeof(uint32_t));
	if (error)
		return (error);

	switch (version) {
	case 0:
	case 1:
		/* These were never supported for CHERI */
		return (EINVAL);

	case 2:	/* JAIL_API_VERSION */
	{
		/* FreeBSD multi-IPv4/IPv6,noIP jails. */
		struct jail_c j_c;

		error = copyincap(uap->jail, &j_c, sizeof(j_c));
		if (error)
			return (error);
		CP(j_c, j, version);
		cheriabi_strcap_to_ptr((const char **)&j.path, &j_c.path, 1);
		cheriabi_strcap_to_ptr((const char **)&j.hostname,
		    &j_c.hostname, 1);
		cheriabi_strcap_to_ptr((const char **)&j.jailname,
		    &j_c.jailname, 1);
		CP(j_c, j, ip4s);
		CP(j_c, j, ip6s);
		error = cheriabi_cap_to_ptr((caddr_t *)&j.ip4, &j_c.ip4,
		    sizeof(*j.ip4) * j.ip4s,
		    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD, 1);
		if (error)
			return (error);
		error = cheriabi_cap_to_ptr((caddr_t *)&j.ip6, &j_c.ip6,
		    sizeof(*j.ip6) * j.ip6s,
		    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD, 1);
		if (error)
			return (error);
		break;
	}

	default:
		/* Sci-Fi jails are not supported, sorry. */
		return (EINVAL);
	}
	return (kern_jail(td, &j));
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

int
cheriabi_jail_get(struct thread *td, struct cheriabi_jail_get_args *uap)
{
	struct uio *auio;
	int error, i;

	/* Check that we have an even number of iovecs. */
	if (uap->iovcnt & 1)
		return (EINVAL);

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_jail_get(td, auio, uap->flags);
	if (error == 0)
		for (i = 0; i < uap->iovcnt; i++) {
			/*
			 * Copyout the length of data previously copied
			 * to userspace by kern_jail_get.  Do not touch the
			 * capabilities as we have no way to reconstruct
			 * the correct values short of pulling them from
			 * userspace again.
			 */
			error = copyout(&auio->uio_iov[i].iov_len,
			    ((char *)uap->iovp + i) +
			     offsetof(struct iovec_c, iov_len),
			    sizeof(auio->uio_iov[i].iov_len));
			if (error != 0)
				break;
		}
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_sigaction(struct thread *td, struct cheriabi_sigaction_args *uap)
{
	struct sigaction_c sa_c;
	struct sigaction sa, osa, *sap;
	struct chericap cap;

	int error, tag;

	if (uap->act) {
		error = copyincap(uap->act, &sa_c, sizeof(sa_c));
		if (error)
			return (error);
		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &sa_c.sa_u, 0);
		CHERI_CGETTAG(tag, CHERI_CR_CTEMP0);
		if (!tag) {
			CHERI_CTOINT(sa.sa_handler, CHERI_CR_CTEMP0);
			if (sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN)
				return (EPROT);
		} else {
			error = cheriabi_cap_to_ptr((caddr_t *)&sa.sa_handler,
			    &sa_c.sa_u,
			    8 /* XXX-BD: at least two instructions */,
		            CHERI_PERM_LOAD | CHERI_PERM_EXECUTE, 0);
			if (error)
				return (error);
		}
		CP(sa_c, sa, sa_flags);
		CP(sa_c, sa, sa_mask);
		sap = &sa;
		cheri_capability_copy(&cap, &sa_c.sa_u);
	} else
		sap = NULL;
	error = kern_sigaction_cap(td, uap->sig, sap, &osa, 0, &cap);
	if (error == 0 && uap->oact != NULL) {
		cheri_capability_copy(&sa_c.sa_u, &cap);
		CP(osa, sa_c, sa_flags);
		CP(osa, sa_c, sa_mask);
		error = copyoutcap(&sa_c, uap->oact, sizeof(sa_c));
	}
	return (error);
}

struct sigvec_c {
	struct chericap	sv_handler;
	int		sv_mask;
	int		sv_flags;
};

struct sigstack32 {
	u_int32_t	ss_sp;
	int		ss_onstack;
};

int cheriabi_ktimer_create(struct thread *td,
    struct cheriabi_ktimer_create_args *uap)
{
	struct sigevent_c ev_c;
	struct sigevent ev, *evp;
	int error, id;

	if (uap->evp == NULL) {
		evp = NULL;
	} else {
		evp = &ev;
		error = copyincap(uap->evp, &ev_c, sizeof(ev_c));
		if (error != 0)
			return (error);
		error = convert_sigevent_c(&ev_c, &ev);
		if (error != 0)
			return (error);
	}
	error = kern_ktimer_create(td, uap->clock_id, evp, &id, -1);
	if (error == 0) {
		error = copyout(&id, uap->timerid, sizeof(int));
		if (error != 0)
			kern_ktimer_delete(td, id);
	}
	return (error);
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
	    &param->child_tid, sizeof(*child_tidp),
	    CHERI_PERM_GLOBAL | CHERI_PERM_STORE, 1);
	if (error)
		return (error);
	error = cheriabi_cap_to_ptr((caddr_t *)&parent_tidp,
	    &param->parent_tid, sizeof(*parent_tidp),
	    CHERI_PERM_GLOBAL | CHERI_PERM_STORE, 1);
	if (error)
		return (error);
	if ((child_tidp != NULL && suword(child_tidp, td->td_tid)) ||
	    (parent_tidp != NULL && suword(parent_tidp, td->td_tid)))
		return (EFAULT);
	cheriabi_set_threadregs(td, param);
	return (cheriabi_set_user_tls(td, &param->tls_base));
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
	error = cheriabi_cap_to_ptr((caddr_t *)&rtpup, &param_c.rtp,
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
cheriabi_sigqueue(struct thread *td, struct cheriabi_sigqueue_args *uap)
{
	/*
	 * XXX-BD: before we can implement this, we need to know how
	 * we're going to handle uap->value.  At a minimum we need to
	 * know which situations we'll send a capability and which if any
	 * we'll send a virtual address.
	 */

	return (EINVAL);
}

int
cheriabi_procctl(struct thread *td, struct cheriabi_procctl_args *uap)
{

	switch (uap->com) {
	case PROC_REAP_GETPIDS:
		/*
		 * XXX-BD: implement struct procctl_reaper_pids_c
		 * support in reap_getpids()
		 */
		return (EOPNOTSUPP);
	}
	return (sys_procctl(td, (struct procctl_args *)uap));
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
	cheri_capability_set_null(&dst->si_addr);
	dst->si_value.sival_int = src->si_value.sival_int;
	dst->si_timerid = src->si_timerid;
	dst->si_overrun = src->si_overrun;
}

int
cheriabi_sigtimedwait(struct thread *td, struct cheriabi_sigtimedwait_args *uap)
{
	struct timespec ts;
	struct timespec *timeout;
	sigset_t set;
	ksiginfo_t ksi;
	struct siginfo_c si_c;
	int error;

	if (uap->timeout) {
		error = copyin(uap->timeout, &ts, sizeof(ts));
		if (error)
			return (error);
		timeout = &ts;
	} else
		timeout = NULL;

	error = copyin(uap->set, &set, sizeof(set));
	if (error)
		return (error);

	error = kern_sigtimedwait(td, set, &ksi, timeout);
	if (error)
		return (error);

	if (uap->info) {
		siginfo_to_siginfo_c(&ksi.ksi_info, &si_c);
		error = copyout(&si_c, uap->info, sizeof(struct siginfo_c));
	}

	if (error == 0)
		td->td_retval[0] = ksi.ksi_signo;
	return (error);
}

/*
 * MPSAFE
 */
int
cheriabi_sigwaitinfo(struct thread *td, struct cheriabi_sigwaitinfo_args *uap)
{
	ksiginfo_t ksi;
	struct siginfo_c si_c;
	sigset_t set;
	int error;

	error = copyin(uap->set, &set, sizeof(set));
	if (error)
		return (error);

	error = kern_sigtimedwait(td, set, &ksi, NULL);
	if (error)
		return (error);

	if (uap->info) {
		siginfo_to_siginfo_c(&ksi.ksi_info, &si_c);
		error = copyout(&si_c, uap->info, sizeof(struct siginfo_c));
	}	
	if (error == 0)
		td->td_retval[0] = ksi.ksi_signo;
	return (error);
}

int
cheriabi_nmount(struct thread *td,
    struct cheriabi_nmount_args /* {
    	struct iovec_c *iovp;
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
cheriabi_kldsym(struct thread *td, struct cheriabi_kldsym_args *uap)
{

	/* XXX-BD: split sys_kldsym into kern_kldsym */
	return (ENOSYS);
}

int
cheriabi_abort2(struct thread *td, struct cheriabi_abort2_args *uap)
{
	struct abort2_args a2args;

	a2args.why = uap->why;
	/*
	 * XXX-BD: need to duplication much of the abort2 logic or
	 * refactor to support passing array of args in kernelspace.
	 */
	a2args.nargs = 0;
	a2args.args = NULL;

	return (sys_abort2(td, &a2args));
}

#if 0
int
syscallcheri_register(int *offset, struct sysent *new_sysent,
    struct sysent *old_sysent, int flags)
{
}

int
syscallcheri_deregister(int *offset, struct sysent *old_sysent)
{
}

int
syscallcheri_module_handler(struct module *mod, int what, void *arg)
{
}

int
syscallcheri_helper_register(struct syscall_helper_data *sd, int flags)
{
}

int
syscallcheri_helper_unregister(struct syscall_helper_data *sd)
{
}
#endif

#define sucap(uaddr, base, offset, length, perms)			\
	do {								\
		struct chericap	_tmpcap;				\
		cheri_capability_set(&_tmpcap, (perms), NULL, (base),	\
		    (length), (offset));				\
		copyoutcap(&_tmpcap, uaddr, sizeof(_tmpcap));		\
	} while(0)

register_t *
cheriabi_copyout_strings(struct image_params *imgp)
{
	int argc, envc;
	struct chericap *vectp;
	char *stringp;
	uintptr_t destp;
	struct chericap *stack_base;
	struct cheriabi_ps_strings *arginfo;
	char canary[sizeof(long) * 8];
	size_t execpath_len;
	int szsigcode, szps;
	struct cheriabi_execdata ce;

	szps = sizeof(pagesizes[0]) * MAXPAGESIZES;
	/*
	 * Calculate string base and vector table pointers.
	 * Also deal with signal trampoline code for this exec type.
	 */
	if (imgp->execpath != NULL && imgp->auxargs != NULL)
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
		destp = rounddown2(destp, sizeof(struct chericap));
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
	destp = rounddown2(destp, sizeof(struct chericap));
	imgp->pagesizes = destp;
	copyout(pagesizes, (void *)destp, szps);
	imgp->pagesizeslen = szps;

	destp -= ARG_MAX - imgp->args->stringspace;
	destp = rounddown2(destp, sizeof(struct chericap));

	/* Clear execdata */
	memset(&ce, 0, sizeof(ce));
	ce.ce_len = sizeof(ce);
	ce.ce_argc = imgp->args->argc;
	cheri_capability_set(&ce.ce_ps_strings, CHERI_CAP_USER_DATA_PERMS, NULL,
	    arginfo, sizeof(struct ps_strings), 0);

	/*
	 * If we have a valid auxargs ptr, prepare some room
	 * on the stack.
	 */
	if (imgp->auxargs) {
		/*
		 * 'AT_COUNT*2' is size for the ELF Auxargs data. This is for
		 * lower compatibility.
		 */
		imgp->auxarg_size = (imgp->auxarg_size) ? imgp->auxarg_size
			: (AT_COUNT * 2);
	} else
		imgp->auxarg_size = 0;
	/*
	 * The '+ 2' is for the null pointers at the end of each of
	 * the arg and env vector sets, and imgp->auxarg_size is room
	 * for argument of runtime loader if any.
	 */
	vectp = (struct chericap *)(destp - (imgp->args->argc +
	    imgp->args->envc + 2 + imgp->auxarg_size) *
	    sizeof(struct chericap));

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
	sucap(&arginfo->ps_argvstr, vectp, 0, argc * sizeof(struct chericap),
	    CHERI_CAP_USER_DATA_PERMS);
	suword32(&arginfo->ps_nargvstr, argc);

	/*
	 * Fill in argument portion of vector table.
	 */
	cheri_capability_set(&ce.ce_argv, CHERI_CAP_USER_DATA_PERMS, NULL,
	    vectp, (argc + 1) * sizeof(struct chericap), 0);
	for (; argc > 0; --argc) {
		sucap(vectp++, (void *)destp, 0, strlen(stringp) + 1,
		    CHERI_CAP_USER_DATA_PERMS);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* a null vector table pointer separates the argp's from the envp's */
	/* XXX: suword clears the tag */
	suword(vectp++, 0);

	sucap(&arginfo->ps_envstr, vectp, 0,
	    arginfo->ps_nenvstr * sizeof(struct chericap),
	    CHERI_CAP_USER_DATA_PERMS);
	suword32(&arginfo->ps_nenvstr, envc);

	/*
	 * Fill in environment portion of vector table.
	 */
	cheri_capability_set(&ce.ce_envp, CHERI_CAP_USER_DATA_PERMS, NULL,
	    vectp, (envc + 1) * sizeof(struct chericap), 0);
	for (; envc > 0; --envc) {
		sucap(vectp++, (void *)destp, 0, strlen(stringp) + 1,
		    CHERI_CAP_USER_DATA_PERMS);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* end of vector table is a null pointer */
	/* XXX: suword clears the tag */
	suword(vectp++, 0);

	cheri_capability_set(&ce.ce_auxargs, CHERI_CAP_USER_DATA_PERMS, NULL,
	    vectp, imgp->auxarg_size * sizeof(struct chericap), 0);

	stack_base -= sizeof(ce) / sizeof(*stack_base);
	copyoutcap(&ce, stack_base, sizeof(ce));

	return ((register_t *)stack_base);
}

int
convert_sigevent_c(struct sigevent_c *sig_c, struct sigevent *sig)
{
	int error;

	CP(*sig_c, *sig, sigev_notify);
	switch (sig->sigev_notify) {
	case SIGEV_NONE:
		break;
	case SIGEV_THREAD_ID:
		CP(*sig_c, *sig, sigev_notify_thread_id);
		/* FALLTHROUGH */
	case SIGEV_SIGNAL:
		CP(*sig_c, *sig, sigev_signo);
		/*
		 * XXX-BD: this conversion follows the freebsd32 pattern,
		 * but seems likely to be wrong.  I think sigev should be
		 * opaque to the kernel and current code is lazily assuming
		 * it can be copied to avoid allocations.
		 */
		error = cheriabi_cap_to_ptr(
		    (caddr_t *)&sig->sigev_value.sival_ptr,
		    &sig_c->sigev_value.sival_ptr, 0, CHERI_PERM_GLOBAL, 1);
		if (error)
			return (error);
		break;
	case SIGEV_KEVENT:
		CP(*sig_c, *sig, sigev_notify_kqueue);
		CP(*sig_c, *sig, sigev_notify_kevent_flags);
		/* XXX-BD: see comment above */
		error = cheriabi_cap_to_ptr(
		    (caddr_t *)&sig->sigev_value.sival_ptr,
		    &sig_c->sigev_value.sival_ptr, 0, CHERI_PERM_GLOBAL, 1);
		if (error)
			return (error);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

#define	AUXARGS_ENTRY_CAP(pos, id, base, offset, len, perm)		\
	do {								\
		suword(pos++, id); sucap(pos++, (void *)(intptr_t)base,	\
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
cheriabi_set_auxargs(struct chericap *pos, struct image_params *imgp)
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
	AUXARGS_ENTRY_CAP(pos, AT_BASE, CHERI_CAP_USER_DATA_BASE, args->base,
	    CHERI_CAP_USER_DATA_LENGTH, CHERI_CAP_USER_DATA_PERMS);
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
	AUXARGS_ENTRY(pos, AT_NULL, 0);

	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;
}

int
cheriabi_elf_fixup(register_t **stack_base, struct image_params *imgp)
{
	struct chericap *base;

	base = (struct chericap *)*stack_base;
	base += sizeof(struct cheriabi_execdata) / sizeof(*base);
	base += imgp->args->argc + imgp->args->envc + 2;

	cheriabi_set_auxargs(base, imgp);

	return (0);
}

int
cheriabi_mmap(struct thread *td, struct cheriabi_mmap_args *uap)
{
	int flags = uap->flags;
	int tag;
	size_t cap_len, cap_offset;
	struct chericap addr_cap;
	register_t perms, reqperms;

	/* MAP_CHERI_NOSETBOUNDS requires MAP_FIXED. */
	if ((flags & (MAP_CHERI_NOSETBOUNDS | MAP_FIXED)) ==
	    MAP_CHERI_NOSETBOUNDS) {
#ifdef KTRACE
		if (KTRPOINT(td, KTR_SYSERRCAUSE))
			ktrsyserrcause(
			    "%s: MAP_CHERI_NOSETBOUNDS without MAP_FIXED",
			    __func__);
#endif
		return (EINVAL);
	}
	/* Forcing alignment makes no sense with MAP_CHERI_NOSETBOUNDS. */
	if ((flags & MAP_CHERI_NOSETBOUNDS) && (flags & MAP_ALIGNMENT_MASK)) {
#ifdef KTRACE
		if (KTRPOINT(td, KTR_SYSERRCAUSE))
			ktrsyserrcause(
			    "%s: MAP_CHERI_NOSETBOUNDS with alignment",
			    __func__);
#endif
		return (EINVAL);
	}

	if (!(flags & MAP_CHERI_NOSETBOUNDS)) {
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
#ifdef KTRACE
				if (KTRPOINT(td, KTR_SYSERRCAUSE))
					ktrsyserrcause(
					    "%s: subpage alignment request",
					    __func__);
#endif
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
	}
	/*
	 * XXX: If this architecture requires an alignment constraint, it is
	 * set at this point.  A simple assert is not easy to contruct...
	 */

	/*
	 * MAP_FIXED && addr != NULL.
	 */
	if (flags & MAP_FIXED) {
		cheriabi_fetch_syscall_arg(td, &addr_cap,
		    CHERIABI_SYS_cheriabi_mmap, 0);
		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &addr_cap, 0);
		CHERI_CGETTAG(tag, CHERI_CR_CTEMP0);

		if (tag) {
			CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &addr_cap, 0);
			CHERI_CGETLEN(cap_len, CHERI_CR_CTEMP0);
			CHERI_CGETOFFSET(cap_offset, CHERI_CR_CTEMP0);
			if (cap_len - cap_offset <
			    roundup2(uap->len, PAGE_SIZE)) {
#ifdef KTRACE
				if (KTRPOINT(td, KTR_SYSERRCAUSE))
					ktrsyserrcause( "%s: MAP_FIXED and "
					    "too little space in capablity "
					    "(0x%zx < 0x%zx)",
					    __func__, cap_len - cap_offset,
					    roundup2(uap->len, PAGE_SIZE));
#endif
				return (EPROT);
			}

			/*
			 * If our address is under aligned, make sure
			 * we have room to shift it down to the page
			 * boundary.
			 */
			if (((vm_offset_t)uap->addr & PAGE_MASK) > cap_offset) {
#ifdef KTRACE
				if (KTRPOINT(td, KTR_SYSERRCAUSE))
					ktrsyserrcause(
					    "%s: insufficent space to shift "
					    "addr (%p) down in capability "
					    "(offset 0x%zx)", __func__,
					    uap->addr, cap_offset);
#endif
				return (EPROT);
			}

			/*
			 * NB: We defer alignment checks to kern_mmap where we
			 * can account for file mapping with oddly aligned
			 * that match the offset alignment.
			 */

			CHERI_CGETPERM(perms, CHERI_CR_CTEMP0);
			reqperms = cheriabi_mmap_prot2perms(uap->prot);
			if ((perms & reqperms) != reqperms)
				return (EPROT);
			/*
			 * XXX-BD: What to do about permissions?
			 *
			 * Existing code expects to be able to reserve
			 * address space with PROT_NONE and then map
			 * sub-regions in with more permissions and we
			 * don't want to break that.
			 *
			 * Maybe an "upgrade allowed" user permisson bit?
			 */
		} else {
			/*
			 * XXX-BD: One could make an argument for
			 * supporting MAP_EXCL at an untagged virtual
			 * address, but use cases seem limited.
			 */
#ifdef KTRACE
			if (KTRPOINT(td, KTR_SYSERRCAUSE))
				ktrsyserrcause(
				    "%s: MAP_FIXED and untagged addr",
				    __func__);
#endif
			return (EPROT);
		}
	}

	return (kern_mmap(td, (vm_offset_t)uap->addr, uap->len, uap->prot,
	    flags, uap->fd, uap->pos));
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

void
cheriabi_mmap_set_retcap(struct thread *td, struct chericap *retcap,
   struct chericap *addr, size_t len, int prot, int flags)
{
	register_t perms, ret;
	size_t addr_base;

	ret = td->td_retval[0];
	/* On failure, return a NULL capability with an offset of -1. */
	if ((void *)ret == MAP_FAILED) {
		cheri_capability_set_null(retcap);
		cheri_capability_setoffset(retcap, (register_t)-1);
		return;
	}

	/*
	 * Leave addr alone in the MAP_CHERI_NOSETBOUNDS case.
	 *
	 * NB: This means no permission changes.
	 * The assumption is that the larger capability has the right
	 * permissions and we're only intrested in adjusting page mappings.
	 */
	if (flags & MAP_CHERI_NOSETBOUNDS) {
		cheri_capability_copy(retcap, addr);
		return;
	}

	if (flags & MAP_FIXED) {
		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, addr, 0);
	} else {
		PROC_LOCK(td->td_proc);
		CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC,
		    &td->td_proc->p_md.md_cheri_mmap_cap, 0);
		PROC_UNLOCK(td->td_proc);
	}

	CHERI_CGETPERM(perms, CHERI_CR_CTEMP0);
	CHERI_CANDPERM(CHERI_CR_CTEMP0, CHERI_CR_CTEMP0,
	    (~PERM_RWX | cheriabi_mmap_prot2perms(prot)));

	if (flags & MAP_FIXED) {
		/*
		 * If addr was under aligned, we need to return a
		 * capability to the whole, properly aligned region
		 * with the offset pointing to addr.
		 */
		CHERI_CGETBASE(addr_base, CHERI_CR_CTEMP0);
		/* Set offset to vaddr of page */
		CHERI_CSETOFFSET(CHERI_CR_CTEMP0, CHERI_CR_CTEMP0,
		    rounddown2(ret, PAGE_SIZE) - addr_base);
		CHERI_CSETBOUNDS(CHERI_CR_CTEMP0, CHERI_CR_CTEMP0,
		    roundup2(len + (ret - rounddown2(ret, PAGE_SIZE)),
		    PAGE_SIZE));
		/* Shift offset up if required */
		CHERI_CGETBASE(addr_base, CHERI_CR_CTEMP0);
		CHERI_CSETOFFSET(CHERI_CR_CTEMP0, CHERI_CR_CTEMP0,
		    addr_base - ret);
	} else {
		/*
		 * XXX-BD: Once we provide a way to change it, we need to make
		 * sure we fit within the mmap cap.
		 */
		CHERI_CSETOFFSET(CHERI_CR_CTEMP0, CHERI_CR_CTEMP0,
		    ret);
		CHERI_CSETBOUNDS(CHERI_CR_CTEMP0, CHERI_CR_CTEMP0,
		    roundup2(len, PAGE_SIZE));

	}
	CHERI_CSC(CHERI_CR_CTEMP0, CHERI_CR_KDC, retcap, 0);
}
