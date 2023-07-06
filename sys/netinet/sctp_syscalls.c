/*-
 * Copyright (c) 1982, 1986, 1989, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"
#include "opt_sctp.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/filedesc.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/sf_buf.h>
#include <sys/sysent.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/signalvar.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#ifdef COMPAT_FREEBSD32
#include <compat/freebsd32/freebsd32.h>
#include <compat/freebsd32/freebsd32_syscall.h>
#include <compat/freebsd32/freebsd32_util.h>
#include <compat/freebsd32/freebsd32_syscall.h>
#include <compat/freebsd32/freebsd32_proto.h>
#endif
#ifdef COMPAT_FREEBSD64
#include <compat/freebsd64/freebsd64.h>
#include <compat/freebsd64/freebsd64_util.h>
#include <compat/freebsd64/freebsd64_syscall.h>
#include <compat/freebsd64/freebsd64_proto.h>
#endif

#include <net/vnet.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <netinet/sctp.h>
#include <netinet/sctp_os_bsd.h>
#include <netinet/sctp_peeloff.h>

static struct syscall_helper_data sctp_syscalls[] = {
	SYSCALL_INIT_HELPER_F(sctp_peeloff, SYF_CAPENABLED),
	SYSCALL_INIT_HELPER_F(sctp_generic_sendmsg, SYF_CAPENABLED),
	SYSCALL_INIT_HELPER_F(sctp_generic_sendmsg_iov, SYF_CAPENABLED),
	SYSCALL_INIT_HELPER_F(sctp_generic_recvmsg, SYF_CAPENABLED),
	SYSCALL_INIT_LAST
};

#ifdef COMPAT_FREEBSD32
static struct syscall_helper_data sctp32_syscalls[] = {
	SYSCALL32_INIT_HELPER_COMPAT(sctp_peeloff),
	SYSCALL32_INIT_HELPER_COMPAT(sctp_generic_sendmsg),
	SYSCALL32_INIT_HELPER(freebsd32_sctp_generic_sendmsg_iov),
	SYSCALL32_INIT_HELPER(freebsd32_sctp_generic_recvmsg),
	SYSCALL_INIT_LAST
};
#endif

#ifdef COMPAT_FREEBSD64
static struct syscall_helper_data sctp64_syscalls[] = {
	FREEBSD64_SYSCALL_INIT_HELPER_COMPAT(sctp_peeloff),
	FREEBSD64_SYSCALL_INIT_HELPER(freebsd64_sctp_generic_sendmsg),
	FREEBSD64_SYSCALL_INIT_HELPER(freebsd64_sctp_generic_sendmsg_iov),
	FREEBSD64_SYSCALL_INIT_HELPER(freebsd64_sctp_generic_recvmsg),
	SYSCALL_INIT_LAST
};
#endif

static int	kern_sys_sctp_generic_sendmsg(struct thread *td, int sd,
		    void * __capability msg, int mlen,
		    const struct sockaddr * __capability uto, socklen_t tolen,
		    struct sctp_sndrcvinfo * __capability usinfo, int flags);
static int	kern_sctp_generic_sendmsg_iov(struct thread *td, int sd,
		    struct iovec * __capability uiov, int iovlen,
		    const struct sockaddr * __capability uto, socklen_t tolen,
		    struct sctp_sndrcvinfo * __capability usinfo, int flags,
		    copyiniov_t *copyiniov_f);
static int	kern_sctp_generic_recvmsg(struct thread *td, int sd,
		    struct iovec * __capability uiov, int iovlen,
		    struct sockaddr * __capability from,
		    socklen_t * __capability fromlenaddr,
		    struct sctp_sndrcvinfo * __capability usinfo,
		    int * __capability umsg_flags,
		    copyiniov_t *copyiniov_f);

int
sctp_syscalls_init(void)
{
	int error;

	error = syscall_helper_register(sctp_syscalls, SY_THR_STATIC_KLD);
	if (error != 0)
		return (error);
#ifdef COMPAT_FREEBSD32
	error = syscall32_helper_register(sctp32_syscalls, SY_THR_STATIC_KLD);
	if (error != 0)
		return (error);
#endif
#ifdef COMPAT_FREEBSD64
	error = freebsd64_syscall_helper_register(sctp64_syscalls,
	    SY_THR_STATIC_KLD);
	if (error != 0)
		return (error);
#endif
	return (0);
}

#ifdef SCTP
SYSINIT(sctp_syscalls, SI_SUB_SYSCALLS, SI_ORDER_ANY, sctp_syscalls_init, NULL);
#endif

int
sctp_syscalls_uninit(void)
{
	int error;

#ifdef COMPAT_FREEBSD64
	error = freebsd64_syscall_helper_unregister(sctp64_syscalls);
	if (error != 0)
		return (error);
#endif
#ifdef COMPAT_FREEBSD32
	error = syscall32_helper_unregister(sctp32_syscalls);
	if (error != 0)
		return (error);
#endif
	error = syscall_helper_unregister(sctp_syscalls);
	if (error != 0)
		return (error);
	return (0);
}

/*
 * SCTP syscalls.
 */
#ifndef _SYS_SYSPROTO_H_
struct sctp_peeloff_args {
int	sd;
	caddr_t	name;
};
#endif
int
sys_sctp_peeloff(struct thread *td, struct sctp_peeloff_args *uap)
{
	struct file *headfp, *nfp = NULL;
	struct socket *head, *so;
	cap_rights_t rights;
	u_int fflag;
	int error, fd;

	AUDIT_ARG_FD(uap->sd);
	error = getsock(td, uap->sd, cap_rights_init_one(&rights, CAP_PEELOFF),
	    &headfp);
	if (error != 0)
		goto done2;
	fflag = atomic_load_int(&headfp->f_flag);
	head = headfp->f_data;
	if (head->so_proto->pr_protocol != IPPROTO_SCTP) {
		error = EOPNOTSUPP;
		goto done;
	}
	error = sctp_can_peel_off(head, (sctp_assoc_t)uap->name);
	if (error != 0)
		goto done;
	/*
	 * At this point we know we do have a assoc to pull
	 * we proceed to get the fd setup. This may block
	 * but that is ok.
	 */

	error = falloc(td, &nfp, &fd, 0);
	if (error != 0)
		goto done;
	td->td_retval[0] = fd;

	CURVNET_SET(head->so_vnet);
	so = sopeeloff(head);
	if (so == NULL) {
		error = ENOMEM;
		goto noconnection;
	}
	finit(nfp, fflag, DTYPE_SOCKET, so, &socketops);
	error = sctp_do_peeloff(head, so, (sctp_assoc_t)uap->name);
	if (error != 0)
		goto noconnection;
	if (head->so_sigio != NULL)
		fsetown(fgetown(&head->so_sigio), &so->so_sigio);

noconnection:
	/*
	 * close the new descriptor, assuming someone hasn't ripped it
	 * out from under us.
	 */
	if (error != 0)
		fdclose(td, nfp, fd);

	/*
	 * Release explicitly held references before returning.
	 */
	CURVNET_RESTORE();
done:
	if (nfp != NULL)
		fdrop(nfp, td);
	fdrop(headfp, td);
done2:
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct sctp_generic_sendmsg_args {
	int sd;
	caddr_t msg;
	int mlen;
	const struct sockaddr *to;
	__socklen_t tolen;
	struct sctp_sndrcvinfo *sinfo;
	int flags;
};
#endif
int
sys_sctp_generic_sendmsg(struct thread *td, struct sctp_generic_sendmsg_args *uap)
{

	return (kern_sys_sctp_generic_sendmsg(td, uap->sd, uap->msg, uap->mlen,
	    uap->to, uap->tolen, uap->sinfo, uap->flags));
}

#ifdef COMPAT_FREEBSD64
int
freebsd64_sctp_generic_sendmsg(struct thread *td,
    struct freebsd64_sctp_generic_sendmsg_args *uap)
{

	return (kern_sys_sctp_generic_sendmsg(td, uap->sd,
	    __USER_CAP(uap->msg, uap->mlen), uap->mlen,
	    __USER_CAP(uap->to, uap->tolen), uap->tolen,
	    __USER_CAP_OBJ(uap->sinfo), uap->flags));
}
#endif

static int
kern_sys_sctp_generic_sendmsg(struct thread *td, int sd,
    void * __capability msg, int mlen, const struct sockaddr * __capability uto,
    socklen_t tolen, struct sctp_sndrcvinfo * __capability usinfo, int flags)
{
	struct sctp_sndrcvinfo sinfo, *u_sinfo = NULL;
	struct socket *so;
	struct file *fp = NULL;
	struct sockaddr *to = NULL;
#ifdef KTRACE
	struct uio *ktruio = NULL;
#endif
	struct uio auio;
	struct iovec iov[1];
	cap_rights_t rights;
	int error = 0, len;

	if (usinfo != NULL) {
		error = copyin(usinfo, &sinfo, sizeof(sinfo));
		if (error != 0)
			return (error);
		u_sinfo = &sinfo;
	}

	cap_rights_init_one(&rights, CAP_SEND);
	if (tolen != 0) {
		error = getsockaddr(&to, uto, tolen);
		if (error != 0) {
			to = NULL;
			goto sctp_bad2;
		}
		cap_rights_set_one(&rights, CAP_CONNECT);
	}

	AUDIT_ARG_FD(sd);
	error = getsock(td, sd, &rights, &fp);
	if (error != 0)
		goto sctp_bad;
#ifdef KTRACE
	if (to && (KTRPOINT(td, KTR_STRUCT)))
		ktrsockaddr(to);
#endif

	IOVEC_INIT_C(&iov[0], msg, mlen);

	so = (struct socket *)fp->f_data;
	if (so->so_proto->pr_protocol != IPPROTO_SCTP) {
		error = EOPNOTSUPP;
		goto sctp_bad;
	}
#ifdef MAC
	error = mac_socket_check_send(td->td_ucred, so);
	if (error != 0)
		goto sctp_bad;
#endif /* MAC */

	auio.uio_iov =  iov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(&auio);
#endif /* KTRACE */
	len = auio.uio_resid = mlen;
	CURVNET_SET(so->so_vnet);
	error = sctp_lower_sosend(so, to, &auio, (struct mbuf *)NULL,
	    (struct mbuf *)NULL, flags, u_sinfo, td);
	CURVNET_RESTORE();
	if (error != 0) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* Generation of SIGPIPE can be controlled per socket. */
		if (error == EPIPE && !(so->so_options & SO_NOSIGPIPE) &&
		    !(flags & MSG_NOSIGNAL)) {
			PROC_LOCK(td->td_proc);
			tdsignal(td, SIGPIPE);
			PROC_UNLOCK(td->td_proc);
		}
	}
	if (error == 0)
		td->td_retval[0] = len - auio.uio_resid;
#ifdef KTRACE
	if (ktruio != NULL) {
		ktruio->uio_resid = td->td_retval[0];
		ktrgenio(sd, UIO_WRITE, ktruio, error);
	}
#endif /* KTRACE */
sctp_bad:
	if (fp != NULL)
		fdrop(fp, td);
sctp_bad2:
	free(to, M_SONAME);
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct sctp_generic_sendmsg_iov_args {
	int sd;
	struct iovec *iov;
	int iovlen;
	struct sockaddr *to;
	__socklen_t tolen;
	struct sctp_sndrcvinfo *sinfo;
	int flags;
};
#endif
int
sys_sctp_generic_sendmsg_iov(struct thread *td, struct sctp_generic_sendmsg_iov_args *uap)
{

	return (kern_sctp_generic_sendmsg_iov(td, uap->sd, uap->iov,
	    uap->iovlen, uap->to, uap->tolen, uap->sinfo, uap->flags,
	    copyiniov));
}

#ifdef COMPAT_FREEBSD32
int
freebsd32_sctp_generic_sendmsg_iov(struct thread *td,
    struct freebsd32_sctp_generic_sendmsg_iov_args *uap)
{

	return (kern_sctp_generic_sendmsg_iov(td, uap->sd,
	    (struct iovec * __capability)__USER_CAP_ARRAY(uap->iov, uap->iovlen),
	    uap->iovlen, __USER_CAP(uap->to, uap->tolen), uap->tolen,
	    __USER_CAP_OBJ(uap->sinfo), uap->flags, freebsd32_copyiniov));
}
#endif

#ifdef COMPAT_FREEBSD64
int
freebsd64_sctp_generic_sendmsg_iov(struct thread *td,
    struct freebsd64_sctp_generic_sendmsg_iov_args *uap)
{

	return (kern_sctp_generic_sendmsg_iov(td, uap->sd,
	    (struct iovec * __capability)__USER_CAP_ARRAY(uap->iov, uap->iovlen),
	    uap->iovlen, __USER_CAP(uap->to, uap->tolen), uap->tolen,
	    __USER_CAP_OBJ(uap->sinfo), uap->flags, freebsd64_copyiniov));
}
#endif

static int
kern_sctp_generic_sendmsg_iov(struct thread *td, int sd,
    struct iovec * __capability uiov, int iovlen,
    const struct sockaddr * __capability uto, socklen_t tolen,
    struct sctp_sndrcvinfo * __capability usinfo, int flags,
    copyiniov_t *copyiniov_f)
{
	struct sctp_sndrcvinfo sinfo, *u_sinfo = NULL;
	struct socket *so;
	struct file *fp = NULL;
	struct sockaddr *to = NULL;
#ifdef KTRACE
	struct uio *ktruio = NULL;
#endif
	struct uio auio;
	struct iovec *iov, *tiov;
	cap_rights_t rights;
	ssize_t len;
	int error, i;

	if (usinfo != NULL) {
		error = copyin(usinfo, &sinfo, sizeof(sinfo));
		if (error != 0)
			return (error);
		u_sinfo = &sinfo;
	}
	cap_rights_init_one(&rights, CAP_SEND);
	if (tolen != 0) {
		error = getsockaddr(&to, uto, tolen);
		if (error != 0) {
			to = NULL;
			goto sctp_bad2;
		}
		cap_rights_set_one(&rights, CAP_CONNECT);
	}

	AUDIT_ARG_FD(sd);
	error = getsock(td, sd, &rights, &fp);
	if (error != 0)
		goto sctp_bad1;

	error = copyiniov_f(uiov, iovlen, &iov, EMSGSIZE);
	if (error != 0)
		goto sctp_bad1;
#ifdef KTRACE
	if (to && (KTRPOINT(td, KTR_STRUCT)))
		ktrsockaddr(to);
#endif

	so = (struct socket *)fp->f_data;
	if (so->so_proto->pr_protocol != IPPROTO_SCTP) {
		error = EOPNOTSUPP;
		goto sctp_bad;
	}
#ifdef MAC
	error = mac_socket_check_send(td->td_ucred, so);
	if (error != 0)
		goto sctp_bad;
#endif /* MAC */

	auio.uio_iov = iov;
	auio.uio_iovcnt = iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	tiov = iov;
	for (i = 0; i <iovlen; i++, tiov++) {
		if ((auio.uio_resid += tiov->iov_len) < 0) {
			error = EINVAL;
			goto sctp_bad;
		}
	}
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(&auio);
#endif /* KTRACE */
	len = auio.uio_resid;
	CURVNET_SET(so->so_vnet);
	error = sctp_lower_sosend(so, to, &auio,
		    (struct mbuf *)NULL, (struct mbuf *)NULL,
		    flags, u_sinfo, td);
	CURVNET_RESTORE();
	if (error != 0) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* Generation of SIGPIPE can be controlled per socket */
		if (error == EPIPE && !(so->so_options & SO_NOSIGPIPE) &&
		    !(flags & MSG_NOSIGNAL)) {
			PROC_LOCK(td->td_proc);
			tdsignal(td, SIGPIPE);
			PROC_UNLOCK(td->td_proc);
		}
	}
	if (error == 0)
		td->td_retval[0] = len - auio.uio_resid;
#ifdef KTRACE
	if (ktruio != NULL) {
		ktruio->uio_resid = td->td_retval[0];
		ktrgenio(sd, UIO_WRITE, ktruio, error);
	}
#endif /* KTRACE */
sctp_bad:
	free(iov, M_IOV);
sctp_bad1:
	if (fp != NULL)
		fdrop(fp, td);
sctp_bad2:
	free(to, M_SONAME);
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct sctp_generic_recvmsg_args {
	int sd;
	struct iovec *iov;
	int iovlen;
	struct sockaddr *from;
	__socklen_t *fromlenaddr;
	struct sctp_sndrcvinfo *sinfo;
	int *msg_flags;
};
#endif
int
sys_sctp_generic_recvmsg(struct thread *td, struct sctp_generic_recvmsg_args *uap)
{

	return (kern_sctp_generic_recvmsg(td, uap->sd, uap->iov, uap->iovlen,
	    uap->from, uap->fromlenaddr, uap->sinfo, uap->msg_flags,
	    copyiniov));
}

#ifdef COMPAT_FREEBSD32
int
freebsd32_sctp_generic_recvmsg(struct thread *td,
    struct freebsd32_sctp_generic_recvmsg_args *uap)
{

	return (kern_sctp_generic_recvmsg(td, uap->sd,
	    (struct iovec * __capability)__USER_CAP_ARRAY(uap->iov, uap->iovlen),
	    uap->iovlen, __USER_CAP_UNBOUND(uap->from),
	    __USER_CAP_OBJ(uap->fromlenaddr), __USER_CAP_OBJ(uap->sinfo),
	    __USER_CAP_OBJ(uap->msg_flags), freebsd32_copyiniov));
}
#endif

#ifdef COMPAT_FREEBSD64
int
freebsd64_sctp_generic_recvmsg(struct thread *td,
    struct freebsd64_sctp_generic_recvmsg_args *uap)
{

	return (kern_sctp_generic_recvmsg(td, uap->sd,
	    (struct iovec * __capability)__USER_CAP_ARRAY(uap->iov, uap->iovlen),
	    uap->iovlen, __USER_CAP_UNBOUND(uap->from),
	    __USER_CAP_OBJ(uap->fromlenaddr), __USER_CAP_OBJ(uap->sinfo),
	    __USER_CAP_OBJ(uap->msg_flags), freebsd64_copyiniov));
}
#endif

static int
kern_sctp_generic_recvmsg(struct thread *td, int sd,
    struct iovec * __capability uiov, int iovlen,
    struct sockaddr * __capability from, socklen_t * __capability fromlenaddr,
    struct sctp_sndrcvinfo * __capability usinfo,
    int * __capability umsg_flags, copyiniov_t *copyiniov_f)
{
	uint8_t sockbufstore[256];
	struct uio auio;
	struct iovec *iov, *tiov;
	struct sctp_sndrcvinfo sinfo;
	struct socket *so;
	struct file *fp = NULL;
	struct sockaddr *fromsa;
	cap_rights_t rights;
#ifdef KTRACE
	struct uio *ktruio = NULL;
#endif
	ssize_t len;
	int error, fromlen, i, msg_flags;

	AUDIT_ARG_FD(sd);
	error = getsock(td, sd, cap_rights_init_one(&rights, CAP_RECV), &fp);
	if (error != 0)
		return (error);
	error = copyiniov_f(uiov, iovlen, &iov, EMSGSIZE);
	if (error != 0)
		goto out1;

	so = fp->f_data;
	if (so->so_proto->pr_protocol != IPPROTO_SCTP) {
		error = EOPNOTSUPP;
		goto out;
	}
#ifdef MAC
	error = mac_socket_check_receive(td->td_ucred, so);
	if (error != 0)
		goto out;
#endif /* MAC */

	if (fromlenaddr != NULL) {
		error = copyin(fromlenaddr, &fromlen, sizeof(fromlen));
		if (error != 0)
			goto out;
	} else {
		fromlen = 0;
	}
	if (umsg_flags) {
		error = copyin(umsg_flags, &msg_flags, sizeof(int));
		if (error != 0)
			goto out;
	} else {
		msg_flags = 0;
	}
	auio.uio_iov = iov;
	auio.uio_iovcnt = iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_td = td;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	tiov = iov;
	for (i = 0; i <iovlen; i++, tiov++) {
		if ((auio.uio_resid += tiov->iov_len) < 0) {
			error = EINVAL;
			goto out;
		}
	}
	len = auio.uio_resid;
	fromsa = (struct sockaddr *)sockbufstore;

#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(&auio);
#endif /* KTRACE */
	memset(&sinfo, 0, sizeof(struct sctp_sndrcvinfo));
	CURVNET_SET(so->so_vnet);
	error = sctp_sorecvmsg(so, &auio, (struct mbuf **)NULL,
		    fromsa, fromlen, &msg_flags,
		    (struct sctp_sndrcvinfo *)&sinfo, 1);
	CURVNET_RESTORE();
	if (error != 0) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	} else {
		if (usinfo)
			error = copyout(&sinfo, usinfo, sizeof(sinfo));
	}
#ifdef KTRACE
	if (ktruio != NULL) {
		ktruio->uio_resid = len - auio.uio_resid;
		ktrgenio(sd, UIO_READ, ktruio, error);
	}
#endif /* KTRACE */
	if (error != 0)
		goto out;
	td->td_retval[0] = len - auio.uio_resid;

	if (fromlen && from != NULL) {
		len = fromlen;
		if (len <= 0 || fromsa == NULL)
			len = 0;
		else {
			len = MIN(len, fromsa->sa_len);
			error = copyout(fromsa, from, (size_t)len);
			if (error != 0)
				goto out;
		}
		error = copyout(&len, fromlenaddr, sizeof (socklen_t));
		if (error != 0)
			goto out;
	}
#ifdef KTRACE
	if (KTRPOINT(td, KTR_STRUCT))
		ktrsockaddr(fromsa);
#endif
	if (umsg_flags) {
		error = copyout(&msg_flags, umsg_flags, sizeof (int));
		if (error != 0)
			goto out;
	}
out:
	free(iov, M_IOV);
out1:
	if (fp != NULL)
		fdrop(fp, td);

	return (error);
}
// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "kernel",
//   "changes": [
//     "iovec-macros",
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
