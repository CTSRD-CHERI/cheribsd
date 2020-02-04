/*-
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

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>

#include <compat/cheriabi/cheriabi_misc.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_util.h>

struct msghdr_c {
	void		* __capability msg_name;		/* optional address */
	socklen_t	 msg_namelen;		/* size of address */
	struct iovec_c	* __capability msg_iov;		/* scatter/gather array */
	int		 msg_iovlen;		/* # elements in msg_iov */
	void		* __capability msg_control;		/* ancillary data, see below */
	socklen_t	 msg_controllen;	/* ancillary data buffer len */
	int		 msg_flags;		/* flags on received message */
};

/*
 * kern_uipc.c
 */

int
cheriabi_bind(struct thread *td, struct cheriabi_bind_args *uap)
{

	return (user_bind(td, uap->s, uap->name, uap->namelen));
}

int
cheriabi_bindat(struct thread *td, struct cheriabi_bindat_args *uap)
{

	return (user_bindat(td, uap->fd, uap->s, uap->name, uap->namelen));
}

int
cheriabi_accept(struct thread *td, struct cheriabi_accept_args *uap)
{

	return (user_accept(td, uap->s, uap->name, uap->anamelen,
	    ACCEPT4_INHERIT));
}

int
cheriabi_accept4(struct thread *td, struct cheriabi_accept4_args *uap)
{

	return (user_accept(td, uap->s, uap->name, uap->anamelen, uap->flags));
}

int
cheriabi_connect(struct thread *td, struct cheriabi_connect_args *uap)
{

	return (user_connectat(td, AT_FDCWD, uap->s, uap->name, uap->namelen));
}

int
cheriabi_connectat(struct thread *td, struct cheriabi_connectat_args *uap)
{

	return (user_connectat(td, uap->fd, uap->s, uap->name, uap->namelen));
}

int
cheriabi_socketpair(struct thread *td, struct cheriabi_socketpair_args *uap)
{

	return (user_socketpair(td, uap->domain, uap->type, uap->protocol,
	    uap->rsv));
}

int
cheriabi_sendto(struct thread *td, struct cheriabi_sendto_args *uap)
{

	return (user_sendto(td, uap->s, uap->buf, uap->len, uap->flags,
	    uap->to, uap->tolen));
}

int
cheriabi_sendmsg(struct thread *td, struct cheriabi_sendmsg_args *uap)
{
	struct msghdr_c msg;
	struct iovec_c *iov;
	struct mbuf *control = NULL;
	struct sockaddr *to = NULL;
	int error;

	error = copyincap(uap->msg, &msg, sizeof(msg));
	if (error)
		return (error);
	error = cheriabi_copyiniov(msg.msg_iov, msg.msg_iovlen,
	    (struct iovec **)&iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_iov = (__cheri_tocap struct iovec_c * __capability)iov;
	if (msg.msg_name != NULL) {
		error = getsockaddr(&to, msg.msg_name, msg.msg_namelen);
		if (error) {
			to = NULL;
			goto out;
		}
		msg.msg_name = (__cheri_tocap void * __capability)to;
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
		error = sockargs(&control, msg.msg_control,
		    msg.msg_controllen, MT_CONTROL);
		if (error)
			goto out;
	}

	error = kern_sendit(td, uap->s, (struct msghdr *)&msg, uap->flags,
	    control, UIO_USERSPACE);

out:
	free(iov, M_IOV);
	if (to)
		free(to, M_SONAME);
	return (error);
}

int
cheriabi_recvfrom(struct thread *td, struct cheriabi_recvfrom_args *uap)
{

	return (kern_recvfrom(td, uap->s, uap->buf, uap->len, uap->flags,
	    uap->from, uap->fromlenaddr));
}

int
cheriabi_recvmsg(struct thread *td, struct cheriabi_recvmsg_args *uap)
{
	struct msghdr_c msg;
	struct iovec_c *__capability uiov;
	struct iovec_c *iov;

	int error;

	error = copyincap(uap->msg, &msg, sizeof(msg));
	if (error)
		return (error);
	uiov = msg.msg_iov;
	error = cheriabi_copyiniov(uiov, msg.msg_iovlen,
	    (struct iovec **)&iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_flags = uap->flags;
	msg.msg_iov = (__cheri_tocap struct iovec_c * __capability)iov;

	error = kern_recvit(td, uap->s, (struct msghdr *)&msg, UIO_USERSPACE,
	    NULL);
	if (error == 0) {
		msg.msg_iov = uiov;

		/*
		 * Message contents have already been copied out, update
		 * lengths.
		 */
		error = copyoutcap(&msg, uap->msg, sizeof(msg));
	}
	free(iov, M_IOV);

	return (error);
}

int
cheriabi_setsockopt(struct thread *td, struct cheriabi_setsockopt_args *uap)
{

	return (kern_setsockopt(td, uap->s, uap->level, uap->name,
	    uap->val, UIO_USERSPACE, uap->valsize));
}

int
cheriabi_getsockopt(struct thread *td, struct cheriabi_getsockopt_args *uap)
{

	return (user_getsockopt(td, uap->s, uap->level, uap->name, uap->val,
	    uap->avalsize));
}

int
cheriabi_getsockname(struct thread *td, struct cheriabi_getsockname_args *uap)
{

	return (user_getsockname(td, uap->fdes, uap->asa, uap->alen, 0));
}

int
cheriabi_getpeername(struct thread *td, struct cheriabi_getpeername_args *uap)
{

	return (user_getpeername(td, uap->fdes, uap->asa, uap->alen, 0));
}

/*
 * uipc_shm.c
 */

int
cheriabi_shm_open2(struct thread *td, struct cheriabi_shm_open2_args *uap)
{

	return (kern_shm_open2(td, uap->path, uap->flags, uap->mode,
	    uap->shmflags, NULL, uap->name));
}

int
cheriabi_shm_unlink(struct thread *td, struct cheriabi_shm_unlink_args *uap)
{

	return (kern_shm_unlink(td, uap->path));
}

int
cheriabi_shm_rename(struct thread *td, struct cheriabi_shm_rename_args *uap)
{

	return (kern_shm_rename(td, uap->path_from, uap->path_to,
	    uap->flags));
}
