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

#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_util.h>

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

// accept
// accept4

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
cheriabi_recvmsg(struct thread *td, struct cheriabi_recvmsg_args *uap)
{
	kmsghdr_t msg;
	struct iovec_c *__capability uiov;
	kiovec_t * __capability iov;

	int error;

	error = copyincap_c(uap->msg, &msg, sizeof(msg));
	if (error)
		return (error);
	uiov = (struct iovec_c * __capability)msg.msg_iov;
	error = cheriabi_copyiniov(uiov, msg.msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_flags = uap->flags;
	msg.msg_iov = iov;

	error = kern_recvit(td, uap->s, &msg, UIO_USERSPACE, NULL);
	if (error == 0) {
		msg.msg_iov = (kiovec_t * __capability)uiov;

		/*
		 * Message contents have already been copied out, update
		 * lengths.
		 */
		error = copyoutcap_c(&msg, uap->msg, sizeof(msg));
	}
	free_c(iov, M_IOV);

	return (error);
}

int
cheriabi_sendmsg(struct thread *td,
		  struct cheriabi_sendmsg_args *uap)
{
	kmsghdr_t msg;
	kiovec_t * __capability iov;
	struct mbuf *control = NULL;
	struct sockaddr *to = NULL;
	int error;

	error = copyincap_c(uap->msg, &msg, sizeof(msg));
	if (error)
		return (error);
	error = cheriabi_copyiniov(msg.msg_iov, msg.msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg.msg_iov = iov;
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
		error = sockargs(&control,
		    __DECAP_CHECK(msg.msg_control, msg.msg_controllen),
		    msg.msg_controllen, MT_CONTROL);
		if (error)
			goto out;
	}

	error = kern_sendit(td, uap->s, &msg, uap->flags, control,
	    UIO_USERSPACE);

out:
	free_c(iov, M_IOV);
	if (to)
		free(to, M_SONAME);
	return (error);
}

/*
 * uipc_shm.c
 */

int
cheriabi_shm_open(struct thread *td, struct cheriabi_shm_open_args *uap)
{

	return (kern_shm_open(td, uap->path, uap->flags, uap->mode, NULL));
}

int
cheriabi_shm_unlink(struct thread *td, struct cheriabi_shm_unlink_args *uap)
{

	return (kern_shm_unlink(td, uap->path));
}
