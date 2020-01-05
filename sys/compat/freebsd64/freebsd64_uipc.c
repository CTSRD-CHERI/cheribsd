/*-
 * Copyright (c) 2015-2019 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of
 * the DARPA SSITH research programme.
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
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>

#include <compat/freebsd64/freebsd64.h>
#include <compat/freebsd64/freebsd64_proto.h>
#include <compat/freebsd64/freebsd64_util.h>

/*
 * kern_uipc.c
 */

int
freebsd64_bind(struct thread *td, struct freebsd64_bind_args *uap)
{

	return (user_bind(td, uap->s, __USER_CAP(uap->name, uap->namelen),
	    uap->namelen));
}

int
freebsd64_bindat(struct thread *td, struct freebsd64_bindat_args *uap)
{

	return (user_bindat(td, uap->fd, uap->s,
	    __USER_CAP(uap->name, uap->namelen), uap->namelen));
}

int
freebsd64_accept(struct thread *td, struct freebsd64_accept_args *uap)
{

	return (user_accept(td, uap->s, __USER_CAP_UNBOUND(uap->name),
	    __USER_CAP_OBJ(uap->anamelen), ACCEPT4_INHERIT));
}

int
freebsd64_accept4(struct thread *td, struct freebsd64_accept4_args *uap)
{

	return (user_accept(td, uap->s, __USER_CAP_UNBOUND(uap->name),
	    __USER_CAP_OBJ(uap->anamelen), uap->flags));
}

int
freebsd64_connect(struct thread *td, struct freebsd64_connect_args *uap)
{

	return (user_connectat(td, AT_FDCWD, uap->s,
	    __USER_CAP(uap->name, uap->namelen), uap->namelen));
}

int
freebsd64_connectat(struct thread *td, struct freebsd64_connectat_args *uap)
{

	return (user_connectat(td, uap->fd, uap->s,
	    __USER_CAP(uap->name, uap->namelen), uap->namelen));
}

int
freebsd64_socketpair(struct thread *td, struct freebsd64_socketpair_args *uap)
{

	return (user_socketpair(td, uap->domain, uap->type, uap->protocol,
	    __USER_CAP_ARRAY(uap->rsv, 2)));
}

int
freebsd64_sendto(struct thread *td, struct freebsd64_sendto_args *uap)
{

	return (user_sendto(td, uap->s, __USER_CAP(uap->buf, uap->len),
	    uap->len, uap->flags, __USER_CAP(uap->to, uap->tolen),
	    uap->tolen));
}

static int
freebsd64_copyinmsghdr(struct msghdr64 *msg64, struct msghdr *msg)
{
	struct msghdr64 m64;
	int error;

	error = copyin(msg64, &m64, sizeof(m64));
	if (error)
		return (error);
	msg->msg_name = __USER_CAP(m64.msg_name, m64.msg_namelen);
	msg->msg_namelen = m64.msg_namelen;
	msg->msg_iov = __USER_CAP_ARRAY(m64.msg_iov, m64.msg_iovlen);
	msg->msg_iovlen = m64.msg_iovlen;
	msg->msg_control = __USER_CAP(m64.msg_control, m64.msg_controllen);
	msg->msg_controllen = m64.msg_controllen;
	msg->msg_flags = m64.msg_flags;
	return (0);
}

/*
 * XXX-BD: arguably we should just update the lenghts and flags and leave
 * the pointers untouched.
 */
static int
freebsd64_copyoutmsghdr(struct msghdr *msg, struct msghdr64 *msg64)
{
	struct msghdr64 m64;
	int error;

	m64.msg_name = (__cheri_fromcap void *)msg->msg_name;
	m64.msg_namelen = msg->msg_namelen;
	/* Use value was previous restored. */
	m64.msg_iov = (__cheri_fromcap void *)msg->msg_iov;
	m64.msg_iovlen = msg->msg_iovlen;
	m64.msg_control = (__cheri_fromcap void *)msg->msg_control;
	m64.msg_controllen = msg->msg_controllen;
	m64.msg_flags = msg->msg_flags;
	error = copyout(&m64, msg64, sizeof(m64));
	return (error);
}

#define	FREEBSD64_ALIGNBYTES	(sizeof(long) - 1)
#define FREEBSD64_ALIGN(p)	\
    (((u_long)(p) + FREEBSD64_ALIGNBYTES) & ~FREEBSD64_ALIGNBYTES)
#define	FREEBSD64_CMSG_SPACE(l)	\
    (FREEBSD64_ALIGN(sizeof(struct cmsghdr)) + FREEBSD64_ALIGN(l))

/*
 * XXX-BD: does this actually need to exist?  We don't need to do time
 * conversions like on i386, but maybe alignment is an issue...
 */
static int
freebsd64_copy_msg_out(struct msghdr *msg, struct mbuf *control)
{
	struct cmsghdr *cm;
	void *data;
	socklen_t clen, datalen, oldclen;
	int error;
	char * __capability ctlbuf;
	int len, maxlen, copylen;
	struct mbuf *m;
	error = 0;

	len    = msg->msg_controllen;
	maxlen = msg->msg_controllen;
	msg->msg_controllen = 0;

	ctlbuf = msg->msg_control;
	for (m = control; m != NULL && len > 0; m = m->m_next) {
		cm = mtod(m, struct cmsghdr *);
		clen = m->m_len;
		while (cm != NULL) {
			if (sizeof(struct cmsghdr) > clen ||
			    cm->cmsg_len > clen) {
				error = EINVAL;
				break;
			}

			data   = CMSG_DATA(cm);
			datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;

			/*
			 * Copy out the message header.  Preserve the native
			 * message size in case we need to inspect the message
			 * contents later.
			 */
			copylen = sizeof(struct cmsghdr);
			if (len < copylen) {
				msg->msg_flags |= MSG_CTRUNC;
				m_dispose_extcontrolm(m);
				goto exit;
			}
			oldclen = cm->cmsg_len;
			cm->cmsg_len = FREEBSD64_ALIGN(sizeof(struct cmsghdr)) +
			    datalen;
			error = copyout_c(cm, ctlbuf, copylen);
			cm->cmsg_len = oldclen;
			if (error != 0)
				goto exit;

			ctlbuf += FREEBSD64_ALIGN(copylen);
			len    -= FREEBSD64_ALIGN(copylen);

			copylen = datalen;
			if (len < copylen) {
				msg->msg_flags |= MSG_CTRUNC;
				m_dispose_extcontrolm(m);
				break;
			}

			/* Copy out the message data. */
			error = copyout_c(data, ctlbuf, copylen);
			if (error)
				goto exit;

			ctlbuf += FREEBSD64_ALIGN(copylen);
			len    -= FREEBSD64_ALIGN(copylen);

			if (CMSG_SPACE(datalen) < clen) {
				clen -= CMSG_SPACE(datalen);
				cm = (struct cmsghdr *)
				    ((caddr_t)cm + CMSG_SPACE(datalen));
			} else {
				clen = 0;
				cm = NULL;
			}

			msg->msg_controllen += FREEBSD64_CMSG_SPACE(datalen);
		}
	}
	if (len == 0 && m != NULL) {
		msg->msg_flags |= MSG_CTRUNC;
		m_dispose_extcontrolm(m);
	}

exit:
	return (error);
}

int
freebsd64_sendmsg(struct thread *td, struct freebsd64_sendmsg_args *uap)
{
	struct msghdr msg;
	struct msghdr64 m64;
	struct iovec *iov;
	int error;

	error = copyin(uap->msg, &m64, sizeof(m64));
	if (error != 0)
		return (error);
	msg.msg_name = __USER_CAP(m64.msg_name, m64.msg_namelen);
	msg.msg_namelen = m64.msg_namelen;
	error = freebsd64_copyiniov(__USER_CAP_ARRAY(m64.msg_iov,
	    m64.msg_iovlen), m64.msg_iovlen, &iov, EMSGSIZE);
	if (error != 0)
		return (error);
	msg.msg_iov = (__cheri_tocap struct iovec * __capability)iov;
	msg.msg_iovlen = m64.msg_iovlen;
	msg.msg_control = __USER_CAP(m64.msg_control, m64.msg_controllen);
	msg.msg_controllen = m64.msg_controllen;
	/* No COMPAT_OLDSOCK support, no 64-bit 43BSD binaries should exist. */
	msg.msg_flags = m64.msg_flags;
	error = user_sendit(td, uap->s, &msg, uap->flags);
	free(iov, M_IOV);
	return (error);
}

int
freebsd64_recvfrom(struct thread *td, struct freebsd64_recvfrom_args *uap)
{

	return (kern_recvfrom(td, uap->s, __USER_CAP(uap->buf, uap->len),
	    uap->len, uap->flags, __USER_CAP_UNBOUND(uap->from),
	    __USER_CAP_OBJ(uap->fromlenaddr)));
}

int
freebsd64_recvmsg(struct thread *td, struct freebsd64_recvmsg_args *uap)
{
	struct msghdr msg;
	struct msghdr64 m64;
	struct iovec * __capability uiov, *iov;
	struct mbuf *control = NULL;
	struct mbuf **controlp;
	int error;

	error = copyin(uap->msg, &m64, sizeof(m64));
	if (error != 0)
		return (error);
	error = freebsd64_copyinmsghdr(uap->msg, &msg);
	if (error != 0)
		return (error);
	error = freebsd64_copyiniov(__USER_CAP_ARRAY(m64.msg_iov,
	    m64.msg_iovlen), m64.msg_iovlen, &iov, EMSGSIZE);
	if (error != 0)
		return (error);
	msg.msg_flags = uap->flags;
	uiov = msg.msg_iov;
	msg.msg_iov = (__cheri_tocap struct iovec * __capability)iov;

	controlp = (msg.msg_control != NULL) ?  &control : NULL;
	error = kern_recvit(td, uap->s, &msg, UIO_USERSPACE, controlp);
	if (error == 0) {
		msg.msg_iov = uiov;

		if (control != NULL)
			error = freebsd64_copy_msg_out(&msg, control);
		else
			msg.msg_controllen = 0;

		if (error == 0)
			error = freebsd64_copyoutmsghdr(&msg, uap->msg);
	}
	free(iov, M_IOV);

	if (control != NULL) {
		if (error != 0)
			m_dispose_extcontrolm(control);
		m_freem(control);
	}

	return (error);
}

int
freebsd64_setsockopt(struct thread *td, struct freebsd64_setsockopt_args *uap)
{

	return (kern_setsockopt(td, uap->s, uap->level, uap->name,
	    __USER_CAP(uap->val, uap->valsize), UIO_USERSPACE, uap->valsize));
}

int
freebsd64_getsockopt(struct thread *td, struct freebsd64_getsockopt_args *uap)
{

	return (user_getsockopt(td, uap->s, uap->level, uap->name,
	    __USER_CAP_UNBOUND(uap->val), __USER_CAP_OBJ(uap->avalsize)));
}

int
freebsd64_getsockname(struct thread *td, struct freebsd64_getsockname_args *uap)
{

	return (user_getsockname(td, uap->fdes, __USER_CAP_UNBOUND(uap->asa),
	    __USER_CAP_OBJ(uap->alen), 0));
}

int
freebsd64_getpeername(struct thread *td, struct freebsd64_getpeername_args *uap)
{

	return (user_getpeername(td, uap->fdes, __USER_CAP_UNBOUND(uap->asa),
	    __USER_CAP_OBJ(uap->alen), 0));
}

/*
 * uipc_shm.c
 */

#ifdef COMPAT_FREEBSD12
int
freebsd12_freebsd64_shm_open(struct thread *td,
    struct freebsd12_freebsd64_shm_open_args *uap)
{

	return (kern_shm_open(td, __USER_CAP_STR(uap->path),
	    uap->flags | O_CLOEXEC, uap->mode, NULL, F_SEAL_SEAL));
}
#endif

int
freebsd64_shm_open2(struct thread *td, struct freebsd64_shm_open2_args *uap)
{

	return (kern_shm_open2(td, __USER_CAP_STR(uap->path), uap->flags,
	    uap->mode, uap->shmflags, NULL, __USER_CAP_STR(uap->name)));
}

int
freebsd64_shm_unlink(struct thread *td, struct freebsd64_shm_unlink_args *uap)
{

	return (kern_shm_unlink(td, __USER_CAP_STR(uap->path)));
}

int
freebsd64_shm_rename(struct thread *td, struct freebsd64_shm_rename_args *uap)
{

	return (kern_shm_rename(td, __USER_CAP_STR(uap->path_from),
	    __USER_CAP_STR(uap->path_to), uap->flags));
}
