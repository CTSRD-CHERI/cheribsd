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
freebsd64_copyinmsghdr(struct msghdr64 *msg64, struct msghdr *msg, struct msghdr64 *m64)
{
	struct iovec *iov;
	int error;

	error = copyin(msg64, m64, sizeof(*m64));
	if (error)
		return (error);
	msg->msg_name = __USER_CAP(m64->msg_name, m64->msg_namelen);
	msg->msg_namelen = m64->msg_namelen;

	msg->msg_iov = NULL;
	error = freebsd64_copyiniov(
	    __USER_CAP_ARRAY((struct iovec64 *)(uintptr_t)m64->msg_iov,
	    m64->msg_iovlen), m64->msg_iovlen, &iov, EMSGSIZE);
	if (error)
		return (error);
	msg->msg_iov = (__cheri_tocap struct iovec * __capability)iov;
	msg->msg_iovlen = m64->msg_iovlen;

	msg->msg_control = __USER_CAP(m64->msg_control, m64->msg_controllen);
	msg->msg_controllen = m64->msg_controllen;
	msg->msg_flags = m64->msg_flags;
	return (0);
}

static int
freebsd64_copyoutmsghdr(struct msghdr64 *m64, struct msghdr *msg, struct msghdr64 *msg64)
{
	int error;
	/* Leave pointers untouched */
	m64->msg_namelen = msg->msg_namelen;
	m64->msg_iovlen = msg->msg_iovlen;
	m64->msg_controllen = msg->msg_controllen;
	m64->msg_flags = msg->msg_flags;
	error = copyout(m64, msg64, sizeof(*m64));
	return (error);
}

#define FREEBSD64_ALIGN(p) roundup2((p), sizeof(long))
#define	FREEBSD64_CMSG_SPACE(l)						\
    (FREEBSD64_ALIGN(sizeof(struct cmsghdr)) + FREEBSD64_ALIGN(l))
#define FREEBSD64_CMSG_LEN(l)				\
    (FREEBSD64_ALIGN(sizeof(struct cmsghdr)) + (l))
#define FREEBSD64_CMSG_DATA(cmsg)				\
    ((char *)(cmsg) + FREEBSD64_ALIGN(sizeof(struct cmsghdr)))

static int
freebsd64_copyout_control(struct msghdr *msg, struct mbuf *control)
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
			cm->cmsg_len = FREEBSD64_CMSG_LEN(datalen);
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

static int
freebsd64_copyin_control(struct mbuf **mp, char * __capability buf, u_int buflen)
{
	int error;
	struct cmsghdr *cmsg;
	struct mbuf *m = NULL;
	caddr_t md;
	u_int idx, newlen, msglen, datalen;

	buflen = FREEBSD64_ALIGN(buflen);
	if (buflen > MCLBYTES)
		return (EINVAL);

	/*
	 * Iterate over the message headers to compute the new length using
	 * the native kernel padding.
	 */
	idx = 0;
	newlen = 0;
	while (idx < buflen) {
		cmsg = (struct cmsghdr *)(buf + idx);
		msglen = fuword32(&cmsg->cmsg_len);
		if (msglen < sizeof(struct cmsghdr) ||
		    idx + FREEBSD64_ALIGN(msglen) > buflen)
			return (EINVAL);
		datalen = (caddr_t)cmsg + msglen - FREEBSD64_CMSG_DATA(cmsg);
		idx += FREEBSD64_CMSG_SPACE(datalen);
		newlen += CMSG_SPACE(datalen);
	}

	if (newlen > MCLBYTES)
		return (EINVAL);

	m = m_get2(newlen, M_WAITOK, MT_CONTROL, 0);
	m->m_len = newlen;

	/* Copyin and realign the control data. */
	md = mtod(m, caddr_t);
	while (buflen > 0) {
		error = copyin(buf, md, sizeof(struct cmsghdr));
		if (error)
			break;
		cmsg = (struct cmsghdr *)md;
		datalen = buf + cmsg->cmsg_len - FREEBSD64_CMSG_DATA(buf);
		buf += FREEBSD64_ALIGN(sizeof(struct cmsghdr));
		md += CMSG_ALIGN(sizeof(struct cmsghdr));

		/* Fix length in the message header */
		cmsg->cmsg_len = CMSG_LEN(datalen);
		if (datalen > 0) {
			error = copyin(buf, md, datalen);
			if (error)
				break;
			md += CMSG_ALIGN(datalen);
			buf += FREEBSD64_ALIGN(datalen);
		}
		buflen -= FREEBSD64_CMSG_SPACE(datalen);
	}

	if (error)
		m_free(m);
	else
		*mp = m;
	return (error);
}

int
freebsd64_sendmsg(struct thread *td, struct freebsd64_sendmsg_args *uap)
{
	struct msghdr msg;
	struct msghdr64 umsg64;
	struct mbuf *control = NULL;
	struct sockaddr *to = NULL;
	int error;

	error = freebsd64_copyinmsghdr(PURECAP_KERNEL_USER_CAP_OBJ(uap->msg),
	    &msg, &umsg64);
	if (error)
		return (error);

#ifdef CAPABILITY_MODE
	if (IN_CAPABILITY_MODE(td) && (msg.msg_name != NULL))
		return (ECAPMODE);
#endif
	if (msg.msg_name != NULL) {
		error = getsockaddr(&to, msg.msg_name, msg.msg_namelen);
		if (error)
			goto out;
		msg.msg_name = to;
	}

	/* No COMPAT_OLDSOCK support, no 64-bit 43BSD binaries should exist. */
	if (msg.msg_control != NULL) {
		if (msg.msg_controllen < sizeof(struct cmsghdr)) {
			error = EINVAL;
			goto out;
		}

		error = freebsd64_copyin_control(&control, msg.msg_control,
		    msg.msg_controllen);
		if (error)
			goto out;

		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	error = kern_sendit(td, uap->s, &msg, uap->flags, control, UIO_USERSPACE);
out:
	if (to)
		free(to, M_SONAME);
	if (msg.msg_iov != NULL)
		free(msg.msg_iov, M_IOV);
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
	struct msghdr64 umsg64;
	struct mbuf *control = NULL;
	struct mbuf **controlp;
	int error;
	struct msghdr64 *umsg = PURECAP_KERNEL_USER_CAP_OBJ(uap->msg);

	error = freebsd64_copyinmsghdr(umsg, &msg, &umsg64);
	if (error != 0)
		return (error);
	msg.msg_flags = uap->flags;

	controlp = (msg.msg_control != NULL) ?  &control : NULL;
	error = kern_recvit(td, uap->s, &msg, UIO_USERSPACE, controlp);
	if (error == 0) {
		if (control != NULL)
			error = freebsd64_copyout_control(&msg, control);
		else
			msg.msg_controllen = 0;

		if (error == 0)
			error = freebsd64_copyoutmsghdr(&umsg64, &msg, umsg);
	}
	free(msg.msg_iov, M_IOV);

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

int
freebsd64_shm_open(struct thread *td, struct freebsd64_shm_open_args *uap)
{

	return (kern_shm_open(td, __USER_CAP_STR(uap->path), uap->flags,
	    uap->mode, NULL));
}

int
freebsd64_shm_unlink(struct thread *td, struct freebsd64_shm_unlink_args *uap)
{

	return (kern_shm_unlink(td, __USER_CAP_STR(uap->path)));
}
