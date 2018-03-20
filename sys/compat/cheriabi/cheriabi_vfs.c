/*-
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2015-2017 SRI International
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
#include <sys/namei.h>
#include <sys/signal.h>
#include <sys/syscallsubr.h>

#include <compat/cheriabi/cheriabi_proto.h>

int
cheriabi_quotactl(struct thread *td, struct cheriabi_quotactl_args *uap)
{

	return (kern_quotactl(td, uap->path, uap->cmd, uap->uid, uap->arg));
}

int
cheriabi_chdir(struct thread *td, struct cheriabi_chdir_args *uap)
{

	return (kern_chdir(td, uap->path, UIO_USERSPACE));
}

int
cheriabi_open(struct thread *td, struct cheriabi_open_args *uap)
{

	return (kern_openat_c(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, uap->mode));
}

int
cheriabi_openat(struct thread *td, struct cheriabi_openat_args *uap)
{

	return (kern_openat_c(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
	    uap->mode));
}

int
cheriabi_link(struct thread *td, struct cheriabi_link_args *uap)
{

	return (kern_linkat_c(td, AT_FDCWD, AT_FDCWD, uap->path, uap->to,
	    UIO_USERSPACE, FOLLOW));
}

int
cheriabi_linkat(struct thread *td, struct cheriabi_linkat_args *uap)
{
	int flag;

	flag = uap->flag;
	if (flag & ~AT_SYMLINK_FOLLOW)
		return (EINVAL);

	return (kern_linkat_c(td, uap->fd1, uap->fd2, uap->path1, uap->path2,
	    UIO_USERSPACE, (flag & AT_SYMLINK_FOLLOW) ? FOLLOW : NOFOLLOW));
}

int
cheriabi_unlink(struct thread *td, struct cheriabi_unlink_args *uap)
{

	return (kern_unlinkat_c(td, AT_FDCWD, uap->path, UIO_USERSPACE, 0));
}

int
cheriabi_unlinkat(struct thread *td, struct cheriabi_unlinkat_args *uap)
{
	int flag = uap->flag;

	if (flag & ~AT_REMOVEDIR)
		return (EINVAL);

	if (flag & AT_REMOVEDIR)
		return (kern_rmdirat_c(td, uap->fd, uap->path, UIO_USERSPACE));
	else
		return (kern_unlinkat_c(td, uap->fd, uap->path, UIO_USERSPACE,
		    0));
}

int
cheriabi_rmdir(struct thread *td, struct cheriabi_rmdir_args *uap)
{

	return (kern_rmdirat_c(td, AT_FDCWD, uap->path, UIO_USERSPACE));
}
