/*-
 * Copyright (c) 2022 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CHERI for Hypervisors and Operating Systems
 * (CHaOS) project, funded by EPSRC grant EP/V000292/1.
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

#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <capv.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "libc_private.h" /* For __sys_openat(); see lib/libc/sys/openat.c */

__thread static void * __capability target = NULL;

/*
 * XXX: This is a testing feature, not a security one.  To make it properly secure
 *      we'd need to start the binaries in Capsicum mode.
 */
__attribute__((constructor))
static void libsyscalls_init(void)
{
	int error;

	error = cap_enter();
	if (error != 0)
		err(1, "cap_enter");
}

/*
 * XXX: This should be a constructor, but we need to do it for each thread.
 */
static int
init_maybe(void)
{
	void * __capability *capv;
	int capc, error;

	if (__predict_true(target != NULL))
		return (0);

	capvfetch(&capc, &capv);
	if (capc <= CAPV_SYSCALL || capv[CAPV_SYSCALL] == NULL) {
		warn("%s: null capability %d", __func__, CAPV_SYSCALL);
		errno = ENOLINK;
		return (-1);
	}
	error = cosetup(COSETUP_COCALL);
	if (error != 0) {
		warn("%s: cosetup", __func__);
		return (-1);
	}
	target = capv[CAPV_SYSCALL];

	return (0);
}

static int
remote_syscall(int op, uintcap_t a0, uintcap_t a1, uintcap_t a2, uintcap_t a3, uintcap_t a4)
{
	capv_syscall_return_t in;
	capv_syscall_t out;
	ssize_t received;
	int error;

	error = init_maybe();
	if (error != 0)
		return (error);

	/*
	 * Send the request.
	 */
	memset(&out, 0, sizeof(out));
	out.len = sizeof(out);
	out.op = op;
	out.arg[0] = a0;
	out.arg[1] = a1;
	out.arg[2] = a2;
	out.arg[3] = a3;
	out.arg[4] = a4;
	out.arg[5] = 0;
	out.arg[6] = 0;
	out.arg[7] = 0;

	received = cocall(target, &out, out.len, &in, sizeof(in));
	if (received < 0) {
		warn("%s: cocall", __func__);
		return (error);
	}

	/*
	 * Handle the response.
	 */
	if ((size_t)received != sizeof(in)) {
		warnx("%s: size mismatch: received %zd, expected %zd; returning ENOMSG",
		    __func__, (size_t)received, sizeof(in));
		errno = ENOMSG;
		return (error);
	}

	/*
	 * Have we received a file descriptor?
	 */
	if ((void * __capability)in.fdcap != NULL) {
		error = captofd((void * __capability)in.fdcap, &in.error);
		if (error != 0)
			err(1, "captofd");
	}

	//fprintf(stderr, "%s: <- op %d returned error %d, errno %d\n", __func__, in.op, in.error, in.errno_);
	error = in.error;
	errno = in.errno_;

	return (error);
}

#define	CAPFROMFD(FDCAP, S)				\
	{						\
		int _error;				\
		_error = capfromfd((void *)FDCAP, S);	\
		if (_error != 0)			\
			err(1, "capfromfd");		\
	}

/*
 * XXX: For AT_FDCWD case we probably want to call the native syscall instead of cocall.
 */
static uintcap_t
fd2c(int fd)
{
	uintcap_t fdcap;

	if (fd == AT_FDCWD)
		return ((uintcap_t)fd);

	CAPFROMFD(&fdcap, fd);
	return (fdcap);
}

/*
 * Here's the (non-exhaustive) list of syscalls we'll probably need to forward.
 * Implementing them is generally trivial; testing is the complicated part.
 * Most of them aren't used very often.
 *
 * open
 * wait4
 * creat
 * link
 * unlink
 * chdir
 * mknod
 * chmod
 * chown
 * getfsstat
 * access
 * chflags
 * stat
 * lstat
 * ktrace
 * symlink
 * readlink
 * execve
 * chroot
 * setpgid
 * wait
 * rename
 * truncate
 * mkfifo
 * utimes
 * killpg
 * coexecve
 * coexecvec
 * statfs
 * uname
 * semsys
 * msgsys
 * shmsys
 * stat
 * lstat
 * truncate
 * __semctl
 * semget
 * semop
 * msgctl
 * msgget
 * msgsend
 * msgrcv
 * shmat
 * shmctl
 * shdt
 * shmget
 * lchown
 * lchmod
 * lutimes
 * nstat
 * __getcwd
 * __acl_get_file
 * __acl_set_file
 * __acl_delete_file
 * __acl_aclcheck_file
 * extattr_set_file
 * extattr_get_file
 * extattr_delete_file
 * __setugid
 * eaccess
 * __mac_get_file
 * lchflags
 * statfs
 * ksem_close
 * ksem_post
 * ksem_wait
 * ksem_trywait
 * ksem_init
 * ksem_open
 * ksem_unlink
 * ksem_destroy
 * __mac_get_link
 * __mac_set_link
 * extattr_set_link
 * extattr_get_link
 * extattr_delete_link
 * __mac_execve
 * __acl_get_link
 * __acl_set_link
 * __acl_delete_link
 * __acl_aclcheck_link
 * extattr_list_file
 * extattr_list_link
 * kmq_open
 * kmq_unlink
 * truncate
 * thr_kill2
 * shm_unlink
 * posix_openpt
 * __semctl
 * msgctl
 * shmctl
 * wait6
 * aio_mlock
 * procctl
 * statfs
 * getfsstat
 * shm_rename
 * __realpathat
 *
 * There's a couple of syscalls that should probably be allowed in Capsicum mode instead:
 *
 * rfork
 * vfork
 * coregister
 * cpuset
 * cpuset_setid
 * cpuset_getid
 * _umtx_lock
 * _umtx_unlock
 * swapcontext
 * clock_nanosleep
 * clock_getcpuclockid2
 */

int
fstatat(int fd, const char *path, struct stat *sb, int flag)
{

	return (remote_syscall(SYS_fstatat, fd2c(fd), (uintcap_t)path, (uintcap_t)sb, flag, 0));
}

int
fchmodat(int fd, const char *path, mode_t mode, int flag)
{

	return (remote_syscall(SYS_fchmodat, fd2c(fd), (uintcap_t)path, (uintcap_t)mode, flag, 0));
}

int
fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag)
{

	return (remote_syscall(SYS_fchownat, fd2c(fd), (uintcap_t)path, owner, group, flag));
}

/*
 * Test with touch(1).
 */
int
utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{

	return (remote_syscall(SYS_utimensat, fd2c(fd), (uintcap_t)path, (uintcap_t)times, flag, 0));
}

int
__sys_openat(int fd, const char *path, int flags, int mode)
{

	return (remote_syscall(SYS_openat, fd2c(fd), (uintcap_t)path, flags, mode, 0));
}

/*
 * Test with "chmod 755".
 */
long
pathconf(const char *path, int name)
{

	return (remote_syscall(SYS_pathconf, (uintcap_t)path, name, 0, 0, 0));
}

/*
 * Test with "ls -al".
 */
long
lpathconf(const char *path, int name)
{

	return (remote_syscall(SYS_lpathconf, (uintcap_t)path, name, 0, 0, 0));
}

/*
 * Test with "ls -al".
 */
int
fchdir(int fd)
{

	return (remote_syscall(SYS_fchdir, fd2c(fd), 0, 0, 0, 0));
}

int __getcwd(char *buf, size_t size);

/*
 * Test with sh(1).
 */
int
__getcwd(char *buf, size_t size)
{

	return (remote_syscall(SYS___getcwd, (uintcap_t)buf, size, 0, 0, 0));
}

int
mkdir(const char *path, mode_t mode)
{

	return (remote_syscall(SYS_mkdir, (uintcap_t)path, mode, 0, 0, 0));
}

int
rmdir(const char *path)
{

	return (remote_syscall(SYS_rmdir, (uintcap_t)path, 0, 0, 0, 0));
}

int
bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	uintcap_t fdcap;

	CAPFROMFD(&fdcap, s);
	return (remote_syscall(SYS_bind, fdcap, (uintcap_t)addr, addrlen, 0, 0));
}

int
connect(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	uintcap_t fdcap;

	CAPFROMFD(&fdcap, s);
	return (remote_syscall(SYS_connect, fdcap, (uintcap_t)addr, addrlen, 0, 0));
}
