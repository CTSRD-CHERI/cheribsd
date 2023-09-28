/*-
 * Copyright (c) 2023 Edward Tomasz Napierala <trasz@FreeBSD.org>
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
#include <cheri/cheric.h>
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

/*
 * XXX: We need to zero this on fork too.
 */
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
	if (capc <= CAPV_PATHS || capv[CAPV_PATHS] == NULL) {
		warn("%s: null capability %d", __func__, CAPV_PATHS);
		errno = ENOLINK;
		return (-1);
	}
	error = cosetup(COSETUP_COCALL);
	if (error != 0) {
		warn("%s: cosetup", __func__);
		return (-1);
	}
	target = capv[CAPV_PATHS];

	return (0);
}

static int
relativise(int *fdp, const char **pathp)
{
	capv_paths_return_t in;
	capv_paths_t out;
	ssize_t received;
	size_t prefix_len;
	int error;

	error = init_maybe();
	if (error != 0)
		return (error);

	/*
	 * Send the request.
	 */
	memset(&out, 0, sizeof(out));
	out.len = sizeof(out);
	out.op = 42; /* Unused */
	strlcpy(out.path, *pathp, sizeof(out.path));

	received = cocall(target, &out, out.len, &in, sizeof(in));
	if (received < 0) {
		warn("%s: cocall", __func__);
		errno = EIO;
		return (-1);
	}

	/*
	 * Handle the response.
	 */
	if ((size_t)received != sizeof(in)) {
		warnx("%s: size mismatch: received %zd, expected %zd; returning ENOMSG",
		    __func__, (size_t)received, sizeof(in));
		errno = EIO;
		return (-1);
	}


	/*
	 * Have we received a file descriptor capability?
	 */
	if (!cheri_getsealed(in.fdcap)) {
		//errno = EIO;
		errno = EPERM;
		return (-1);
	}

	error = captofd((void * __capability)in.fdcap, fdp);
	if (error != 0)
		err(1, "captofd");

	prefix_len = strlen(in.path);
	if (strncmp(*pathp, out.path, prefix_len) != 0) {
		fprintf(stderr, "%s: path mismatch, wanted %s, got %s, len %zd\n", __func__, *pathp, in.path, prefix_len); 
	}

	/*
	 * Skip the prefix part of the path plus the trailing "/", unless the whole
	 * prefix is just "/" or the whole path is the prefix.
	 */
	*pathp += prefix_len;
	if (prefix_len > 1 && **pathp != '\0')
		*pathp += 1;

	return (0);
}

static int
do_fd_and_path(int op, uintcap_t a0, uintcap_t a1, uintcap_t a2, uintcap_t a3, uintcap_t a4)
{
	int error, error_;

	/*
	 * First try calling it directly.  If it fails, ask paths(1) for the fd
	 * and path prefix it corresponds to, then retry.
	 *
	 * XXX: This should probably use dlsym(3)-based solution instead of syscall(2).
	 */
	error = syscall(op, a0, a1, a2, a3, a4);
	if (error >= 0 || errno != ECAPMODE)
		return (error);

	error = relativise((int *)&a0, (const char **)&a1);
	if (error != 0)
		return (error);

	error = syscall(op, a0, a1, a2, a3, a4);

	/*
	 * Close the file descriptor returned by relativise().
	 */
	error_ = close(a0);
	if (error_ != 0)
		warn("close");

	return (error);
}

static int
do_path(int op, int op2, uintcap_t a0, uintcap_t a1, uintcap_t a2, uintcap_t a3, uintcap_t a4)
{
	int error, error_, fd;

	/*
	 * First try calling it directly.
	 *
	 * XXX: This should probably use dlsym(3)-based solution instead of syscall(2).
	 */
	error = syscall(op, a0, a1, a2, a3, a4);
	if (error >= 0 || errno != ECAPMODE)
		return (error);

	/*
	 * Nope, need to talk to paths(1).
	 */
	fd = -1;
	error = relativise(&fd, (const char **)&a0);
	if (error != 0)
		return (error);

	/*
	 * Yes, they are shifted by one.  Sorry!
	 */
	error = syscall(op2, fd, a0, a1, a2, a3, a4);

	/*
	 * Close the file descriptor returned by relativise().
	 */
	error_ = close(fd);
	if (error_ != 0)
		warn("close");

	return (error);
}

static int
do_path_and_stuff(int op, int op2, uintcap_t a0, uintcap_t a1, uintcap_t a2, uintcap_t a3, uintcap_t a4)
{
	int error, error_, fd;

	/*
	 * First try calling it directly.
	 *
	 * XXX: This should probably use dlsym(3)-based solution instead of syscall(2).
	 */
	error = syscall(op, a0, a1, a2, a3, a4);
	if (error >= 0 || errno != ECAPMODE)
		return (error);

	/*
	 * Nope, need to talk to paths(1).
	 */
	fd = -1;
	error = relativise(&fd, (const char **)&a0);
	if (error != 0)
		return (error);

	// XXX
	fd = openat(fd, (const char *)a0, O_RDONLY);
	if (error != 0) {
		warn("openat %d %s", fd, (const char *)a0);
		return (error);
	}

	error = syscall(op2, fd, a1, a2, a3, a4);

	/*
	 * XXX Close the other file descriptor.
	 */

	/*
	 * Close the file descriptor returned by relativise().
	 */
	error_ = close(fd);
	if (error_ != 0)
		warn("close");

	return (error);
}

int
fstatat(int fd, const char *path, struct stat *sb, int flag)
{

	return (do_fd_and_path(SYS_fstatat, fd, (uintcap_t)path, (uintcap_t)sb, flag, 0));
}

int
fchmodat(int fd, const char *path, mode_t mode, int flag)
{

	return (do_fd_and_path(SYS_fchmodat, fd, (uintcap_t)path, (uintcap_t)mode, flag, 0));
}

int
fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag)
{

	return (do_fd_and_path(SYS_fchownat, fd, (uintcap_t)path, owner, group, flag));
}

/*
 * Test with touch(1).
 */
int
utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{

	return (do_fd_and_path(SYS_utimensat, fd, (uintcap_t)path, (uintcap_t)times, flag, 0));
}

int
__sys_openat(int fd, const char *path, int flags, int mode)
{

	return (do_fd_and_path(SYS_openat, fd, (uintcap_t)path, flags, mode, 0));
}

/*
 * Test with "chmod 755".
 */
long
pathconf(const char *path, int name)
{

	return (do_path_and_stuff(SYS_pathconf, SYS_fpathconf, (uintcap_t)path, name, 0, 0, 0));
}

/*
 * Test with "ls -al".
 */
long
lpathconf(const char *path, int name)
{
	/*
	 * XXX: I'm not sure how to articulate the problem here, but it should be obvious.
	 */
	return (do_path_and_stuff(SYS_lpathconf, SYS_fpathconf, (uintcap_t)path, name, 0, 0, 0));
}

int
execve(const char *path, char *const argv[], char *const envp[])
{

	fprintf(stderr, "%s: foo\n", __func__);

	return (do_path_and_stuff(SYS_execve, SYS_fexecve, (uintcap_t)path, (uintcap_t)argv, (uintcap_t)envp, 0, 0));
}

int
mkdir(const char *path, mode_t mode)
{

	return (do_path(SYS_mkdir, SYS_mkdirat, (uintcap_t)path, mode, 0, 0, 0));
}

#if 0
int
rmdir(const char *path)
{

	// XXX: AT_REMOVEDIRAT
	return (do_path(SYS_rmdir, SYS_unlinkat, (uintcap_t)path, 0, 0, 0, 0));
}
#endif
