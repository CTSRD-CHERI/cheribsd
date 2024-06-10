/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019 Alex Richardson <arichardson@FreeBSD.org>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#ifndef _RTLD_AVOID_LIBC_DEPS_H_
#define _RTLD_AVOID_LIBC_DEPS_H_

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

/* Avoid dependencies on libthr (used by closedir/opendir/readdir) */
#define __isthreaded 0
#define _pthread_mutex_lock(mtx)	(void)0
#define _pthread_mutex_unlock(mtx)	(void)0
#define _pthread_mutex_destroy(mtx)	(void)0
#define __libc_interposing error, must not use this variable inside rtld

int	__sys_close(int);
void	__sys_exit(int) __dead2;
int	__sys_fstat(int fd, struct stat *);
int	__sys_fstatat(int, const char *, struct stat *, int);
int	__sys___getcwd(char *, size_t);
int	__sys_sigprocmask(int, const sigset_t *, sigset_t *);
int	__sys_thr_kill(long, int);
int	__sys_thr_self(long *);
#if defined(__CHERI_PURE_CAPABILITY__) && defined(CHERI_LIB_C18N)
void    __sys_thr_exit(long *);
struct sigaction;
int     __sys_sigaction(int, const struct sigaction *, struct sigaction *);
#endif
__ssize_t	__sys_pread(int, void *, __size_t, __off_t);
__ssize_t	__sys_read(int, void *, __size_t);
__ssize_t	__sys_write(int, const void *, __size_t);

extern char* __progname;
const char *_getprogname(void);
int __getosreldate(void);


/*
 * Don't pull in any of the libc wrappers. Instead we use the system call
 * directly inside RTLD to avoid pulling in __libc_interposing (which pulls
 * in lots more object files).
 */
#define close(fd)	__sys_close(fd)
#define _close(fd)	__sys_close(fd)
#define exit(status)	__sys_exit(status)
#define _exit(status)	__sys_exit(status)
#define _fstat(fd, sb)	__sys_fstat(fd, sb)
#define pread(fd, buf, nbytes, offset)	__sys_pread(fd, buf, nbytes, offset)
#define read(fd, buf, nbytes)	__sys_read(fd, buf, nbytes)
#define sigprocmask(how, set, oset)	__sys_sigprocmask(how, set, oset)
#define strerror(errno)	rtld_strerror(errno)
#define _write(fd, buf, nbytes)	__sys_write(fd, buf, nbytes)
#define write(fd, buf, nbytes)	__sys_write(fd, buf, nbytes)

// For CHERI with optional syscall args do not using the varargs calling
// convention. Work around this by using macros with default arguments:
#ifdef __CHERI_PURE_CAPABILITY__
int	__sys_fcntl(int, int, intptr_t);
int	__sys_open(const char *, int, int);
int	__sys_openat(int, const char *, int, int);
#else
int	__sys_fcntl(int, int, ...);
int	__sys_open(const char *, int, ...);
int	__sys_openat(int, const char *, int, ...);
#endif

#define GET_FOURTH_ARG(_1,_2,_3,NAME,...) NAME
#define GET_FIFTH_ARG(_1,_2,_3, _4, NAME,...) NAME
#define open_2_args(path, oflag) __sys_open(path, oflag, 0)
#define open_3_args(path, oflag, mode) __sys_open(path, oflag, mode)
#define open(...) GET_FOURTH_ARG(__VA_ARGS__, open_3_args, open_2_args)(__VA_ARGS__)
#define fcntl_2_args(fd, cmd)   __sys_fcntl(fd, cmd, 0)
#define fcntl_3_args(fd, cmd, arg)  __sys_fcntl(fd, cmd, arg)
#define fcntl(...) GET_FOURTH_ARG(__VA_ARGS__, fcntl_3_args, fcntl_2_args)(__VA_ARGS__)
#define openat_3_args(dirfd, path, oflag) __sys_openat(dirfd, path, oflag, 0)
#define openat_4_args(dirfd, path, oflag, mode) __sys_openat(dirfd, path, oflag, mode)
#define openat(...) GET_FIFTH_ARG(__VA_ARGS__, openat_4_args, openat_3_args)(__VA_ARGS__)

#define _fcntl(...) fcntl(__VA_ARGS__)
#define _open(...) open(__VA_ARGS__)
#define _openat(...) openat(__VA_ARGS__)

#endif /* _RTLD_AVOID_LIBC_DEPS_H_ */
