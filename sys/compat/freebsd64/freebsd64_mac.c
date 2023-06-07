/*-
 * Copyright (c) 2016-2019 SRI International
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

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/imgact.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>

#include <compat/freebsd64/freebsd64_proto.h>
#include <compat/freebsd64/freebsd64_util.h>

#include <security/mac/mac_framework.h>

#ifdef MAC
int
freebsd64___mac_get_pid(struct thread *td,
    struct freebsd64___mac_get_pid_args *uap)
{
	return (kern_mac_get_pid(td, uap->pid, __USER_CAP_OBJ(uap->mac_p)));
}

int
freebsd64___mac_get_proc(struct thread *td,
    struct freebsd64___mac_get_proc_args *uap)
{
	return (kern_mac_get_proc(td, __USER_CAP_OBJ(uap->mac_p)));
}

int
freebsd64___mac_set_proc(struct thread *td,
    struct freebsd64___mac_set_proc_args *uap)
{
	return (kern_mac_set_proc(td, __USER_CAP_OBJ(uap->mac_p)));
}

int
freebsd64___mac_get_fd(struct thread *td,
    struct freebsd64___mac_get_fd_args *uap)
{
	return (kern_mac_get_fd(td, uap->fd, __USER_CAP_OBJ(uap->mac_p)));
}

int
freebsd64___mac_get_file(struct thread *td,
    struct freebsd64___mac_get_file_args *uap)
{
	return (kern_mac_get_path(td, __USER_CAP_STR(uap->path_p),
	    __USER_CAP_OBJ(uap->mac_p), FOLLOW));
}

int
freebsd64___mac_get_link(struct thread *td,
    struct freebsd64___mac_get_link_args *uap)
{
	return (kern_mac_get_path(td, __USER_CAP_STR(uap->path_p),
	    __USER_CAP_OBJ(uap->mac_p), NOFOLLOW));
}

int
freebsd64___mac_set_fd(struct thread *td,
    struct freebsd64___mac_set_fd_args *uap)
{
	return (kern_mac_set_fd(td, uap->fd, __USER_CAP_OBJ(uap->mac_p)));
}

int
freebsd64___mac_set_file(struct thread *td,
    struct freebsd64___mac_set_file_args *uap)
{
	return (kern_mac_set_path(td, __USER_CAP_STR(uap->path_p),
	    __USER_CAP_OBJ(uap->mac_p), FOLLOW));
}

int
freebsd64___mac_set_link(struct thread *td,
    struct freebsd64___mac_set_link_args *uap)
{
	return (kern_mac_set_path(td, __USER_CAP_STR(uap->path_p),
	    __USER_CAP_OBJ(uap->mac_p), NOFOLLOW));
}

int
freebsd64_mac_syscall(struct thread *td,
    struct freebsd64_mac_syscall_args *uap)
{
	return (kern_mac_syscall(td, __USER_CAP_OBJ(uap->policy), uap->call,
	    __USER_CAP_UNBOUND(uap->arg)));
}

int
freebsd64___mac_execve(struct thread *td,
    struct freebsd64___mac_execve_args *uap)
{
	struct image_args eargs;
	struct vmspace *oldvmspace;
	int error;

	error = pre_execve(td, &oldvmspace);
	if (error != 0)
		return (error);
	error = exec_copyin_args(&eargs, NULL, UIO_SYSSPACE,
	    __USER_CAP_UNBOUND(uap->argv), __USER_CAP_UNBOUND(uap->envv));
	if (error == 0)
		error = kern_execve(td, &eargs, __USER_CAP_OBJ(uap->mac_p),
		    oldvmspace);

	post_execve(td, error, oldvmspace);
	return (error);
}

#else /* !MAC */

int
freebsd64___mac_get_proc(struct thread *td,
    struct freebsd64___mac_get_proc_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_set_proc(struct thread *td,
    struct freebsd64___mac_set_proc_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_get_fd(struct thread *td,
    struct freebsd64___mac_get_fd_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_get_file(struct thread *td,
    struct freebsd64___mac_get_file_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_set_fd(struct thread *td,
    struct freebsd64___mac_set_fd_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_set_file(struct thread *td,
    struct freebsd64___mac_set_file_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_get_pid(struct thread *td,
    struct freebsd64___mac_get_pid_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_get_link(struct thread *td,
    struct freebsd64___mac_get_link_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_set_link(struct thread *td,
    struct freebsd64___mac_set_link_args *uap)
{
	return(ENOSYS);
}

int
freebsd64_mac_syscall(struct thread *td,
    struct freebsd64_mac_syscall_args *uap)
{
	return(ENOSYS);
}

int
freebsd64___mac_execve(struct thread *td,
    struct freebsd64___mac_execve_args *uap)
{
	return(ENOSYS);
}

#endif /* !MAC */
