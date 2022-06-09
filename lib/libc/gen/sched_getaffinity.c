/*-
 * Copyright (c) 2021 The FreeBSD Foundation
 *
 * This software were developed by Konstantin Belousov <kib@FreeBSD.org>
 * under sponsorship from the FreeBSD Foundation.
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

#include <errno.h>
#include <sched.h>
#include <string.h>

int
sched_getaffinity(pid_t pid, size_t cpusetsz, cpuset_t *cpuset)
{
	/*
	 * Be more Linux-compatible:
	 * - return EINVAL in passed size is less than size of cpuset_t
	 *   in advance, instead of ERANGE from the syscall
	 * - if passed size is larger than the size of cpuset_t, be
	 *   permissive by claming it back to sizeof(cpuset_t) and
	 *   zeroing the rest.
	 */
	if (cpusetsz < sizeof(cpuset_t)) {
		errno = EINVAL;
		return (-1);
	}
	if (cpusetsz > sizeof(cpuset_t)) {
		memset((char *)cpuset + sizeof(cpuset_t), 0,
		    cpusetsz - sizeof(cpuset_t));
		cpusetsz = sizeof(cpuset_t);
	}

	return (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID,
	    pid == 0 ? -1 : pid, cpusetsz, cpuset));
}
