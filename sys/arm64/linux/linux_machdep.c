/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 Turing Robotic Industries Inc.
 * Copyright (c) 2000 Marcel Moolenaar
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

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

#include <vm/vm_param.h>

#ifdef COMPAT_LINUX64
#include <arm64/linux64/linux.h>
#include <arm64/linux64/linux64_proto.h>
#else
#include <arm64/linux/linux.h>
#include <arm64/linux/linux_proto.h>
#endif
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_util.h>

#define	LINUX_ARCH_AARCH64		0xc00000b7


int
linux_set_upcall(struct thread *td, register_t stack)
{

	if (stack)
		td->td_frame->tf_sp = stack;

	/*
	 * The newly created Linux thread returns
	 * to the user space by the same path that a parent does.
	 */
	td->td_frame->tf_x[0] = 0;
	return (0);
}

int
linux_set_cloned_tls(struct thread *td, void *desc)
{

	if ((uint64_t)desc >= VM_MAXUSER_ADDRESS)
		return (EPERM);

	return (cpu_set_user_tls(td, __USER_CAP_UNBOUND(desc)));
}

void
bsd_to_linux_regset(const struct reg *b_reg, struct linux_pt_regset *l_regset)
{

	KASSERT(sizeof(l_regset->x) == sizeof(b_reg->x) + sizeof(l_ulong),
	    ("%s: size mismatch\n", __func__));
	memcpy(l_regset->x, b_reg->x, sizeof(b_reg->x));

	l_regset->x[30] = b_reg->lr;
	l_regset->sp = b_reg->sp;
	l_regset->pc = b_reg->elr;
	l_regset->cpsr = b_reg->spsr;
}

void
linux_to_bsd_regset(struct reg *b_reg, const struct linux_pt_regset *l_regset)
{

	KASSERT(sizeof(l_regset->x) == sizeof(b_reg->x) + sizeof(l_ulong),
	    ("%s: size mismatch\n", __func__));

	memcpy(b_reg->x, l_regset->x, sizeof(b_reg->x));
	b_reg->sp = l_regset->sp;
	b_reg->elr = l_regset->pc;
	b_reg->spsr = l_regset->cpsr;
}

void
linux_ptrace_get_syscall_info_machdep(const struct reg *reg,
    struct syscall_info *si)
{

	si->arch = LINUX_ARCH_AARCH64;
	si->instruction_pointer = reg->lr;
	si->stack_pointer = reg->sp;
}

int
linux_ptrace_getregs_machdep(struct thread *td __unused, pid_t pid __unused,
    struct linux_pt_regset *l_regset __unused)
{

	return (0);
}

int
linux_ptrace_peekuser(struct thread *td, pid_t pid, void * __capability addr, void * __capability data)
{

	LINUX_RATELIMIT_MSG_OPT1("PTRACE_PEEKUSER offset %ld not implemented; "
	    "returning EINVAL", (__cheri_addr long)addr);

	return (EINVAL);
}

int
linux_ptrace_pokeuser(struct thread *td, pid_t pid, void * __capability addr, void * __capability data)
{

	LINUX_RATELIMIT_MSG_OPT1("PTRACE_POKEUSER offset %ld "
	    "not implemented; returning EINVAL", (__cheri_addr long)addr);
	return (EINVAL);
}

CTASSERT(sizeof(struct l_iovec64) == 16);

int
linux64_copyiniov(struct l_iovec64 * __capability iovp64, l_ulong iovcnt,
    struct iovec **iovp, int error)
{
	struct l_iovec64 iov64;
	struct iovec *iov;
	uint64_t iovlen;
	int i;
	*iovp = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(struct iovec);
	iov = malloc(iovlen, M_IOV, M_WAITOK);
	for (i = 0; i < iovcnt; i++) {
		error = copyin(&iovp64[i], &iov64, sizeof(struct l_iovec64));
		if (error) {
			free(iov, M_IOV);
			return (error);
		}
		IOVEC_INIT_C(&iov[i], __USER_CAP(iov64.iov_base,
		    iov64.iov_len), iov64.iov_len);
	}
	*iovp = iov;
	return(0);
}

int
linux64_copyinuio(struct l_iovec64 * __capability iovp, l_ulong iovcnt,
    struct uio **uiop)
{
	struct l_iovec64 iov64;
	struct iovec *iov;
	struct uio *uio;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	uio = allocuio(iovcnt);
	iov = uio->uio_iov;
	for (i = 0; i < iovcnt; i++) {
		error = copyin(&iovp[i], &iov64, sizeof(struct l_iovec64));
		if (error) {
			freeuio(uio);
			return (error);
		}
		IOVEC_INIT_C(&iov[i], __USER_CAP(iov64.iov_base,
		    iov64.iov_len), iov64.iov_len);
	}
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov->iov_len > SIZE_MAX - uio->uio_resid) {
			freeuio(uio);
			return (EINVAL);
		}
		uio->uio_resid += iov->iov_len;
		iov++;
	}
	*uiop = uio;
	return (0);
}