/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)sys_machdep.c	5.5 (Berkeley) 1/19/91
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/sysent.h>

#include <machine/cpufunc.h>
#include <machine/cpuinfo.h>
#include <machine/sysarch.h>
#include <machine/cpuregs.h>
#include <machine/tls.h>

#ifndef _SYS_SYSPROTO_H_
struct sysarch_args {
	int op;
	char *parms;
};
#endif

int
sysarch(struct thread *td, struct sysarch_args *uap)
{
	int error;
#ifdef CPU_QEMU_MALTA
	int intval;
#endif
	void *tlsbase;

	switch (uap->op) {
	case MIPS_SET_TLS:
#if __has_feature(capabilities)
		return (cheriabi_set_user_tls(td, uap->parms));
#else
		td->td_md.md_tls = __USER_CAP_UNBOUND(uap->parms);

		/*
		 * If there is an user local register implementation (ULRI)
		 * update it as well.  Add the TLS and TCB offsets so the
		 * value in this register is adjusted like in the case of the
		 * rdhwr trap() instruction handler.
		 *
		 * The user local register needs the TLS and TCB offsets
		 * because the compiler simply generates a 'rdhwr reg, $29'
		 * instruction to access thread local storage (i.e., variables
		 * with the '_thread' attribute).
		 */
		if (cpuinfo.userlocal_reg == true) {
			mips_wr_userlocal((unsigned long)(uap->parms +
			    td->td_md.md_tls_tcb_offset));
		}
		return (0);

	case MIPS_GET_TLS:
		tlsbase = (__cheri_fromcap void *)td->td_md.md_tls;
		error = copyout(&tlsbase, uap->parms, sizeof(tlsbase));
		return (error);

	case MIPS_GET_COUNT:
		td->td_retval[0] = mips_rd_count();
		return (0);

#ifdef CPU_QEMU_MALTA
	case QEMU_GET_QTRACE:
		intval = (td->td_md.md_flags & MDTD_QTRACE) ? 1 : 0;
		error = copyout(&intval, uap->parms, sizeof(intval));
		return (error);

	case QEMU_SET_QTRACE:
		error = copyin(uap->parms, &intval, sizeof(intval));
		if (error)
			return (error);
		if (intval)
			td->td_md.md_flags |= MDTD_QTRACE;
		else
			td->td_md.md_flags &= ~MDTD_QTRACE;
		return (0);
#endif

#ifdef CPU_CHERI
#if 0
	case CHERI_GET_STACK:
		return (cheri_sysarch_getstack(td, uap));

	case CHERI_SET_STACK:
		return (cheri_sysarch_setstack(td, uap));
#endif

	case CHERI_GET_SEALCAP:
#if __has_feature(capabilities)
		return (cheri_sysarch_getsealcap(td, uap->parms));
#else
		return (cheri_sysarch_getsealcap(td,
		    __USER_CAP(uap->parms, sizeof(void * __capability))));
#endif

#if __has_feature(capabilities)
	/*
	 * CheriABI specific operations.
	 */
	case CHERI_MMAP_GETBASE: {
		size_t base;

		base = cheri_getbase(td->td_md.md_cheri_mmap_cap);
		if (suword(uap->parms, base) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETLEN: {
		size_t len;

		len = cheri_getlen(td->td_md.md_cheri_mmap_cap);
		if (suword(uap->parms, len) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETOFFSET: {
		ssize_t offset;

		offset = cheri_getoffset(td->td_md.md_cheri_mmap_cap);
		if (suword(uap->parms, offset) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETPERM: {
		uint64_t perms;

		perms = cheri_getperm(td->td_md.md_cheri_mmap_cap);
		if (suword64(uap->parms, perms) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_ANDPERM: {
		uint64_t perms;
		perms = fuword64(uap->parms);

		if (perms == -1)
			return (EINVAL);
		td->td_md.md_cheri_mmap_cap =
		    cheri_andperm(td->td_md.md_cheri_mmap_cap, perms);
		perms = cheri_getperm(td->td_md.md_cheri_mmap_cap);
		if (suword64(uap->parms, perms) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_SETOFFSET: {
		size_t len;
		ssize_t offset;

		offset = fuword(uap->parms);
		/* Reject errors and misaligned offsets */
		if (offset == -1 || (offset & PAGE_MASK) != 0)
			return (EINVAL);
		len = cheri_getlen(td->td_md.md_cheri_mmap_cap);
		/* Don't allow out of bounds offsets, they aren't useful */
		if (offset < 0 || offset > len) {
			return (EINVAL);
		}
		td->td_md.md_cheri_mmap_cap =
		    cheri_setoffset(td->td_md.md_cheri_mmap_cap,
		    (register_t)offset);
		return (0);
	}

	case CHERI_MMAP_SETBOUNDS: {
		size_t len, olen;
		ssize_t offset;

		len = fuword(uap->parms);
		/* Reject errors or misaligned lengths */
		if (len == (size_t)-1 || (len & PAGE_MASK) != 0)
			return (EINVAL);
		olen = cheri_getlen(td->td_md.md_cheri_mmap_cap);
		offset = cheri_getoffset(td->td_md.md_cheri_mmap_cap);
		/* Don't try to set out of bounds lengths */
		if (offset > olen || len > olen - offset) {
			return (EINVAL);
		}
		td->td_md.md_cheri_mmap_cap =
		    cheri_csetbounds(td->td_md.md_cheri_mmap_cap,
		    (register_t)len);
		return (0);
	}
#endif /* __has_feature(capabilities) */
#endif /* CPU_CHERI */

	default:
		break;
	}
	return (EINVAL);
}
// CHERI CHANGES START
// {
//   "updated": 20180629,
//   "target_type": "kernel",
//   "changes": [
//     "support",
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
