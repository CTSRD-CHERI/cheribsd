/*-
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
 *
 * $FreeBSD$
 */

#ifndef _MACHINE_UCONTEXT_H_
#define	_MACHINE_UCONTEXT_H_

struct gpregs {
	__register_t	gp_ra;
	__register_t	gp_sp;
	__register_t	gp_gp;
	__register_t	gp_tp;
	__register_t	gp_t[7];
	__register_t	gp_s[12];
	__register_t	gp_a[8];
	__register_t	gp_sepc;
	__register_t	gp_sstatus;
};

struct fpregs {
	__uint64_t	fp_x[32][2];
	__uint64_t	fp_fcsr;
	int		fp_flags;
	int		pad;
};

#if __has_feature(capabilities)
struct capregs {
	__uintcap_t	cp_cra;
	__uintcap_t	cp_csp;
	__uintcap_t	cp_cgp;
	__uintcap_t	cp_ctp;
	__uintcap_t	cp_ct[7];
	__uintcap_t	cp_cs[12];
	__uintcap_t	cp_ca[8];
	__uintcap_t	cp_sepcc;
	__uintcap_t	cp_ddc;
	__register_t	cp_sstatus;
	__register_t	cp_pad;
};
#endif

struct __mcontext {
#if __CHERI_USER_ABI
	struct capregs	mc_capregs;
#else
	struct gpregs	mc_gpregs;
#endif
	struct fpregs	mc_fpregs;
	int		mc_flags;
#define	_MC_FP_VALID	0x1		/* Set when mc_fpregs has valid data */
#define	_MC_CAP_VALID	0x2		/* Set when mc_capregs has valid data */
	int		mc_pad;
#if __CHERI_USER_ABI
	__uint64_t	mc_spare[8];
#else
	__uint64_t	mc_capregs;
	__uint64_t	mc_spare[7];	/* Space for expansion */
#endif
};

typedef struct __mcontext mcontext_t;

#ifdef COMPAT_FREEBSD64
#include <compat/freebsd64/freebsd64_signal.h>

typedef struct	__mcontext64 {
	struct gpregs	mc_gpregs;
	struct fpregs	mc_fpregs;
	int		mc_flags;
	int		mc_pad;
	__uint64_t	mc_capregs;
	__uint64_t	mc_spare[7];
} mcontext64_t;

typedef struct __ucontext64 {
	sigset_t		uc_sigmask;
	mcontext64_t		uc_mcontext;
	uint64_t		uc_link;
	struct sigaltstack64	uc_stack;
	int			uc_flags;
	int			__spare__[4];
} ucontext64_t;
#endif

#endif	/* !_MACHINE_UCONTEXT_H_ */
