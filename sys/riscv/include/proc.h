/*-
 * Copyright (c) 1991 Regents of the University of California.
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
 *      from: @(#)proc.h        7.1 (Berkeley) 5/15/91
 *	from: FreeBSD: src/sys/i386/include/proc.h,v 1.11 2001/06/29
 * $FreeBSD$
 */

#ifndef	_MACHINE_PROC_H_
#define	_MACHINE_PROC_H_

#ifdef CPU_CHERI
struct switchercb {
	/*
	 * Peer context - callee in caller's context, caller in callee's.
	 * This also serves as the callee's spinlock.  Must be first,
	 * as the cllc instruction doesn't take an offset.
	 */
	struct switchercb * __capability	scb_peer_scb;

	/*
	 * Thread owning the context; the same thread that called cosetup(2).
	 */
	struct thread				*scb_td;

	/*
	 * Thread owning the context we're lending our thread to.  When
	 * calling cocall(), this will be the callee thread.  NULL when
	 * not lending.
	 */
	struct thread				*scb_borrower_td;

	/*
	 * Capability to unseal peer context.
	 */
	void * __capability			scb_unsealcap;

	/*
	 * TLS pointer, to be returned by CReadHwr.
	 */
	void * __capability			scb_tls;

	/*
	 * There's more stuff here; we allocate an entire page.
	 */
};
#endif

struct mdthread {
	int	md_spinlock_count;	/* (k) */
	register_t md_saved_sstatus_ie;	/* (k) */
	int	md_flags;		/* (k) */
#ifdef	CPU_CHERI
	vaddr_t		md_scb;

	/*
	 * Stuff below is used for cocall_slow(2)/cocaccept_slow(2).
	 */
	struct cv	md_slow_cv;
	struct sx	md_slow_lock;
	struct thread	*md_slow_caller_td;
	void		*md_slow_buf;
	size_t		md_slow_len;
	bool		md_slow_accepting;
#endif
};

/* md_flags */
#ifdef CPU_QEMU_RISCV
#define	MDTD_QTRACE	0x0001		/* QEMU-CHERI ISA-level tracing */
#endif

struct mdproc {
#if __has_feature(capabilities)
	void * __capability md_sigcode;
#endif
	int dummy;
};

#if __has_feature(capabilities)
#define	KINFO_PROC_SIZE		1248
#define	KINFO_PROC64_SIZE	1088
#else
#define	KINFO_PROC_SIZE	1088
#endif

#define	MAXARGS		8
struct syscall_args {
	u_int code;
	struct sysent *callp;
	syscallarg_t args[MAXARGS];
	int narg;
};

#endif /* !_MACHINE_PROC_H_ */
