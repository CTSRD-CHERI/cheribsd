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
/*
 * When modifying this, make sure to update <machine/switcher.h>
 */
struct switchercb {
	/*
	 * Caller context: context of the thread that cocalled us.
	 * This also serves as the callee's spinlock.  Must be first,
	 * as the cllc instruction doesn't take an offset.
	 *
	 * This can also be set to a zero-length capability, with the offset
	 * equal to errno to be returned by cocall(2).
	 */
	struct switchercb * __capability	scb_caller_scb;

	/*
	 * Callee context, context of the thread we're cocalling into.
	 */
	struct switchercb * __capability	scb_callee_scb;

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
	 * XXX
	 */
	void * __capability			scb_csp;

	/*
	 * XXX
	 */
	void * __capability			scb_cra;

	/*
	 * XXX
	 */
	const void * __capability		scb_outbuf;

	/*
	 * XXX
	 */
	size_t					scb_outlen;

	/*
	 * XXX
	 */
	void * __capability			scb_inbuf;

	/*
	 * XXX
	 */
	size_t					scb_inlen;

	/*
	 * XXX
	 */
	void * __capability			scb_cookiep;
};
#endif

struct mdthread {
	int	md_spinlock_count;	/* (k) */
	register_t md_saved_sstatus_ie;	/* (k) */
	int	md_flags;		/* (k) */
};

/* md_flags */
#ifdef CPU_QEMU_RISCV
#define	MDTD_QTRACE		0x0001		/* QEMU-CHERI ISA-level tracing */
#define	MDTD_QTRACE_USERMODE	0x0002		/* QEMU-CHERI user-only tracing */
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

#ifdef _KERNEL
#include <machine/pcb.h>

/* Get the current kernel thread stack usage. */
#define	GET_STACK_USAGE(total, used) do {				\
	struct thread *td = curthread;					\
	(total) = td->td_kstack_pages * PAGE_SIZE - sizeof(struct pcb);	\
	(used) = td->td_kstack + (total) - (vm_offset_t)&td;		\
} while (0)

#endif  /* _KERNEL */
#endif /* !_MACHINE_PROC_H_ */
