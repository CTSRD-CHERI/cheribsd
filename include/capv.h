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

#ifndef _CAPV_H_
#define	_CAPV_H_

/*
 * Define conventions used for services using capv(6) framework.
 * Try to follow those, unless you really have a good reason not
 * to (and writing a replacement mechanism is just one example).
 * Or at least keep the size_t-sized length at the very beginning
 * of every output buffer passed to cocall(2).  You can compare
 * it with the size returned by cocall(2)/coaccept(2) to make sure
 * you actually received all the data.  Integer-sized opcode 0
 * that follows is reserved for answerback, for both calls and
 * returns; other values are left for application use.
 *
 * For an example of how to use it, see usr.bin/clocks/clocks.c
 * (service) and lib/libclocks/clocks.c (client).
 */

/*
 * Applications might expect services to be found at particular
 * offsets within the capability vector they inherit.  Those numbers
 * can be thought of as part of capv ABI.  Use the even numbers,
 * leaving odd ones for ad-hoc use.
 */
#define	CAPV_CODISCOVER	2
#define	CAPV_COINSERT	4
#define	CAPV_COSELECT	6
#define	CAPV_CLOCKS	8
#define	CAPV_BINDS	10
#define	CAPV_SYSCALL	12

#include <sys/socket.h> // XXX binds
#include <time.h> // XXX clocks

typedef union {
	/* Buffers used for cocall(2) need to be capability-aligned. */
	void * __capability aligner;

	/* Everything assumes buffers start with those two fields. */
	struct {
		size_t	len;
		int	op;
	};
} capv_t;

typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		char	answerback[1024];
	};
} capv_answerback_t;

/*
 * XXX: Those should eventually be split into separate headers,
 *      but leave them here for the time being so we can maintain
 *      some consistency.
 */
typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		int	error;
		int	errno_;
		struct timespec	ts;
	};
} capv_clocks_t;

typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		void * __capability s;
		struct sockaddr_storage addr;
		socklen_t addrlen;
	};
} capv_binds_t;

typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		uintcap_t arg[8];
	};
} capv_syscall_t;

/*
 * XXX: Merge those two into an universal error return struct?
 */
typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		int	error;
		int	errno_;
	};
} capv_binds_return_t;

typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		int	error;
		int	errno_;
	};
} capv_clearances_return_t;

typedef union {
	void * __capability aligner;
	struct {
		size_t	len;
		int	op;
		int	error;
		int	errno_;
		uintcap_t fdcap;
	};
} capv_syscall_return_t;

#endif /* !_CAPV_H_ */

