/*-
 * Copyright (c) 2015 Dmitry Chagin
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

#ifndef _LINUX_MI_H_
#define _LINUX_MI_H_

#include <sys/queue.h>

#define	LINUX_IFHWADDRLEN	6
#define	LINUX_IFNAMSIZ		16

/*
 * Criteria for interface name translation
 */
#define	IFP_IS_ETH(ifp)		(ifp->if_type == IFT_ETHER)
#define	IFP_IS_LOOP(ifp)	(ifp->if_type == IFT_LOOP)

struct l_sockaddr {
	unsigned short	sa_family;
	char		sa_data[14];
};

#define	LINUX_ARPHRD_ETHER	1
#define	LINUX_ARPHRD_LOOPBACK	772

/*
 * Supported address families
 */
#define	LINUX_AF_UNSPEC		0
#define	LINUX_AF_UNIX		1
#define	LINUX_AF_INET		2
#define	LINUX_AF_AX25		3
#define	LINUX_AF_IPX		4
#define	LINUX_AF_APPLETALK	5
#define	LINUX_AF_INET6		10

/*
 * net device flags
 */
#define	LINUX_IFF_UP		0x0001
#define	LINUX_IFF_BROADCAST	0x0002
#define	LINUX_IFF_DEBUG		0x0004
#define	LINUX_IFF_LOOPBACK	0x0008
#define	LINUX_IFF_POINTOPOINT	0x0010
#define	LINUX_IFF_NOTRAILERS	0x0020
#define	LINUX_IFF_RUNNING	0x0040
#define	LINUX_IFF_NOARP		0x0080
#define	LINUX_IFF_PROMISC	0x0100
#define	LINUX_IFF_ALLMULTI	0x0200
#define	LINUX_IFF_MASTER	0x0400
#define	LINUX_IFF_SLAVE		0x0800
#define	LINUX_IFF_MULTICAST	0x1000
#define	LINUX_IFF_PORTSEL	0x2000
#define	LINUX_IFF_AUTOMEDIA	0x4000
#define	LINUX_IFF_DYNAMIC	0x8000

/* sigaltstack */
#define	LINUX_SS_ONSTACK	1
#define	LINUX_SS_DISABLE	2

int linux_to_bsd_sigaltstack(int lsa);
int bsd_to_linux_sigaltstack(int bsa);

/* sigset */
typedef struct {
	uint64_t	__mask;
} l_sigset_t;

/* primitives to manipulate sigset_t */
#define	LINUX_SIGEMPTYSET(set)		(set).__mask = 0
#define	LINUX_SIGISMEMBER(set, sig)	(1UL & ((set).__mask >> _SIG_IDX(sig)))
#define	LINUX_SIGADDSET(set, sig)	(set).__mask |= 1UL << _SIG_IDX(sig)

void linux_to_bsd_sigset(l_sigset_t *, sigset_t *);
void bsd_to_linux_sigset(sigset_t *, l_sigset_t *);

/* signaling */
#define	LINUX_SIGHUP		1
#define	LINUX_SIGINT		2
#define	LINUX_SIGQUIT		3
#define	LINUX_SIGILL		4
#define	LINUX_SIGTRAP		5
#define	LINUX_SIGABRT		6
#define	LINUX_SIGIOT		LINUX_SIGABRT
#define	LINUX_SIGBUS		7
#define	LINUX_SIGFPE		8
#define	LINUX_SIGKILL		9
#define	LINUX_SIGUSR1		10
#define	LINUX_SIGSEGV		11
#define	LINUX_SIGUSR2		12
#define	LINUX_SIGPIPE		13
#define	LINUX_SIGALRM		14
#define	LINUX_SIGTERM		15
#define	LINUX_SIGSTKFLT		16
#define	LINUX_SIGCHLD		17
#define	LINUX_SIGCONT		18
#define	LINUX_SIGSTOP		19
#define	LINUX_SIGTSTP		20
#define	LINUX_SIGTTIN		21
#define	LINUX_SIGTTOU		22
#define	LINUX_SIGURG		23
#define	LINUX_SIGXCPU		24
#define	LINUX_SIGXFSZ		25
#define	LINUX_SIGVTALRM		26
#define	LINUX_SIGPROF		27
#define	LINUX_SIGWINCH		28
#define	LINUX_SIGIO		29
#define	LINUX_SIGPOLL		LINUX_SIGIO
#define	LINUX_SIGPWR		30
#define	LINUX_SIGSYS		31
#define	LINUX_SIGTBLSZ		31
#define	LINUX_SIGRTMIN		32
#define	LINUX_SIGRTMAX		64

#define LINUX_SIG_VALID(sig)	((sig) <= LINUX_SIGRTMAX && (sig) > 0)

int linux_to_bsd_signal(int sig);
int bsd_to_linux_signal(int sig);

extern LIST_HEAD(futex_list, futex) futex_list;
extern struct mtx futex_mtx;

void linux_dev_shm_create(void);
void linux_dev_shm_destroy(void);

#endif /* _LINUX_MI_H_ */
