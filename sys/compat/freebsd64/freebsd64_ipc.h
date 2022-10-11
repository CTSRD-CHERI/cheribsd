/*-
 * Copyright (c) 2015-2019 SRI International
 * Copyright (c) 2001 Doug Rabson
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#ifndef _COMPAT_FREEBSD64_FREEBSD64_IPC_H_
#define _COMPAT_FREEBSD64_FREEBSD64_IPC_H_

#include <sys/msg.h>
#include <sys/shm.h>

struct semid_ds64 {
	struct ipc_perm	sem_perm;
	uint64_t	__sem_base;
	unsigned short	sem_nsems;
	time_t		sem_otime;
	time_t		sem_ctime;
};

#ifdef _KERNEL
struct semid_kernel64 {
	/* Data structure exposed to user space. */
	struct semid_ds64	u;

	/* Kernel-private components of the semaphore. */
	uint64_t		label;
	uint64_t		cred;
};
#endif /* _KERNEL */

union semun64 {
	int		val;
	uint64_t	buf;
	uint64_t	array;
};

struct msqid_ds64 {
	struct ipc_perm	msg_perm;
	uint64_t	__msg_first;
	uint64_t	__msg_last;
	msglen_t	msg_cbytes;
	msgqnum_t	msg_qnum;
	msglen_t	msg_qbytes;
	pid_t		msg_lspid;
	pid_t		msg_lrpid;
	time_t		msg_stime;
	time_t		msg_rtime;
	time_t		msg_ctime;
};

#ifdef _KERNEL
struct msqid_kernel64 {
	struct msqid_ds64	u;
	uint64_t		label;
	uint64_t		cred;
};
#endif

struct shmid_ds64 {
	struct ipc_perm	shm_perm;
	size_t		shm_segsz;
	pid_t		shm_lpid;
	pid_t		shm_cpid;
	shmatt_t	shm_nattch;
	time_t		shm_atime;
	time_t		shm_dtime;
	time_t		shm_ctime;
};

#ifdef _KERNEL
struct shmid_kernel64 {
	struct shmid_ds64	u;
	uint64_t		object;
	uint64_t		label;
	uint64_t		cred;
};
#endif

#if defined(COMPAT_FREEBSD4) || defined(COMPAT_FREEBSD5) || \
    defined(COMPAT_FREEBSD6) || defined(COMPAT_FREEBSD7)
struct semid_ds_old64 {
	struct ipc_perm_old sem_perm;
	uint64_t	__sem_base;
	unsigned short	sem_nsems;
	time_t		sem_otime;
	long		sem_pad1;
	time_t		sem_ctime;
	long		sem_pad2;
	long		sem_pad3[4];
};

struct msqid_ds_old64 {
	struct ipc_perm_old	msg_perm;
	int64_t			__msg_first;
	int64_t			__msg_last;
	msglen_t		msg_cbytes;
	msgqnum_t		msg_qnum;
	msglen_t		msg_qbytes;
	pid_t			msg_lspid;
	pid_t			msg_lrpid;
	time_t			msg_stime;
	long			msg_pad1;
	time_t			msg_rtime;
	long			msg_pad2;
	time_t			msg_ctime;
	long			msg_pad3;
	long			msg_pad4[4];

};

struct shmid_ds_old64 {
	struct ipc_perm_old shm_perm;
	int		shm_segsz;
	pid_t		shm_lpid;
	pid_t		shm_cpid;
	short		shm_nattch;
	time_t		shm_atime;
	time_t		shm_dtime;
	time_t		shm_ctime;
	uint64_t	shm_internal;
};

union semun_old64 {
	int		val;
	uint64_t	buf;
	uint64_t	array;
};
#endif

#endif /* !_COMPAT_FREEBSD64_FREEBSD64_IPC_H_ */
