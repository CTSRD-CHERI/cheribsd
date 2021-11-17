/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002 Doug Rabson
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

#ifndef _COMPAT_FREEBSD32_FREEBSD32_IPC_H_
#define _COMPAT_FREEBSD32_FREEBSD32_IPC_H_

struct ipc_perm32 {
	uid_t		cuid;
	gid_t		cgid;
	uid_t		uid;
	gid_t		gid;
	mode_t		mode;
	uint16_t	seq;
	uint32_t	key;
};

#if defined(COMPAT_FREEBSD4) || defined(COMPAT_FREEBSD5) || \
    defined(COMPAT_FREEBSD6) || defined(COMPAT_FREEBSD7)
struct ipc_perm_old32 {
	uint16_t	cuid;
	uint16_t	cgid;
	uint16_t	uid;
	uint16_t	gid;
	uint16_t	mode;
	uint16_t	seq;
	uint32_t	key;
};

void	freebsd32_ipcperm_old_in(struct ipc_perm_old32 *ip32,
	    struct ipc_perm *ip);
void	freebsd32_ipcperm_old_out(struct ipc_perm *ip,
	    struct ipc_perm_old32 *ip32);
#endif

void	freebsd32_ipcperm_in(struct ipc_perm32 *ip32, struct ipc_perm *ip);
void	freebsd32_ipcperm_out(struct ipc_perm *ip, struct ipc_perm32 *ip32);

#endif /* !_COMPAT_FREEBSD32_FREEBSD32_IPC_H_ */
