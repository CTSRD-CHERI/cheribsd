/*-
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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

/* User-visible header. */

#ifndef _DEV_HWT_HWT_H_
#define _DEV_HWT_HWT_H_

#define	HWT_MAGIC	0x42
#define	HWT_IOC_ALLOC \
	_IOW(HWT_MAGIC, 0x00, struct hwt_alloc)
#define	HWT_IOC_START \
	_IOW(HWT_MAGIC, 0x01, struct hwt_start)
#define	HWT_IOC_RECORD_GET \
	_IOW(HWT_MAGIC, 0x02, struct hwt_record_get)
#define	HWT_IOC_BUFPTR_GET \
	_IOW(HWT_MAGIC, 0x03, struct hwt_bufptr_get)

struct hwt_alloc {
	int		cpu_id;
	pid_t		pid;
} __packed __aligned(16);

struct hwt_start {
	int		cpu_id;
	pid_t		pid;
} __packed __aligned(16);

struct hwt_record_user_entry {
	char fullpath[MAXPATHLEN];
	uintptr_t addr;
	size_t size;
} __packed __aligned(16);

struct hwt_record_get {
	struct hwt_record_user_entry	*records;
	int				*nentries;
	int				cpu_id;
	pid_t				pid;
} __packed __aligned(16);

struct hwt_bufptr_get {
	int		*ptr;
	int		*curpage;
	vm_offset_t	*curpage_offset;
	int		cpu_id;
	pid_t		pid;
} __packed __aligned(16);

#endif /* !_DEV_HWT_HWT_H_ */
