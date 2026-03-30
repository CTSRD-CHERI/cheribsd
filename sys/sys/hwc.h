/*-
 * Copyright (c) 2026 Ruslan Bukin <br@bsdpad.com>
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
 */

/* User-visible header. */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/types.h>

#ifndef _SYS_HWC_H_
#define _SYS_HWC_H_

#define	HWC_MAGIC		0x42
#define	HWC_IOC_ALLOC		_IOW(HWC_MAGIC, 0x00, struct hwc_alloc)
#define	HWC_IOC_CONFIGURE	_IOW(HWC_MAGIC, 0x01, struct hwc_configure)
#define	HWC_IOC_START		_IOW(HWC_MAGIC, 0x02, struct hwc_start)
#define	HWC_IOC_STOP		_IOW(HWC_MAGIC, 0x03, struct hwc_stop)

#define	HWC_BACKEND_MAXNAMELEN	256

#define	HWC_MODE_THREAD		1

#ifdef COMPAT_FREEBSD64
struct hwc_alloc64 {
	int		mode;
	pid_t		pid;		/* thread mode */
	uint64_t	backend_name;
	size_t		backend_name_len;
	uint64_t	ident;
} __aligned(16);
#endif

struct hwc_alloc {
	int		mode;
	pid_t		pid;		/* thread mode */
	const char	* __capability backend_name;
	size_t		backend_name_len;
	int		* __capability ident;
} __aligned(16);

struct hwc_configure {
	int		event_id;
	int		counter_id;
	int		flags;
} __aligned(16);

struct hwc_start {
	int		counter_mask;
	int		flags;
	int		data;
} __aligned(16);

struct hwc_stop {
	int		counter_mask;
	int		flags;
} __aligned(16);

#endif /* !_SYS_HWC_H_ */
