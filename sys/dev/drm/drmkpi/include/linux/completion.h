/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	__DRMCOMPAT_LINUX_COMPLETION_H__
#define	__DRMCOMPAT_LINUX_COMPLETION_H__

#include <linux/errno.h>

#include <drmcompat/completion.h>

#define	INIT_COMPLETION(c) \
	((c).done = 0)
#define	init_completion(c) \
	do { (c)->done = 0; } while (0)
#define	reinit_completion(c) \
	do { (c)->done = 0; } while (0)
#define	complete(c)				\
	drmcompat_complete_common((c), 0)
#define	complete_all(c)				\
	drmcompat_complete_common((c), 1)
#define	wait_for_completion(c)			\
	drmcompat_wait_for_common((c), 0)
#define	wait_for_completion_interruptible(c)	\
	drmcompat_wait_for_common((c), 1)
#define	wait_for_completion_timeout(c, timeout)	\
	drmcompat_wait_for_timeout_common((c), (timeout), 0)
#define	wait_for_completion_interruptible_timeout(c, timeout)	\
	drmcompat_wait_for_timeout_common((c), (timeout), 1)
#define	try_wait_for_completion(c) \
	drmcompat_try_wait_for_completion(c)
#define	completion_done(c) \
	drmcompat_completion_done(c)

#endif	/* __DRMCOMPAT_LINUX_COMPLETION_H__ */
