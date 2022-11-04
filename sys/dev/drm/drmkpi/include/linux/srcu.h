/*-
 * Copyright (c) 2015-2017 Mellanox Technologies, Ltd.
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

#ifndef __DRMCOMPAT_LINUX_SRCU_H__
#define	__DRMCOMPAT_LINUX_SRCU_H__

#include <drmcompat/srcu.h>

#define	__DEFINE_SRCU(name, is_static)					\
	is_static struct srcu_struct name;
#define	DEFINE_SRCU(name)		__DEFINE_SRCU(name, )
#define	DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)

#define	srcu_dereference(ptr,srcu)	((__typeof(*(ptr)) *)(ptr))

/* prototypes */

#define	srcu_read_lock(s)	drmcompat_srcu_read_lock(s)
#define	srcu_read_unlock(s, i)	drmcompat_srcu_read_unlock(s, i)
#define	synchronize_srcu(s)	drmcompat_synchronize_srcu(s)
#define	scru_barrier(s)		drmcompat_srcu_barrier(s)
#define	cleanup_srcu_struct(s)	drmcompat_cleanup_srcu_struct(s)
#define	init_srcu_struct(s)	drmcompat_init_srcu_struct(s)

#endif	/* __DRMCOMPAT_LINUX_SRCU_H__ */
