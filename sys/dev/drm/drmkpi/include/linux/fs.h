/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2017 Mellanox Technologies, Ltd.
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

#ifndef	__DRMCOMPAT_LINUX_FS_H__
#define	__DRMCOMPAT_LINUX_FS_H__

#include <linux/types.h>
#include <linux/wait.h>

#include <drmcompat/fs.h>

#define	S_IRUGO	(S_IRUSR | S_IRGRP | S_IROTH)
#define	S_IWUGO	(S_IWUSR | S_IWGRP | S_IWOTH)

/*
 * This is ugly way how reduce number of #ifdef __linux__
 * changes due to struct file FBSD <-> Linux file->private_data field naming
 * difference. Alternatively, we may usee unnamed union in definition of
 * struct file.
 */
#define	private_data	f_data
#define	f_flags		f_flag
#define	EPOLLIN		POLLIN
#define	EPOLLRDNORM	POLLRDNORM

#define  shmem_file_setup(...) \
  drmcompat_shmem_file_setup(__VA_ARGS__)

#define	iminor(inode)	drmcompat_iminor(inode)

#endif /* __DRMCOMPAT_LINUX_FS_H__ */
