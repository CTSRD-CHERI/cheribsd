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

#ifndef __DRMCOMPAT_LINUX_MODULE_H__
#define	__DRMCOMPAT_LINUX_MODULE_H__

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/linker.h>

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/moduleparam.h>

#define MODULE_AUTHOR(name)
#define MODULE_DESCRIPTION(name)
#define MODULE_LICENSE(name)
#define	MODULE_INFO(tag, info)
#define	MODULE_FIRMWARE(firmware)

#define	THIS_MODULE	((struct module *)0)

#define	__MODULE_STRING(x) __stringify(x)

#define	module_init(fn)							\
	SYSINIT(fn, SI_SUB_DRIVERS, SI_ORDER_THIRD, (fn), NULL)

#define	module_exit(fn)							\
	SYSUNINIT(fn, SI_SUB_DRIVERS, SI_ORDER_THIRD, (fn), NULL)
#define	module_get(module)
#define	module_put(module)
#define	try_module_get(module)	1

#endif /* __DRMCOMPAT_LINUX_MODULE_H__ */
