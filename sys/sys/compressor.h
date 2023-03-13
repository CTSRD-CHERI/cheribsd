/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014, 2017 Mark Johnston <markj@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
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

#ifndef _SYS__COMPRESSOR_H_
#define _SYS__COMPRESSOR_H_

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/linker_set.h>
#include <sys/malloc.h>
#include <sys/queue.h>

/* Supported compressor methods. */
#define	COMPRESS_ZLIB_DEFLATE	1
#define	COMPRESS_ZLIB_INFLATE	2
#define	COMPRESS_GZIP		3
#define	COMPRESS_ZSTD		4

#define	COMPRESSOR_LOAD(name, methods)					\
	SYSINIT(compressor_ ## name, SI_SUB_DRIVERS, SI_ORDER_ANY,	\
	(sysinit_cfunc_t)compressor_register, methods);			\
	SYSUNINIT(compressor_ ## name, SI_SUB_DRIVERS, SI_ORDER_ANY,	\
	compressor_unregister, methods)

typedef int (*compressor_cb_t)(void *, size_t, off_t, void *);

struct compressor_methods {
	int format;
	void *(*init)(size_t, int);
	void (*reset)(void *);
	int (*write)(void *, void *, size_t, compressor_cb_t, void *);
	void (*fini)(void *);
	TAILQ_ENTRY(compressor_methods) next;
};

struct compressor;

MALLOC_DECLARE(M_COMPRESS);

void		compressor_register(struct compressor_methods *method);
void		compressor_unregister(struct compressor_methods *method);
bool		compressor_avail(int format);
struct compressor *compressor_init(compressor_cb_t cb, int format,
		    size_t maxiosize, int level, void *arg);
void		compressor_reset(struct compressor *stream);
int		compressor_write(struct compressor *stream, void *data,
		    size_t len);
int		compressor_flush(struct compressor *stream);
void		compressor_fini(struct compressor *stream);

#endif /* _KERNEL */
#endif /* _SYS__COMPRESSOR_H_ */
