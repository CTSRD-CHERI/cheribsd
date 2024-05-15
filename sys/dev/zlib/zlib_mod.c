/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 The FreeBSD Foundation
 * Copyright (c) 2022 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#include <sys/param.h>
#include <sys/compressor.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sdt.h>
#include <sys/time.h>

#include <contrib/zlib/zlib.h>
#include <contrib/zlib/zutil.h>

SDT_PROVIDER_DECLARE(zlib);
SDT_PROBE_DEFINE3(zlib, , init, error,
    "int", "int", "int");
SDT_PROBE_DEFINE6(zlib, , write, error3,
    "int", "int", "int", "int", "int", "int");
SDT_PROBE_DEFINE6(zlib, , write, iteration,
    "int", "int", "int", "int", "int", "int");

#define	ZLIB_PROBE_ERROR(fun, deflate, ret)				\
	SDT_PROBE3(zlib, , fun, error, deflate, __LINE__, ret)
#define	ZLIB_PROBE_ERROR3(fun, deflate, ret, arg0, arg1, arg2)		\
	SDT_PROBE6(zlib, , fun, error3, deflate, __LINE__, ret, arg0,	\
	arg1, arg2)
#define	ZLIB_PROBE_ITERATION(fun, deflate, arg0, arg1, arg2)		\
	SDT_PROBE5(zlib, , fun, 0, deflate, __LINE__, arg0, arg1, arg2)

struct zlib_stream {
	bool			zls_deflate;	/* deflate/inflate flag */
	z_stream		zls_stream;	/* zlib state */
	size_t			zls_size;	/* size of zls_data[] */
	uint8_t			zls_data[];	/* output buffer */
};

static void	zlib_reset(void *stream);
static void	zlib_fini(void *stream);

static void *
zlib_stream_zalloc(void *arg __unused, u_int n, u_int sz)
{

	/*
	 * Memory for zlib state is allocated using M_NODUMP since it may be
	 * used to compress a kernel dump, and we don't want zlib to attempt to
	 * compress its own state.
	 */
	return (malloc(n * sz, M_COMPRESS, M_WAITOK | M_ZERO | M_NODUMP));
}

static void
zlib_stream_free(void *arg __unused, void *ptr)
{

	free(ptr, M_COMPRESS);
}

static void *
zlib_init(size_t maxiosize, int level, bool deflate)
{
	struct zlib_stream *s;
	z_stream *zstream;
	int error;

	error = 0;

	s = zlib_stream_zalloc(NULL, 1, roundup(sizeof(*s) + maxiosize,
	    PAGE_SIZE));
	if (s == NULL) {
		error = ENOMEM;
		ZLIB_PROBE_ERROR(init, deflate, error);
		goto fail;
	}

	zstream = &s->zls_stream;
	zstream->zalloc = zlib_stream_zalloc;
	zstream->zfree = zlib_stream_free;
	zstream->opaque = Z_NULL;

	s->zls_deflate = deflate;
	s->zls_size = maxiosize;
	if (level != Z_DEFAULT_COMPRESSION) {
		if (level < Z_BEST_SPEED)
			level = Z_BEST_SPEED;
		else if (level > Z_BEST_COMPRESSION)
			level = Z_BEST_COMPRESSION;
	}
	if (s->zls_deflate) {
		/*
		 * XXXKW: windowBits should be configurable, e.g. opencrypto(9)
		 * sets it to -12 in upstream.
		 */
		error = deflateInit2(zstream, level, Z_DEFLATED,
		    -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);
	} else {
		error = inflateInit2(zstream, -MAX_WBITS);
	}
	if (error != 0) {
		ZLIB_PROBE_ERROR(init, s->zls_deflate, error);
		goto fail;
	}

	zlib_reset(s);
fail:
	if (error != 0 && s != NULL) {
		zlib_fini(s);
		s = NULL;
	}
	return (s);
}

static void
zlib_reset(void *stream)
{
	struct zlib_stream *s;
	z_stream *zstream;

	s = stream;
	zstream = &s->zls_stream;

	(void)deflateReset(zstream);
	zstream->avail_out = s->zls_size;
	zstream->next_out = s->zls_data;
}

static void *
zlib_deflate_init(size_t maxiosize, int level)
{

	return (zlib_init(maxiosize, level, true));
}

static void *
zlib_inflate_init(size_t maxiosize, int level)
{

	return (zlib_init(maxiosize, level, false));
}

static int
zlib_write(void *stream, void *data, size_t len, compressor_cb_t cb, void *bufs)
{
	struct zlib_stream *s;
	int error, zerror, zflag;
	z_stream *zstream;

	s = stream;
	zstream = &s->zls_stream;

	error = 0;
	if (data == NULL) {
		if (s->zls_deflate) {
			zflag = Z_FINISH;
		} else {
			zflag = Z_SYNC_FLUSH;
		}
	} else {
		zflag = Z_NO_FLUSH;
	}
	zstream->next_in = data;
	zstream->avail_in = len;
	do {
		if (s->zls_deflate)
			zerror = deflate(zstream, zflag);
		else
			zerror = inflate(zstream, zflag);
		if (zerror != Z_OK && zerror != Z_STREAM_END) {
			ZLIB_PROBE_ERROR3(write, s->zls_deflate, zerror,
			    zstream->avail_in, zstream->avail_out,
			    zstream->total_out);
			error = EIO;
			break;
		}

		ZLIB_PROBE_ITERATION(write, s->zls_deflate,
		    zstream->avail_in, zstream->avail_out,
		    zstream->total_out);

		if (zstream->avail_out == 0 || zerror == Z_STREAM_END) {
			/*
			 * We need to flush an output buffer for another
			 * iteration.
			 */
			error = cb(&s->zls_data, zstream->total_out, 0, bufs);
			if (error != 0) {
				ZLIB_PROBE_ERROR3(write, s->zls_deflate, error,
				    zstream->avail_in, zstream->avail_out,
				    zstream->total_out);
			}
			zstream->next_out = s->zls_data;
			zstream->avail_out = s->zls_size;
		}
	} while (zerror != Z_STREAM_END &&
	    (zflag == Z_FINISH || zstream->avail_in > 0));

	return (error);
}

static void
zlib_fini(void *stream)
{
	struct zlib_stream *s;

	s = stream;
	if (s->zls_deflate)
		deflateEnd(&s->zls_stream);
	else
		deflateEnd(&s->zls_stream);
	zlib_stream_free(NULL, s);
}

static struct compressor_methods zlib_deflate_methods = {
	.format = COMPRESS_ZLIB_DEFLATE,
	.init = zlib_deflate_init,
	.reset = zlib_reset,
	.write = zlib_write,
	.fini = zlib_fini
};
COMPRESSOR_LOAD(zlib_deflate, &zlib_deflate_methods);

static struct compressor_methods zlib_inflate_methods = {
	.format = COMPRESS_ZLIB_INFLATE,
	.init = zlib_inflate_init,
	.reset = zlib_reset,
	.write = zlib_write,
	.fini = zlib_fini
};
COMPRESSOR_LOAD(zlib_inflate, &zlib_inflate_methods);

static int
zlib_modevent(module_t mod, int type, void *unused)
{
	switch (type) {
	case MOD_LOAD:
		return 0;
	case MOD_UNLOAD:
		return 0;
	}
	return EINVAL;
}

static moduledata_t zlib_mod = {
	"zlib",
	zlib_modevent,
	0
};
DECLARE_MODULE(zlib, zlib_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(zlib, 1);
