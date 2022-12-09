/* $OpenBSD: deflate.c,v 1.3 2001/08/20 02:45:22 hugh Exp $ */

/*-
 * Copyright (c) 2001 Jean-Jacques Bernard-Gundol (jj@wabbitt.org)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
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
 */

/*
 * This file contains a wrapper around the deflate algo compression
 * functions using the zlib library (see sys/contrib/zlib)
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/compressor.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sdt.h>
#include <sys/systm.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/deflate.h>

SDT_PROVIDER_DECLARE(opencrypto);
SDT_PROBE_DEFINE2(opencrypto, deflate, deflate_global, entry,
    "int", "uint32_t");
SDT_PROBE_DEFINE6(opencrypto, deflate, deflate_global, bad,
    "int", "int", "int", "int", "int", "int");
SDT_PROBE_DEFINE2(opencrypto, deflate, deflate_global, return,
    "int", "uint32_t");

static int
deflate_global_cb(void *base, size_t length, off_t offset __unused, void *arg)
{
	struct deflate_buf *newbuf;
	TAILQ_HEAD(, deflate_buf) *bufsp;

	newbuf = malloc(sizeof(*newbuf) + length, M_CRYPTO_DATA, M_NOWAIT);
	if (newbuf == NULL) {
		return (ENOMEM);
	}
	newbuf->size = length;

	bcopy(base, &newbuf->data, newbuf->size);

	bufsp = arg;
	TAILQ_INSERT_TAIL(bufsp, newbuf, next);
	return (0);
}

/*
 * This function takes a block of data and (de)compress it using the deflate
 * algorithm
 */
uint32_t
deflate_global(uint8_t *data, uint32_t size, int decomp, uint8_t **out)
{
	/* decomp indicates whether we compress (0) or decompress (1) */

	uint8_t *output, *outputp;
	uint32_t result;
	int error, i;
	struct compressor *stream;
	TAILQ_HEAD(, deflate_buf) bufs;
	struct deflate_buf *buf, *tmpbuf;

	SDT_PROBE2(opencrypto, deflate, deflate_global, entry, decomp, size);

	result = 0;
	output = NULL;

	if (!decomp) {
		i = 1;
	} else {
		/*
	 	 * Choose a buffer with 4x the size of the input buffer
	 	 * for the size of the output buffer in the case of
	 	 * decompression. If it's not sufficient, it will need to be
	 	 * updated while the decompression is going on.
	 	 */
		i = 4;
	}
	/*
	 * Make sure we do have enough output space.  Repeated calls to
	 * deflate need at least 6 bytes of output buffer space to avoid
	 * repeated markers.  We will always provide at least 16 bytes.
	 */
	while ((size * i) < 16)
		i++;

	TAILQ_INIT(&bufs);
	if (decomp) {
		stream = compressor_init(deflate_global_cb,
		    COMPRESS_ZLIB_INFLATE, size * i, 0, &bufs);
	} else {
		stream = compressor_init(deflate_global_cb,
		    COMPRESS_ZLIB_DEFLATE, size * i, 0, &bufs);
	}
	if (stream == NULL) {
		SDT_PROBE6(opencrypto, deflate, deflate_global, bad,
		    decomp, 0, __LINE__, 0, 0, 0);
		goto out;
	}

	error = compressor_write(stream, data, size);
	if (error != 0) {
		SDT_PROBE6(opencrypto, deflate, deflate_global, bad,
		    decomp, error, __LINE__, 0, 0, 0);
		goto out;
	}

	error = compressor_flush(stream);
	if (error != 0) {
		SDT_PROBE6(opencrypto, deflate, deflate_global, bad,
		    decomp, error, __LINE__, 0, 0, 0);
		goto out;
	}

	TAILQ_FOREACH(buf, &bufs, next) {
		result += buf->size;
	}
	output = malloc(result, M_CRYPTO_DATA, M_NOWAIT);
	if (*out == NULL) {
		SDT_PROBE6(opencrypto, deflate, deflate_global, bad, decomp,
		    ENOMEM, __LINE__, 0, 0, 0);
		goto out;
	}
	outputp = output;
	TAILQ_FOREACH_SAFE(buf, &bufs, next, tmpbuf) {
		bcopy(&buf->data, outputp, buf->size);
		outputp += buf->size;
		TAILQ_REMOVE(&bufs, buf, next);
		free(buf, M_CRYPTO_DATA);
	}

	SDT_PROBE2(opencrypto, deflate, deflate_global, return, decomp, result);
out:
	*out = output;
	if (stream != NULL)
		compressor_fini(stream);
	return (result);
}
