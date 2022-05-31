/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Stormshield.
 * Copyright (c) 2021 Semihalf.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/malloc.h>

#include <opencrypto/cryptodev.h>

#include <crypto/openssl/ossl.h>
#include <crypto/openssl/ossl_cipher.h>

#if defined(__amd64__) || defined(__i386__)
#include <crypto/openssl/ossl_x86.h>
#elif defined (__aarch64__)
#include <crypto/openssl/ossl_aarch64.h>
#endif

static ossl_cipher_process_t ossl_aes_cbc;

struct ossl_cipher ossl_cipher_aes_cbc = {
	.type = CRYPTO_AES_CBC,
	.blocksize = AES_BLOCK_LEN,
	.ivsize = AES_BLOCK_LEN,

	/* Filled during initialization based on CPU caps. */
	.set_encrypt_key = NULL,
	.set_decrypt_key = NULL,
	.process = ossl_aes_cbc
};

static int
ossl_aes_cbc(struct ossl_session_cipher *s, struct cryptop *crp,
    const struct crypto_session_params *csp)
{
	struct crypto_buffer_cursor cc_in, cc_out;
	unsigned char block[EALG_MAX_BLOCK_LEN];
	unsigned char iv[EALG_MAX_BLOCK_LEN];
	const unsigned char *in, *inseg;
	unsigned char *out, *outseg;
	size_t plen, seglen, inlen, outlen;
	struct ossl_cipher_context key;
	struct ossl_cipher *cipher;
	int blocklen, error;
	bool encrypt;

	cipher = s->cipher;
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);
	plen = crp->crp_payload_length;
	blocklen = cipher->blocksize;

	if (plen % blocklen)
		return (EINVAL);

	if (crp->crp_cipher_key != NULL) {
		if (encrypt)
			error = cipher->set_encrypt_key(crp->crp_cipher_key,
			    8 * csp->csp_cipher_klen, &key);
		else
			error = cipher->set_decrypt_key(crp->crp_cipher_key,
			    8 * csp->csp_cipher_klen, &key);
		if (error)
			return (error);
	} else {
		if (encrypt)
			key = s->enc_ctx;
		else
			key = s->dec_ctx;
	}

	crypto_read_iv(crp, iv);

	/* Derived from ossl_chacha20.c */
	crypto_cursor_init(&cc_in, &crp->crp_buf);
	crypto_cursor_advance(&cc_in, crp->crp_payload_start);
	inseg = crypto_cursor_segment(&cc_in, &inlen);
	if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
		crypto_cursor_init(&cc_out, &crp->crp_obuf);
		crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);
	} else {
		cc_out = cc_in;
	}
	outseg = crypto_cursor_segment(&cc_out, &outlen);

	while (plen >= blocklen) {
		if (inlen < blocklen) {
			crypto_cursor_copydata(&cc_in, blocklen, block);
			in = block;
			inlen = blocklen;
		} else {
			in = inseg;
		}
		if (outlen < blocklen) {
			out = block;
			outlen = blocklen;
		} else {
			out = outseg;
		}

		/* Figure out how many blocks we can encrypt/decrypt at once. */
		seglen = rounddown(MIN(plen, MIN(inlen, outlen)), blocklen);

		AES_CBC_ENCRYPT(in, out, seglen, &key, iv, encrypt);

		if (out == block) {
			crypto_cursor_copyback(&cc_out, blocklen, block);
			outseg = crypto_cursor_segment(&cc_out, &outlen);
		} else {
			crypto_cursor_advance(&cc_out, seglen);
			outseg += seglen;
			outlen -= seglen;
		}
		if (in == block) {
			inseg = crypto_cursor_segment(&cc_in, &inlen);
		} else {
			crypto_cursor_advance(&cc_in, seglen);
			inseg += seglen;
			inlen -= seglen;
		}
		plen -= seglen;
	}

	explicit_bzero(block, sizeof(block));
	explicit_bzero(iv, sizeof(iv));
	explicit_bzero(&key, sizeof(key));
	return (0);
}
