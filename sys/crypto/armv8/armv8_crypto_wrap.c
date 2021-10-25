/*-
 * Copyright (c) 2016 The FreeBSD Foundation
 * Copyright (c) 2020 Ampere Computing
 * All rights reserved.
 *
 * This software was developed by Andrew Turner under
 * sponsorship from the FreeBSD Foundation.
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

/*
 * This code is built with floating-point enabled. Make sure to have entered
 * into floating-point context before calling any of these functions.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/gmac.h>
#include <crypto/rijndael/rijndael.h>
#include <crypto/armv8/armv8_crypto.h>

#include <arm_neon.h>

static uint8x16_t
armv8_aes_enc(int rounds, const uint8x16_t *keysched, const uint8x16_t from)
{
	uint8x16_t tmp;
	int i;

	tmp = from;
	for (i = 0; i < rounds - 1; i += 2) {
		tmp = vaeseq_u8(tmp, keysched[i]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, keysched[i + 1]);
		tmp = vaesmcq_u8(tmp);
	}

	tmp = vaeseq_u8(tmp, keysched[rounds - 1]);
	tmp = vaesmcq_u8(tmp);
	tmp = vaeseq_u8(tmp, keysched[rounds]);
	tmp = veorq_u8(tmp, keysched[rounds + 1]);

	return (tmp);
}

static uint8x16_t
armv8_aes_dec(int rounds, const uint8x16_t *keysched, const uint8x16_t from)
{
	uint8x16_t tmp;
	int i;

	tmp = from;
	for (i = 0; i < rounds - 1; i += 2) {
		tmp = vaesdq_u8(tmp, keysched[i]);
		tmp = vaesimcq_u8(tmp);
		tmp = vaesdq_u8(tmp, keysched[i+1]);
		tmp = vaesimcq_u8(tmp);
	}

	tmp = vaesdq_u8(tmp, keysched[rounds - 1]);
	tmp = vaesimcq_u8(tmp);
	tmp = vaesdq_u8(tmp, keysched[rounds]);
	tmp = veorq_u8(tmp, keysched[rounds + 1]);

	return (tmp);
}

void
armv8_aes_encrypt_cbc(const AES_key_t *key, size_t len,
    const uint8_t *from, uint8_t *to, const uint8_t iv[static AES_BLOCK_LEN])
{
	uint8x16_t tot, ivreg, tmp;
	size_t i;

	len /= AES_BLOCK_LEN;
	ivreg = vld1q_u8(iv);
	for (i = 0; i < len; i++) {
		tmp = vld1q_u8(from);
		tot = armv8_aes_enc(key->aes_rounds - 1,
		    (const void*)key->aes_key, veorq_u8(tmp, ivreg));
		ivreg = tot;
		vst1q_u8(to, tot);
		from += AES_BLOCK_LEN;
		to += AES_BLOCK_LEN;
	}
}

void
armv8_aes_decrypt_cbc(const AES_key_t *key, size_t len,
    uint8_t *buf, const uint8_t iv[static AES_BLOCK_LEN])
{
	uint8x16_t ivreg, nextiv, tmp;
	size_t i;

	len /= AES_BLOCK_LEN;
	ivreg = vld1q_u8(iv);
	for (i = 0; i < len; i++) {
		nextiv = vld1q_u8(buf);
		tmp = armv8_aes_dec(key->aes_rounds - 1,
		    (const void*)key->aes_key, nextiv);
		vst1q_u8(buf, veorq_u8(tmp, ivreg));
		ivreg = nextiv;
		buf += AES_BLOCK_LEN;
	}
}

#define	AES_XTS_BLOCKSIZE	16
#define	AES_XTS_IVSIZE		8
#define	AES_XTS_ALPHA		0x87	/* GF(2^128) generator polynomial */

static inline int32x4_t
xts_crank_lfsr(int32x4_t inp)
{
	const int32x4_t alphamask = {AES_XTS_ALPHA, 1, 1, 1};
	int32x4_t xtweak, ret;

	/* set up xor mask */
	xtweak = vextq_s32(inp, inp, 3);
	xtweak = vshrq_n_s32(xtweak, 31);
	xtweak &= alphamask;

	/* next term */
	ret = vshlq_n_s32(inp, 1);
	ret ^= xtweak;

	return ret;
}

static void
armv8_aes_crypt_xts_block(int rounds, const uint8x16_t *key_schedule,
    uint8x16_t *tweak, const uint8_t *from, uint8_t *to, int do_encrypt)
{
	uint8x16_t block;

	block = vld1q_u8(from) ^ *tweak;

	if (do_encrypt)
		block = armv8_aes_enc(rounds - 1, key_schedule, block);
	else
		block = armv8_aes_dec(rounds - 1, key_schedule, block);

	vst1q_u8(to, block ^ *tweak);

	*tweak = vreinterpretq_u8_s32(xts_crank_lfsr(vreinterpretq_s32_u8(*tweak)));
}

static void
armv8_aes_crypt_xts(int rounds, const uint8x16_t *data_schedule,
    const uint8x16_t *tweak_schedule, size_t len, const uint8_t *from,
    uint8_t *to, const uint8_t iv[static AES_BLOCK_LEN], int do_encrypt)
{
	uint8x16_t tweakreg;
	uint8_t tweak[AES_XTS_BLOCKSIZE] __aligned(16);
	size_t i, cnt;

	/*
	 * Prepare tweak as E_k2(IV). IV is specified as LE representation
	 * of a 64-bit block number which we allow to be passed in directly.
	 */
#if BYTE_ORDER == LITTLE_ENDIAN
	bcopy(iv, tweak, AES_XTS_IVSIZE);
	/* Last 64 bits of IV are always zero. */
	bzero(tweak + AES_XTS_IVSIZE, AES_XTS_IVSIZE);
#else
#error Only LITTLE_ENDIAN architectures are supported.
#endif
	tweakreg = vld1q_u8(tweak);
	tweakreg = armv8_aes_enc(rounds - 1, tweak_schedule, tweakreg);

	cnt = len / AES_XTS_BLOCKSIZE;
	for (i = 0; i < cnt; i++) {
		armv8_aes_crypt_xts_block(rounds, data_schedule, &tweakreg,
		    from, to, do_encrypt);
		from += AES_XTS_BLOCKSIZE;
		to += AES_XTS_BLOCKSIZE;
	}
}

void
armv8_aes_encrypt_xts(AES_key_t *data_schedule,
    const void *tweak_schedule, size_t len, const uint8_t *from, uint8_t *to,
    const uint8_t iv[static AES_BLOCK_LEN])
{

	armv8_aes_crypt_xts(data_schedule->aes_rounds,
	    (const void *)&data_schedule->aes_key, tweak_schedule, len, from,
	    to, iv, 1);
}

void
armv8_aes_decrypt_xts(AES_key_t *data_schedule,
    const void *tweak_schedule, size_t len, const uint8_t *from, uint8_t *to,
    const uint8_t iv[static AES_BLOCK_LEN])
{

	armv8_aes_crypt_xts(data_schedule->aes_rounds,
	    (const void *)&data_schedule->aes_key, tweak_schedule, len, from,
	    to,iv, 0);

}

#define	AES_INC_COUNTER(counter)				\
	do {							\
		for (int pos = AES_BLOCK_LEN - 1;		\
		     pos >= 0; pos--)				\
			if (++(counter)[pos])			\
				break;				\
	} while (0)

void
armv8_aes_encrypt_gcm(AES_key_t *aes_key, size_t len,
    const uint8_t *from, uint8_t *to,
    size_t authdatalen, const uint8_t *authdata,
    uint8_t tag[static GMAC_DIGEST_LEN],
    const uint8_t iv[static AES_GCM_IV_LEN],
    const __uint128_val_t *Htable)
{
	size_t i;
	const uint64_t *from64;
	uint64_t *to64;
	uint8_t aes_counter[AES_BLOCK_LEN];
	uint8_t block[AES_BLOCK_LEN];
	size_t trailer;
	__uint128_val_t EK0, EKi, Xi, lenblock;

	bzero(&aes_counter, AES_BLOCK_LEN);
	memcpy(aes_counter, iv, AES_GCM_IV_LEN);

	/* Setup the counter */
	aes_counter[AES_BLOCK_LEN - 1] = 1;

	/* EK0 for a final GMAC round */
	aes_v8_encrypt(aes_counter, EK0.c, aes_key);

	/* GCM starts with 2 as counter, 1 is used for final xor of tag. */
	aes_counter[AES_BLOCK_LEN - 1] = 2;

	memset(Xi.c, 0, sizeof(Xi.c));
	memset(block, 0, sizeof(block));
	memcpy(block, authdata, min(authdatalen, sizeof(block)));
	gcm_ghash_v8(Xi.u, Htable, block, AES_BLOCK_LEN);

	from64 = (const uint64_t*)from;
	to64 = (uint64_t*)to;
	trailer = len % AES_BLOCK_LEN;

	for (i = 0; i < (len - trailer); i += AES_BLOCK_LEN) {
		aes_v8_encrypt(aes_counter, EKi.c, aes_key);
		AES_INC_COUNTER(aes_counter);
		to64[0] = from64[0] ^ EKi.u[0];
		to64[1] = from64[1] ^ EKi.u[1];
		gcm_ghash_v8(Xi.u, Htable, (uint8_t*)to64, AES_BLOCK_LEN);

		to64 += 2;
		from64 += 2;
	}

	to += (len - trailer);
	from += (len - trailer);

	if (trailer) {
		aes_v8_encrypt(aes_counter, EKi.c, aes_key);
		AES_INC_COUNTER(aes_counter);
		for (i = 0; i < trailer; i++) {
			block[i] = to[i] = from[i] ^ EKi.c[i % AES_BLOCK_LEN];
		}

		for (; i < AES_BLOCK_LEN; i++)
			block[i] = 0;

		gcm_ghash_v8(Xi.u, Htable, block, AES_BLOCK_LEN);
	}

	/* Lengths block */
	lenblock.u[0] = lenblock.u[1] = 0;
	lenblock.d[1] = htobe32(authdatalen * 8);
	lenblock.d[3] = htobe32(len * 8);
	gcm_ghash_v8(Xi.u, Htable, lenblock.c, AES_BLOCK_LEN);

	Xi.u[0] ^= EK0.u[0];
	Xi.u[1] ^= EK0.u[1];
	memcpy(tag, Xi.c, GMAC_DIGEST_LEN);

	explicit_bzero(aes_counter, sizeof(aes_counter));
	explicit_bzero(Xi.c, sizeof(Xi.c));
	explicit_bzero(EK0.c, sizeof(EK0.c));
	explicit_bzero(EKi.c, sizeof(EKi.c));
	explicit_bzero(lenblock.c, sizeof(lenblock.c));
}

int
armv8_aes_decrypt_gcm(AES_key_t *aes_key, size_t len,
    const uint8_t *from, uint8_t *to,
    size_t authdatalen, const uint8_t *authdata,
    const uint8_t tag[static GMAC_DIGEST_LEN],
    const uint8_t iv[static AES_GCM_IV_LEN],
    const __uint128_val_t *Htable)
{
	size_t i;
	const uint64_t *from64;
	uint64_t *to64;
	uint8_t aes_counter[AES_BLOCK_LEN];
	uint8_t block[AES_BLOCK_LEN];
	size_t trailer;
	__uint128_val_t EK0, EKi, Xi, lenblock;
	int error;

	error = 0;
	bzero(&aes_counter, AES_BLOCK_LEN);
	memcpy(aes_counter, iv, AES_GCM_IV_LEN);

	/* Setup the counter */
	aes_counter[AES_BLOCK_LEN - 1] = 1;

	/* EK0 for a final GMAC round */
	aes_v8_encrypt(aes_counter, EK0.c, aes_key);

	memset(Xi.c, 0, sizeof(Xi.c));
	memset(block, 0, sizeof(block));
	memcpy(block, authdata, min(authdatalen, sizeof(block)));
	gcm_ghash_v8(Xi.u, Htable, block, AES_BLOCK_LEN);
	trailer = len % AES_BLOCK_LEN;
	gcm_ghash_v8(Xi.u, Htable, from, len - trailer);

	if (trailer) {
		for (i = 0; i < trailer; i++)
			block[i] = from[len - trailer + i];
		for (; i < AES_BLOCK_LEN; i++)
			block[i] = 0;
		gcm_ghash_v8(Xi.u, Htable, block, AES_BLOCK_LEN);
	}

	/* Lengths block */
	lenblock.u[0] = lenblock.u[1] = 0;
	lenblock.d[1] = htobe32(authdatalen * 8);
	lenblock.d[3] = htobe32(len * 8);
	gcm_ghash_v8(Xi.u, Htable, lenblock.c, AES_BLOCK_LEN);

	Xi.u[0] ^= EK0.u[0];
	Xi.u[1] ^= EK0.u[1];
	if (timingsafe_bcmp(tag, Xi.c, GMAC_DIGEST_LEN) != 0) {
		error = EBADMSG;
		goto out;
	}

	/* GCM starts with 2 as counter, 1 is used for final xor of tag. */
	aes_counter[AES_BLOCK_LEN - 1] = 2;

	from64 = (const uint64_t*)from;
	to64 = (uint64_t*)to;

	for (i = 0; i < (len - trailer); i += AES_BLOCK_LEN) {
		aes_v8_encrypt(aes_counter, EKi.c, aes_key);
		AES_INC_COUNTER(aes_counter);
		to64[0] = from64[0] ^ EKi.u[0];
		to64[1] = from64[1] ^ EKi.u[1];
		to64 += 2;
		from64 += 2;
	}

	to += (len - trailer);
	from += (len - trailer);

	if (trailer) {
		aes_v8_encrypt(aes_counter, EKi.c, aes_key);
		AES_INC_COUNTER(aes_counter);
		for (i = 0; i < trailer; i++)
			to[i] = from[i] ^ EKi.c[i % AES_BLOCK_LEN];
	}

out:
	explicit_bzero(aes_counter, sizeof(aes_counter));
	explicit_bzero(Xi.c, sizeof(Xi.c));
	explicit_bzero(EK0.c, sizeof(EK0.c));
	explicit_bzero(EKi.c, sizeof(EKi.c));
	explicit_bzero(lenblock.c, sizeof(lenblock.c));

	return (error);
}
