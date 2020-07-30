/*	$FreeBSD$	*/
/*	$OpenBSD: xform.h,v 1.8 2001/08/28 12:20:43 ben Exp $	*/

/*-
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 * Copyright (c) 2014 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by John-Mark Gurney
 * under sponsorship of the FreeBSD Foundation and
 * Rubicon Communications, LLC (Netgate).
 *
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software. 
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#ifndef _CRYPTO_XFORM_ENC_H_
#define _CRYPTO_XFORM_ENC_H_

#include <sys/malloc.h>
#include <sys/errno.h>
#include <crypto/rijndael/rijndael.h>
#include <crypto/camellia/camellia.h>
#include <opencrypto/cryptodev.h>
#ifdef _STANDALONE
#include <stand.h>
#endif

#define AESICM_BLOCKSIZE	AES_BLOCK_LEN
#define	AES_XTS_BLOCKSIZE	16
#define	AES_XTS_IVSIZE		8
#define	AES_XTS_ALPHA		0x87	/* GF(2^128) generator polynomial */

/* Declarations */
struct enc_xform {
	int type;
	char *name;
	size_t ctxsize;
	u_int16_t blocksize;	/* Required input block size -- 1 for stream ciphers. */
	uint16_t native_blocksize;	/* Used for stream ciphers. */
	u_int16_t ivsize;
	u_int16_t minkey, maxkey;

	/*
	 * Encrypt/decrypt a single block.  For stream ciphers this
	 * encrypts/decrypts a single "native" block.
	 */
	void (*encrypt) (void *, const uint8_t *, uint8_t *);
	void (*decrypt) (void *, const uint8_t *, uint8_t *);
	int (*setkey) (void *, const uint8_t *, int len);
	void (*reinit) (void *, const u_int8_t *);

	/*
	 * For stream ciphers, encrypt/decrypt the final partial block
	 * of 'len' bytes.
	 */
	void (*encrypt_last) (void *, const uint8_t *, uint8_t *, size_t len);
	void (*decrypt_last) (void *, const uint8_t *, uint8_t *, size_t len);
};


extern struct enc_xform enc_xform_null;
extern struct enc_xform enc_xform_rijndael128;
extern struct enc_xform enc_xform_aes_icm;
extern struct enc_xform enc_xform_aes_nist_gcm;
extern struct enc_xform enc_xform_aes_nist_gmac;
extern struct enc_xform enc_xform_aes_xts;
extern struct enc_xform enc_xform_camellia;
extern struct enc_xform enc_xform_chacha20;
extern struct enc_xform enc_xform_ccm;

struct aes_icm_ctx {
	u_int32_t	ac_ek[4*(RIJNDAEL_MAXNR + 1)];
	/* ac_block is initialized to IV */
	u_int8_t	ac_block[AESICM_BLOCKSIZE];
	int		ac_nr;
};

struct aes_xts_ctx {
	rijndael_ctx key1;
	rijndael_ctx key2;
	u_int8_t tweak[AES_XTS_BLOCKSIZE];
};

#endif /* _CRYPTO_XFORM_ENC_H_ */
