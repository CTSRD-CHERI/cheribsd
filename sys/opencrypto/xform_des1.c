/*	$OpenBSD: xform.c,v 1.16 2001/08/28 12:20:43 ben Exp $	*/
/*-
 * The authors of this code are John Ioannidis (ji@tla.org),
 * Angelos D. Keromytis (kermit@csd.uch.gr),
 * Niels Provos (provos@physnet.uni-hamburg.de) and
 * Damien Miller (djm@mindrot.org).
 *
 * This code was written by John Ioannidis for BSD/OS in Athens, Greece,
 * in November 1995.
 *
 * Ported to OpenBSD and NetBSD, with additional transforms, in December 1996,
 * by Angelos D. Keromytis.
 *
 * Additional transforms and features in 1997 and 1998 by Angelos D. Keromytis
 * and Niels Provos.
 *
 * Additional features in 1999 by Angelos D. Keromytis.
 *
 * AES XTS implementation in 2008 by Damien Miller
 *
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 by John Ioannidis,
 * Angelos D. Keromytis and Niels Provos.
 *
 * Copyright (C) 2001, Angelos D. Keromytis.
 *
 * Copyright (C) 2008, Damien Miller
 * Copyright (c) 2014 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by John-Mark Gurney
 * under sponsorship of the FreeBSD Foundation and
 * Rubicon Communications, LLC (Netgate).
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software.
 * You may use this code under the GNU public license if you so wish. Please
 * contribute changes back to the authors under this freer than GPL license
 * so that we may further the use of strong encryption without limitations to
 * all.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <crypto/des/des.h>
#include <opencrypto/xform_enc.h>

static	int des1_setkey(u_int8_t **, const u_int8_t *, int);
static	void des1_encrypt(caddr_t, u_int8_t *);
static	void des1_decrypt(caddr_t, u_int8_t *);
static	void des1_zerokey(u_int8_t **);

/* Encryption instances */
struct enc_xform enc_xform_des = {
	CRYPTO_DES_CBC, "DES",
	DES_BLOCK_LEN, DES_BLOCK_LEN, DES_MIN_KEY, DES_MAX_KEY,
	des1_encrypt,
	des1_decrypt,
	des1_setkey,
	des1_zerokey,
	NULL,
};

/*
 * Encryption wrapper routines.
 */
static void
des1_encrypt(caddr_t key, u_int8_t *blk)
{
	des_key_schedule *p = (des_key_schedule *) key;

	des_ecb_encrypt(blk, blk, p[0], DES_ENCRYPT);
}

static void
des1_decrypt(caddr_t key, u_int8_t *blk)
{
	des_key_schedule *p = (des_key_schedule *) key;

	des_ecb_encrypt(blk, blk, p[0], DES_DECRYPT);
}

static int
des1_setkey(u_int8_t **sched, const u_int8_t *key, int len)
{
	des_key_schedule *p;
	int err;

	p = KMALLOC(sizeof (des_key_schedule),
		M_CRYPTO_DATA, M_NOWAIT|M_ZERO);
	if (p != NULL) {
		des_set_key(key, p[0]);
		err = 0;
	} else
		err = ENOMEM;
	*sched = (u_int8_t *) p;
	return err;
}

static void
des1_zerokey(u_int8_t **sched)
{
	bzero(*sched, sizeof (des_key_schedule));
	KFREE(*sched, M_CRYPTO_DATA);
	*sched = NULL;
}
