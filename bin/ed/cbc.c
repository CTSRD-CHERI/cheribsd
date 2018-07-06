/* cbc.c: This file contains the encryption routines for the ed line editor */
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Copyright (c) 1993 Andrew Moore, Talke Studio.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#ifdef DES
#include <time.h>
#include <openssl/des.h>
#define ED_DES_INCLUDES
#endif

#include "ed.h"


/*
 * BSD and System V systems offer special library calls that do
 * block move_liness and fills, so if possible we take advantage of them
 */
#define	MEMCPY(dest,src,len)	memcpy((dest),(src),(len))
#define	MEMZERO(dest,len)	memset((dest), 0, (len))

/* Hide the calls to the primitive encryption routines. */
#define	DES_XFORM(buf)							\
		DES_ecb_encrypt(buf, buf, &schedule, 			\
		    inverse ? DES_DECRYPT : DES_ENCRYPT);

/*
 * read/write - no error checking
 */
#define	READ(buf, n, fp)	fread(buf, sizeof(char), n, fp)
#define WRITE(buf, n, fp)	fwrite(buf, sizeof(char), n, fp)

/*
 * global variables and related macros
 */

#ifdef DES
static DES_cblock ivec;			/* initialization vector */
static DES_cblock pvec;			/* padding vector */

static char bits[] = {			/* used to extract bits from a char */
	'\200', '\100', '\040', '\020', '\010', '\004', '\002', '\001'
};

static int pflag;			/* 1 to preserve parity bits */

static DES_key_schedule schedule;	/* expanded DES key */

static unsigned char des_buf[8];/* shared buffer for get_des_char/put_des_char */
static int des_ct = 0;		/* count for get_des_char/put_des_char */
static int des_n = 0;		/* index for put_des_char/get_des_char */
#endif

/* init_des_cipher: initialize DES */
void
init_des_cipher(void)
{
#ifdef DES
	des_ct = des_n = 0;

	/* initialize the initialization vector */
	MEMZERO(ivec, 8);

	/* initialize the padding vector */
	arc4random_buf(pvec, sizeof(pvec));
#endif
}


/* get_des_char: return next char in an encrypted file */
int
get_des_char(FILE *fp)
{
#ifdef DES
	if (des_n >= des_ct) {
		des_n = 0;
		des_ct = cbc_decode(des_buf, fp);
	}
	return (des_ct > 0) ? des_buf[des_n++] : EOF;
#else
	return (getc(fp));
#endif
}


/* put_des_char: write a char to an encrypted file; return char written */
int
put_des_char(int c, FILE *fp)
{
#ifdef DES
	if (des_n == sizeof des_buf) {
		des_ct = cbc_encode(des_buf, des_n, fp);
		des_n = 0;
	}
	return (des_ct >= 0) ? (des_buf[des_n++] = c) : EOF;
#else
	return (fputc(c, fp));
#endif
}


/* flush_des_file: flush an encrypted file's output; return status */
int
flush_des_file(FILE *fp)
{
#ifdef DES
	if (des_n == sizeof des_buf) {
		des_ct = cbc_encode(des_buf, des_n, fp);
		des_n = 0;
	}
	return (des_ct >= 0 && cbc_encode(des_buf, des_n, fp) >= 0) ? 0 : EOF;
#else
	return (fflush(fp));
#endif
}

#ifdef DES
/*
 * get keyword from tty or stdin
 */
int
get_keyword(void)
{
	char *p;			/* used to obtain the key */
	DES_cblock msgbuf;		/* I/O buffer */

	/*
	 * get the key
	 */
	if ((p = getpass("Enter key: ")) != NULL && *p != '\0') {

		/*
		 * copy it, nul-padded, into the key area
		 */
		expand_des_key(msgbuf, p);
		MEMZERO(p, _PASSWORD_LEN);
		set_des_key(&msgbuf);
		MEMZERO(msgbuf, sizeof msgbuf);
		return 1;
	}
	return 0;
}


/*
 * print a warning message and, possibly, terminate
 */
void
des_error(const char *s)
{
	errmsg = s ? s : strerror(errno);
}

/*
 * map a hex character to an integer
 */
int
hex_to_binary(int c, int radix)
{
	switch(c) {
	case '0':		return(0x0);
	case '1':		return(0x1);
	case '2':		return(radix > 2 ? 0x2 : -1);
	case '3':		return(radix > 3 ? 0x3 : -1);
	case '4':		return(radix > 4 ? 0x4 : -1);
	case '5':		return(radix > 5 ? 0x5 : -1);
	case '6':		return(radix > 6 ? 0x6 : -1);
	case '7':		return(radix > 7 ? 0x7 : -1);
	case '8':		return(radix > 8 ? 0x8 : -1);
	case '9':		return(radix > 9 ? 0x9 : -1);
	case 'A': case 'a':	return(radix > 10 ? 0xa : -1);
	case 'B': case 'b':	return(radix > 11 ? 0xb : -1);
	case 'C': case 'c':	return(radix > 12 ? 0xc : -1);
	case 'D': case 'd':	return(radix > 13 ? 0xd : -1);
	case 'E': case 'e':	return(radix > 14 ? 0xe : -1);
	case 'F': case 'f':	return(radix > 15 ? 0xf : -1);
	}
	/*
	 * invalid character
	 */
	return(-1);
}

/*
 * convert the key to a bit pattern
 *	obuf		bit pattern
 *	kbuf		the key itself
 */
void
expand_des_key(char *obuf, char *kbuf)
{
	int i, j;			/* counter in a for loop */
	int nbuf[64];			/* used for hex/key translation */

	/*
	 * leading '0x' or '0X' == hex key
	 */
	if (kbuf[0] == '0' && (kbuf[1] == 'x' || kbuf[1] == 'X')) {
		kbuf = &kbuf[2];
		/*
		 * now translate it, bombing on any illegal hex digit
		 */
		for (i = 0; i < 16 && kbuf[i]; i++)
			if ((nbuf[i] = hex_to_binary((int) kbuf[i], 16)) == -1)
				des_error("bad hex digit in key");
		while (i < 16)
			nbuf[i++] = 0;
		for (i = 0; i < 8; i++)
			obuf[i] =
			    ((nbuf[2*i]&0xf)<<4) | (nbuf[2*i+1]&0xf);
		/* preserve parity bits */
		pflag = 1;
		return;
	}
	/*
	 * leading '0b' or '0B' == binary key
	 */
	if (kbuf[0] == '0' && (kbuf[1] == 'b' || kbuf[1] == 'B')) {
		kbuf = &kbuf[2];
		/*
		 * now translate it, bombing on any illegal binary digit
		 */
		for (i = 0; i < 16 && kbuf[i]; i++)
			if ((nbuf[i] = hex_to_binary((int) kbuf[i], 2)) == -1)
				des_error("bad binary digit in key");
		while (i < 64)
			nbuf[i++] = 0;
		for (i = 0; i < 8; i++)
			for (j = 0; j < 8; j++)
				obuf[i] = (obuf[i]<<1)|nbuf[8*i+j];
		/* preserve parity bits */
		pflag = 1;
		return;
	}
	/*
	 * no special leader -- ASCII
	 */
	(void)strncpy(obuf, kbuf, 8);
}

/*****************
 * DES FUNCTIONS *
 *****************/
/*
 * This sets the DES key and (if you're using the deszip version)
 * the direction of the transformation.  This uses the Sun
 * to map the 64-bit key onto the 56 bits that the key schedule
 * generation routines use: the old way, which just uses the user-
 * supplied 64 bits as is, and the new way, which resets the parity
 * bit to be the same as the low-order bit in each character.  The
 * new way generates a greater variety of key schedules, since many
 * systems set the parity (high) bit of each character to 0, and the
 * DES ignores the low order bit of each character.
 */
void
set_des_key(DES_cblock *buf)			/* key block */
{
	int i, j;				/* counter in a for loop */
	int par;				/* parity counter */

	/*
	 * if the parity is not preserved, flip it
	 */
	if (!pflag) {
		for (i = 0; i < 8; i++) {
			par = 0;
			for (j = 1; j < 8; j++)
				if ((bits[j] & (*buf)[i]) != 0)
					par++;
			if ((par & 0x01) == 0x01)
				(*buf)[i] &= 0x7f;
			else
				(*buf)[i] = ((*buf)[i] & 0x7f) | 0x80;
		}
	}

	DES_set_odd_parity(buf);
	DES_set_key(buf, &schedule);
}


/*
 * This encrypts using the Cipher Block Chaining mode of DES
 */
int
cbc_encode(unsigned char *msgbuf, int n, FILE *fp)
{
	int inverse = 0;	/* 0 to encrypt, 1 to decrypt */

	/*
	 * do the transformation
	 */
	if (n == 8) {
		for (n = 0; n < 8; n++)
			msgbuf[n] ^= ivec[n];
		DES_XFORM((DES_cblock *)msgbuf);
		MEMCPY(ivec, msgbuf, 8);
		return WRITE(msgbuf, 8, fp);
	}
	/*
	 * at EOF or last block -- in either case, the last byte contains
	 * the character representation of the number of bytes in it
	 */
/*
	MEMZERO(msgbuf +  n, 8 - n);
*/
	/*
	 *  Pad the last block randomly
	 */
	(void)MEMCPY(msgbuf + n, pvec, 8 - n);
	msgbuf[7] = n;
	for (n = 0; n < 8; n++)
		msgbuf[n] ^= ivec[n];
	DES_XFORM((DES_cblock *)msgbuf);
	return WRITE(msgbuf, 8, fp);
}

/*
 * This decrypts using the Cipher Block Chaining mode of DES
 *	msgbuf	I/O buffer
 *	fp	input file descriptor
 */
int
cbc_decode(unsigned char *msgbuf, FILE *fp)
{
	DES_cblock tbuf;	/* temp buffer for initialization vector */
	int n;			/* number of bytes actually read */
	int c;			/* used to test for EOF */
	int inverse = 1;	/* 0 to encrypt, 1 to decrypt */

	if ((n = READ(msgbuf, 8, fp)) == 8) {
		/*
		 * do the transformation
		 */
		MEMCPY(tbuf, msgbuf, 8);
		DES_XFORM((DES_cblock *)msgbuf);
		for (c = 0; c < 8; c++)
			msgbuf[c] ^= ivec[c];
		MEMCPY(ivec, tbuf, 8);
		/*
		 * if the last one, handle it specially
		 */
		if ((c = fgetc(fp)) == EOF) {
			n = msgbuf[7];
			if (n < 0 || n > 7) {
				des_error("decryption failed (block corrupted)");
				return EOF;
			}
		} else
			(void)ungetc(c, fp);
		return n;
	}
	if (n > 0)
		des_error("decryption failed (incomplete block)");
	else if (n < 0)
		des_error("cannot read file");
	return EOF;
}
#endif	/* DES */
