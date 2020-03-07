/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2014-2019 Netflix Inc.
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
 *
 * $FreeBSD$
 */
#ifndef _SYS_KTLS_H_
#define	_SYS_KTLS_H_

#include <sys/refcount.h>
#include <sys/_task.h>

struct tls_record_layer {
	uint8_t  tls_type;
	uint8_t  tls_vmajor;
	uint8_t  tls_vminor;
	uint16_t tls_length;
	uint8_t  tls_data[0];
} __attribute__ ((packed));

#define	TLS_MAX_MSG_SIZE_V10_2	16384
#define	TLS_MAX_PARAM_SIZE	1024	/* Max key/mac/iv in sockopt */
#define	TLS_AEAD_GCM_LEN	4
#define	TLS_1_3_GCM_IV_LEN	12
#define	TLS_CBC_IMPLICIT_IV_LEN	16

/* Type values for the record layer */
#define	TLS_RLTYPE_APP		23

/*
 * Nonce for GCM for TLS 1.2 per RFC 5288.
 */
struct tls_nonce_data {
	uint8_t fixed[TLS_AEAD_GCM_LEN];
	uint64_t seq;
} __packed; 

/*
 * AEAD additional data format for TLS 1.2 per RFC 5246.
 */
struct tls_aead_data {
	uint64_t seq;	/* In network order */
	uint8_t	type;
	uint8_t tls_vmajor;
	uint8_t tls_vminor;
	uint16_t tls_length;	
} __packed;

/*
 * AEAD additional data format for TLS 1.3 per RFC 8446.
 */
struct tls_aead_data_13 {
	uint8_t	type;
	uint8_t tls_vmajor;
	uint8_t tls_vminor;
	uint16_t tls_length;
} __packed;

/*
 * Stream Cipher MAC additional data input.  This does not match the
 * exact data on the wire (the sequence number is not placed on the
 * wire, and any explicit IV after the record header is not covered by
 * the MAC).
 */
struct tls_mac_data {
	uint64_t seq;
	uint8_t type;
	uint8_t tls_vmajor;
	uint8_t tls_vminor;
	uint16_t tls_length;	
} __packed;

#define	TLS_MAJOR_VER_ONE	3
#define	TLS_MINOR_VER_ZERO	1	/* 3, 1 */
#define	TLS_MINOR_VER_ONE	2	/* 3, 2 */
#define	TLS_MINOR_VER_TWO	3	/* 3, 3 */
#define	TLS_MINOR_VER_THREE	4	/* 3, 4 */

/* For TCP_TXTLS_ENABLE */
struct tls_enable {
	const uint8_t *cipher_key;
	const uint8_t *iv;		/* Implicit IV. */
	const uint8_t *auth_key;
	int	cipher_algorithm;	/* e.g. CRYPTO_AES_CBC */
	int	cipher_key_len;
	int	iv_len;
	int	auth_algorithm;		/* e.g. CRYPTO_SHA2_256_HMAC */
	int	auth_key_len;
	int	flags;
	uint8_t tls_vmajor;
	uint8_t tls_vminor;
};

struct tls_session_params {
	uint8_t *cipher_key;
	uint8_t *auth_key;
	uint8_t iv[TLS_CBC_IMPLICIT_IV_LEN];
	int	cipher_algorithm;
	int	auth_algorithm;
	uint16_t cipher_key_len;
	uint16_t iv_len;
	uint16_t auth_key_len;
	uint16_t max_frame_len;
	uint8_t tls_vmajor;
	uint8_t tls_vminor;
	uint8_t tls_hlen;
	uint8_t tls_tlen;
	uint8_t tls_bs;
	uint8_t flags;
};

#ifdef _KERNEL

#define	KTLS_API_VERSION 6

struct iovec;
struct ktls_session;
struct m_snd_tag;
struct mbuf;
struct mbuf_ext_pgs;
struct sockbuf;
struct socket;

struct ktls_crypto_backend {
	LIST_ENTRY(ktls_crypto_backend) next;
	int (*try)(struct socket *so, struct ktls_session *tls);
	int prio;
	int api_version;
	int use_count;
	const char *name;
};

struct ktls_session {
	int	(*sw_encrypt)(struct ktls_session *tls,
	    const struct tls_record_layer *hdr, uint8_t *trailer,
	    struct iovec *src, struct iovec *dst, int iovcnt,
	    uint64_t seqno, uint8_t record_type);
	union {
		void *cipher;
		struct m_snd_tag *snd_tag;
	};
	struct ktls_crypto_backend *be;
	void (*free)(struct ktls_session *tls);
	struct tls_session_params params;
	u_int	wq_index;
	volatile u_int refcount;
	int mode;

	struct task reset_tag_task;
	struct inpcb *inp;
	bool reset_pending;
} __aligned(CACHE_LINE_SIZE);

int ktls_crypto_backend_register(struct ktls_crypto_backend *be);
int ktls_crypto_backend_deregister(struct ktls_crypto_backend *be);
int ktls_enable_tx(struct socket *so, struct tls_enable *en);
void ktls_destroy(struct ktls_session *tls);
void ktls_frame(struct mbuf *m, struct ktls_session *tls, int *enqueue_cnt,
    uint8_t record_type);
void ktls_seq(struct sockbuf *sb, struct mbuf *m);
void ktls_enqueue(struct mbuf *m, struct socket *so, int page_count);
void ktls_enqueue_to_free(struct mbuf_ext_pgs *pgs);
int ktls_set_tx_mode(struct socket *so, int mode);
int ktls_get_tx_mode(struct socket *so);
int ktls_output_eagain(struct inpcb *inp, struct ktls_session *tls);

static inline struct ktls_session *
ktls_hold(struct ktls_session *tls)
{

	if (tls != NULL)
		refcount_acquire(&tls->refcount);
	return (tls);
}

static inline void
ktls_free(struct ktls_session *tls)
{

	if (refcount_release(&tls->refcount))
		ktls_destroy(tls);
}

#endif /* !_KERNEL */
#endif /* !_SYS_KTLS_H_ */
