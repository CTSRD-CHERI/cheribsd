/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012 Oleksandr Tymoshenko
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 * 
 */

#ifndef	__MIPS_TLS_H__
#define	__MIPS_TLS_H__

/*
 * TLS parameters
 */

#define TLS_TP_OFFSET	0x7000
#define TLS_DTP_OFFSET	0x8000


/* XXX-AR: #define TLS_TCB_SIZE	(2 * sizeof(void*)) for all ABIs? */
#ifdef __CHERI_PURE_CAPABILITY__
#define TLS_TCB_SIZE	(2 * CHERICAP_SIZE)
#elif defined(__mips_n64)
#if __has_feature(capabilities)
#define	TLS_TCB_SIZE	(2*sizeof(struct chericap))
#else /* ! feature(capabilities) */
#define TLS_TCB_SIZE	16
#endif /* ! feature(capabilities) */
#ifdef COMPAT_FREEBSD32
#define TLS_TCB_SIZE32	8
#endif
#if __has_feature(capabilities)
#define	TLS_TCB_SIZE_C	(2*sizeof(struct chericap))
#endif
#else /* ! __mips_n64 */
#define TLS_TCB_SIZE	8
#endif /* ! __mips_n64 */

#endif	/* __MIPS_TLS_H__ */
// CHERI CHANGES START
// {
//   "updated": 20180629,
//   "target_type": "header",
//   "changes": [
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
