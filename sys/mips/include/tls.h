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

#if defined(__CHERI_PURE_CAPABILITY__) || \
    (defined(_KERNEL) && __has_feature(capabilities))
#define TLS_TP_OFFSET	0
#define TLS_DTP_OFFSET	0
#else
#define TLS_TP_OFFSET	0x7000
#define TLS_DTP_OFFSET	0x8000
#endif
#ifdef COMPAT_FREEBSD32
#define TLS_TP_OFFSET32	0x7000
#endif
#ifdef COMPAT_FREEBSD64
#define TLS_TP_OFFSET64	0x7000
#endif
#ifdef COMPAT_CHERIABI
#define	TLS_TP_OFFSET_C	0
#endif

#define	TLS_TCB_SIZE	(2 * sizeof(void * __kerncap))
#ifdef COMPAT_FREEBSD32
#define TLS_TCB_SIZE32	8
#endif
#ifdef COMPAT_FREEBSD64
#define	TLS_TCB_SIZE64	16
#endif
#ifdef COMPAT_CHERIABI
#define	TLS_TCB_SIZE_C	(2 * __SIZEOF_CHERI_CAPABILITY__)
#endif

#endif	/* __MIPS_TLS_H__ */
// CHERI CHANGES START
// {
//   "updated": 20181114,
//   "target_type": "header",
//   "changes": [
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
