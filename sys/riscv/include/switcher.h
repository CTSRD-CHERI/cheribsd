/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 *
 * $FreeBSD$
 */

#ifndef _MACHINE_SWITCHER_H_
#define _MACHINE_SWITCHER_H_

#define	SCB_CALLER_SCB(X)	0(X)
#define	SCB_CALLEE_SCB(X)	1*CHERICAP_SIZE(X)
#define	SCB_TD(X)		2*CHERICAP_SIZE(X)
#define	SCB_BORROWER_TD(X)	3*CHERICAP_SIZE(X)
#define	SCB_UNSEALCAP(X)	4*CHERICAP_SIZE(X)
#define	SCB_CSP(X)		5*CHERICAP_SIZE(X)
#define	SCB_CRA(X)		6*CHERICAP_SIZE(X)
#define	SCB_OUTBUF(X)		7*CHERICAP_SIZE(X)
#define	SCB_OUTLEN(X)		8*CHERICAP_SIZE(X)
#define	SCB_INBUF(X)		9*CHERICAP_SIZE(X)
#define	SCB_INLEN(X)		10*CHERICAP_SIZE(X)
#define	SCB_COOKIEP(X)		11*CHERICAP_SIZE(X)

#endif /* !_MACHINE_SWITCHER_H_ */
