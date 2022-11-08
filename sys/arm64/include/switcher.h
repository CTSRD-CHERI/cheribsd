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

#define	SCB_CALLER_SCB(X)	[X]
#define	SCB_CALLEE_SCB(X)	[X, #1*CHERICAP_SIZE]
#define	SCB_TD(X)		[X, #2*CHERICAP_SIZE]
#define	SCB_BORROWER_TD(X)	[X, #3*CHERICAP_SIZE]
#define	SCB_UNSEALCAP(X)	[X, #4*CHERICAP_SIZE]
#define	SCB_Q8(X)		[X, #5*CHERICAP_SIZE]
#define	SCB_Q9(X)		[X, #6*CHERICAP_SIZE]
#define	SCB_Q10(X)		[X, #7*CHERICAP_SIZE]
#define	SCB_Q11(X)		[X, #8*CHERICAP_SIZE]
#define	SCB_Q12(X)		[X, #9*CHERICAP_SIZE]
#define	SCB_Q13(X)		[X, #10*CHERICAP_SIZE]
#define	SCB_Q14(X)		[X, #11*CHERICAP_SIZE]
#define	SCB_Q15(X)		[X, #12*CHERICAP_SIZE]
#define	SCB_CSP(X)		[X, #13*CHERICAP_SIZE]
#define	SCB_CRA(X)		[X, #14*CHERICAP_SIZE]
#define	SCB_OUTBUF(X)		[X, #15*CHERICAP_SIZE]
#define	SCB_OUTLEN(X)		[X, #16*CHERICAP_SIZE]
#define	SCB_INBUF(X)		[X, #17*CHERICAP_SIZE]
#define	SCB_INLEN(X)		[X, #18*CHERICAP_SIZE]
#define	SCB_COOKIEP(X)		[X, #19*CHERICAP_SIZE]
#define	SCB_C19(X)		[X, #20*CHERICAP_SIZE]
#define	SCB_C20(X)		[X, #21*CHERICAP_SIZE]
#define	SCB_C21(X)		[X, #22*CHERICAP_SIZE]
#define	SCB_C22(X)		[X, #23*CHERICAP_SIZE]
#define	SCB_C23(X)		[X, #24*CHERICAP_SIZE]
#define	SCB_C24(X)		[X, #25*CHERICAP_SIZE]
#define	SCB_C25(X)		[X, #26*CHERICAP_SIZE]
#define	SCB_C26(X)		[X, #27*CHERICAP_SIZE]
#define	SCB_C27(X)		[X, #28*CHERICAP_SIZE]
#define	SCB_C28(X)		[X, #29*CHERICAP_SIZE]
#define	SCB_TLS(X)		[X, #30*CHERICAP_SIZE]
#define	SCB_FPCR(X)		[X, #31*CHERICAP_SIZE]
#define	SCB_FPSR(X)		[X, #32*CHERICAP_SIZE]

#endif /* !_MACHINE_SWITCHER_H_ */
