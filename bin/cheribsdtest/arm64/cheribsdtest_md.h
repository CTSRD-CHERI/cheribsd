/*-
 * Copyright (c) 2012-2018, 2020 Robert N. M. Watson
 * Copyright (c) 2014-2016,2020 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#ifndef _CHERIBSDTEST_MD_H_
#define	_CHERIBSDTEST_MD_H_

#include <machine/armreg.h>

#define	TRAPNO_STORE_CAP_PF	EXCP_DATA_ABORT_L
#define	TRAPNO_LOAD_STORE	EXCP_DATA_ABORT_L

#define	CHERI_SEAL_VIOLATION_EXCEPTION	0

#define	SI_CODE_STORELOCAL	PROT_CHERI_PERM

#ifndef __CHERI_PURE_CAPABILITY__
/* The Morello compiler currently sets bounds on globals. */
#define	XFAIL_HYBRID_BOUNDS_GLOBALS	NULL
#define	XFAIL_HYBRID_BOUNDS_GLOBALS_STATIC	NULL
#define	XFAIL_HYBRID_BOUNDS_GLOBALS_EXTERN	NULL
#endif

#ifdef __CHERI_PURE_CAPABILITY__
#define	TLS_EXACT_BOUNDS
#endif

#endif /* !_CHERIBSDTEST_H_ */
