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

#include <machine/riscvreg.h>

#if !defined(__riscv_y)
#define	TRAPNO_LOAD_STORE	(SCAUSE_CHERI)
#define	TRAPNO_LOAD		(SCAUSE_CHERI)
#define	TRAPNO_STORE		(SCAUSE_CHERI)
#else
#define	TRAPNO_LOAD		(SCAUSE_CHERI_LOAD_ACCESS_FAULT)
#define	TRAPNO_STORE		(SCAUSE_CHERI_STORE_AMO_ACCESS_FAULT)
#endif
#ifdef __riscv_zcheripurecap
#define	TRAPNO_STORE_CAP_PF	(SCAUSE_STORE_PAGE_FAULT)
#else
#define	TRAPNO_STORE_CAP_PF	(SCAUSE_CHERI_STORE_AMO_PAGE_FAULT)
#endif
#define	TRAPNO_LOAD_PF		(SCAUSE_LOAD_PAGE_FAULT)
#define	TRAPNO_STORE_PF		(SCAUSE_STORE_PAGE_FAULT)
#define	TRAPNO_EXEC_PF		(SCAUSE_INST_PAGE_FAULT)

#if !defined(__riscv_y)
#define	SI_CODE_CHERI_BOUNDS	PROT_CHERI_BOUNDS
#define	SI_CODE_CHERI_TAG	PROT_CHERI_TAG
#define	SI_CODE_CHERI_PERM	PROT_CHERI_PERM
#else
/*
 * XXX-AM: RVY can't distinguish cheri exception types.
 * These will all become a single si_code under SIGSEGV in the
 * future.
 */
#define	SI_CODE_CHERI_BOUNDS	PROT_CHERI_BOUNDS
#define	SI_CODE_CHERI_TAG	PROT_CHERI_BOUNDS
#define	SI_CODE_CHERI_PERM	PROT_CHERI_BOUNDS
#endif

#define	CHERI_SEAL_VIOLATION_EXCEPTION	1

#if defined(__CHERI_PURE_CAPABILITY__) && !defined(__riscv_zcheripurecap)
#define	XFAIL_VARARG_BOUNDS	"varargs bounds known to be unimplemented"
#endif

#ifdef __CHERI_TGOT_TLS__
#define	TLS_EXACT_BOUNDS
#endif

/* Supported architecture permission bits feature flags */
#ifdef __riscv_xcheri
#define	HAS_CHERI_PERM_LOAD_STORE_CAP
#define	HAS_CHERI_PERM_SEAL

#define PERM_RESERVED0_MASK ((register_t)0)
#define PERM_RESERVED1_MASK ((register_t)0)
#else
#define	HAS_CHERI_PERM_CAP
#define	HAS_CHERI_PERM_LOAD_MUTABLE

/* [XLEN - 1:34] reserved0 */
#define PERM_RESERVED0_MASK ~(((register_t)1 << 24) - 1)
/* [23:19] [15:9] reserved1, bits [4:2] are checked for Zylevels1b */
#define PERM_RESERVED1_MASK (((register_t)0x1f << 19) | ((register_t)0x3f << 10))
#endif

#define	CAPREG_PCC(capreg)	((capreg)->sepcc)

#endif /* !_CHERIBSDTEST_MD_H_ */
