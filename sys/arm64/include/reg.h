/*-
 * Copyright (c) 2014 Andrew Turner
 * Copyright (c) 2014-2015 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Andrew Turner under
 * sponsorship from the FreeBSD Foundation.
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

#ifndef	_MACHINE_REG_H_
#define	_MACHINE_REG_H_

#include <sys/_types.h>

struct reg {
	__uint64_t x[30];
	__uint64_t lr;
	__uint64_t sp;
	__uint64_t elr;
	__uint32_t spsr;
};

struct reg32 {
	unsigned int r[13];
	unsigned int r_sp;
	unsigned int r_lr;
	unsigned int r_pc;
	unsigned int r_cpsr;
};

struct fpreg {
	__uint128_t	fp_q[32];
	__uint32_t	fp_sr;
	__uint32_t	fp_cr;
};

struct fpreg32 {
	int dummy;
};

struct dbreg {
	__uint8_t	db_debug_ver;
	__uint8_t	db_nbkpts;
	__uint8_t	db_nwtpts;
	__uint8_t	db_pad[5];

	struct {
		__uint64_t dbr_addr;
		__uint32_t dbr_ctrl;
		__uint32_t dbr_pad;
	} db_breakregs[16];
	struct {
		__uint64_t dbw_addr;
		__uint32_t dbw_ctrl;
		__uint32_t dbw_pad;
	} db_watchregs[16];
};

struct dbreg32 {
	int dummy;
};

struct arm64_addr_mask {
	__uint64_t	code;
	__uint64_t	data;
};

#if __has_feature(capabilities)
struct capreg {
	__uintcap_t c[30];
	__uintcap_t clr;
	__uintcap_t csp;
	__uintcap_t celr;
	__uintcap_t ddc;
	__uintcap_t ctpidr;
	__uintcap_t ctpidrro;
	__uintcap_t cid;
	__uintcap_t rcsp;
	__uintcap_t rddc;
	__uintcap_t rctpidr;
	__uint64_t tagmask;
	__uint64_t pad;
};
#endif

#define	__HAVE_REG32

#endif /* !_MACHINE_REG_H_ */
