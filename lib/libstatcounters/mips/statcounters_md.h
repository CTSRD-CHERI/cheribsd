/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Alex Richardson
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security by
 * Design (DSbD) Technology Platform Prototype".
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
#pragma once

typedef struct statcounters_bank {
#define STATCOUNTER_ITEM(name, field, args) uint64_t field;
#include "statcounters_md.inc"
} statcounters_bank_t;

/* Note: LLVM rejects certain selectors for RDHWR, so we have to use .word. */
#define STATCOUNTER_RDHWR_TO_REG12(major, minor)		\
	".word (0x1f << 26) | (0x0 << 21) | (12 << 16) | "	\
	"(" #major " << 11) | ( " #minor "  << 6) | 0x3b"
#define STATCOUNTER_ITEM(name, field, args)			\
	static inline uint64_t					\
	statcounters_read_##field(void)				\
	{							\
		uint64_t ret;					\
		asm volatile(STATCOUNTER_RDHWR_TO_REG12 args	\
			"\n\tmove %0, $12" :"=r"(ret)::"$12");	\
		return ret;					\
	}
#include "statcounters_md.inc"

#if __has_feature(capabilities)
#define STATCOUNTERS_ARCH "cheri" __XSTRING(_MIPS_SZCAP)
#if defined(__CHERI_PURE_CAPABILITY__)
/* No suffix for purecap for compatibility with old analysis scripts. */
#define STATCOUNTERS_ABI ""
#else
#define STATCOUNTERS_ABI "-hybrid"
#endif
#else
#define STATCOUNTERS_ARCH "mips"
#if defined(__mips_n64)
#define STATCOUNTERS_ABI "" /* n64 is default case -> no suffix */
#elif defined(__mips_n32)
#define STATCOUNTERS_ABI "-n32"
#else
#error "Unknown MIPS ABI"
#endif
#endif
