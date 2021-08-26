/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2020 Alex Richardson <arichardson@FreeBSD.org>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security by
 * Design (DSbD) Technology Platform Prototype".
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#pragma once

typedef struct statcounters_bank {
#define STATCOUNTER_ITEM(name, field, args) uint64_t field;
#include "statcounters_md.inc"
} statcounters_bank_t;

/* This header also exposes statcounters_get_cycle_count(), etc. functions */
#define STATCOUNTER_ITEM(name, field, args)			\
	static inline uint64_t					\
	statcounters_read_##field(void)				\
	{							\
		uint64_t ret;					\
		asm volatile("csrr %0, " #args : "=r"(ret));	\
		return ret;					\
	}
#include "statcounters_md.inc"

#define STATCOUNTERS_ARCH "riscv" __XSTRING(__riscv_xlen)

#if __has_feature(capabilities)
#if defined(__CHERI_PURE_CAPABILITY__)
#define STATCOUNTERS_ABI "-purecap"
#else
#define STATCOUNTERS_ABI "-hybrid"
#endif
#else
#define STATCOUNTERS_ABI ""
#endif
