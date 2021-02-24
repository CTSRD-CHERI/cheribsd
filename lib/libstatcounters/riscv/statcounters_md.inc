/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2020 Alex Richardson <arichardson@FreeBSD.org>
 * Copyright 2021 Alexandre Joannou
 *
 * This work was supported by Innovate UK project 105694, "Digital Security by
 * Design (DSbD) Technology Platform Prototype".
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#ifndef STATCOUNTER_ITEM
#error Must define STATCOUNTER_ITEM(name, field, args) when including this file.
#endif

#ifndef RISCV_STATCOUNTER
#define RISCV_STATCOUNTER(csr) STATCOUNTER_ITEM(csr, csr, csr)
#endif

STATCOUNTER_ITEM(cycles, cycles, cycle)
STATCOUNTER_ITEM(instructions, instructions, instret)
RISCV_STATCOUNTER(time)
/*
 * XXX THIS CURRENTLY HAS TO MATCH THE STATIC ALLOCATION IN RISCV-PK
 *     see hpm_init() in riscv-pk/machine/minit.c
 */
STATCOUNTER_ITEM(redirect, redirect, hpmcounter3)
STATCOUNTER_ITEM(branch, branch, hpmcounter4)
STATCOUNTER_ITEM(jal, jal, hpmcounter5)
STATCOUNTER_ITEM(jalr, jalr, hpmcounter6)
STATCOUNTER_ITEM(trap, trap, hpmcounter7)
STATCOUNTER_ITEM(load_wait, load_wait, hpmcounter8)
STATCOUNTER_ITEM(cap_load_tag_set, cap_load_tag_set, hpmcounter9)
STATCOUNTER_ITEM(cap_store_tag_set, cap_store_tag_set, hpmcounter10)
STATCOUNTER_ITEM(itlb_miss_wait, itlb_miss_wait, hpmcounter11)
STATCOUNTER_ITEM(icache_load, icache_load, hpmcounter12)
STATCOUNTER_ITEM(icache_load_miss, icache_load_miss, hpmcounter13)
STATCOUNTER_ITEM(icache_load_miss_wait, icache_load_miss_wait, hpmcounter14)
STATCOUNTER_ITEM(dtlb_access, dtlb_access, hpmcounter15)
STATCOUNTER_ITEM(dtlb_miss, dtlb_miss, hpmcounter16)
STATCOUNTER_ITEM(dtlb_miss_wait, dtlb_miss_wait, hpmcounter17)
STATCOUNTER_ITEM(dcache_load, dcache_load, hpmcounter18)
STATCOUNTER_ITEM(dcache_load_miss, dcache_load_miss, hpmcounter19)
STATCOUNTER_ITEM(dcache_load_miss_wait, dcache_load_miss_wait, hpmcounter20)
STATCOUNTER_ITEM(dcache_store, dcache_store, hpmcounter21)
STATCOUNTER_ITEM(dcache_store_miss, dcache_store_miss, hpmcounter22)
STATCOUNTER_ITEM(llcache_load_miss, llcache_load_miss, hpmcounter23)
STATCOUNTER_ITEM(llcache_load_miss_wait, llcache_load_miss_wait, hpmcounter24)
STATCOUNTER_ITEM(tagcache_load, tagcache_load, hpmcounter25)
STATCOUNTER_ITEM(tagcache_load_miss, tagcache_load_miss, hpmcounter26)
STATCOUNTER_ITEM(tagcache_store, tagcache_store, hpmcounter27)
STATCOUNTER_ITEM(tagcache_store_miss, tagcache_store_miss, hpmcounter28)
STATCOUNTER_ITEM(tagcache_evict, tagcache_evict, hpmcounter29)

#undef RISCV_STATCOUNTER
#undef STATCOUNTER_ITEM
