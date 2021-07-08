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
#define RISCV_STATCOUNTER(name, csr) STATCOUNTER_ITEM(name, name, csr)
#endif

#ifndef STATCOUNTERS_GROUP_END
#define STATCOUNTERS_GROUP_END()
#endif

RISCV_STATCOUNTER(cycles, cycle)
RISCV_STATCOUNTER(instructions, instret)
RISCV_STATCOUNTER(time, time)
STATCOUNTERS_GROUP_END()
/*
 * XXX THIS CURRENTLY HAS TO MATCH THE STATIC ALLOCATION IN RISCV-PK
 * (see hpm_init() in riscv-pk/machine/minit.c)
 */
RISCV_STATCOUNTER(redirect, hpmcounter3)
RISCV_STATCOUNTER(branch, hpmcounter4)
RISCV_STATCOUNTER(jal, hpmcounter5)
RISCV_STATCOUNTER(jalr, hpmcounter6)
RISCV_STATCOUNTER(trap, hpmcounter7)
STATCOUNTERS_GROUP_END()
RISCV_STATCOUNTER(load_wait, hpmcounter8)
RISCV_STATCOUNTER(cap_load_tag_set, hpmcounter9)
RISCV_STATCOUNTER(cap_store_tag_set, hpmcounter10)
STATCOUNTERS_GROUP_END()
RISCV_STATCOUNTER(itlb_miss, hpmcounter11)
RISCV_STATCOUNTER(icache_load, hpmcounter12)
RISCV_STATCOUNTER(icache_load_miss, hpmcounter13)
RISCV_STATCOUNTER(icache_load_miss_wait, hpmcounter14)
STATCOUNTERS_GROUP_END()
RISCV_STATCOUNTER(dtlb_access, hpmcounter15)
RISCV_STATCOUNTER(dtlb_miss, hpmcounter16)
RISCV_STATCOUNTER(dtlb_miss_wait, hpmcounter17)
RISCV_STATCOUNTER(dcache_load, hpmcounter18)
RISCV_STATCOUNTER(dcache_load_miss, hpmcounter19)
RISCV_STATCOUNTER(dcache_load_miss_wait, hpmcounter20)
RISCV_STATCOUNTER(dcache_store, hpmcounter21)
RISCV_STATCOUNTER(dcache_store_miss, hpmcounter22)
STATCOUNTERS_GROUP_END()
RISCV_STATCOUNTER(llcache_load_miss, hpmcounter23)
RISCV_STATCOUNTER(llcache_load_miss_wait, hpmcounter24)
STATCOUNTERS_GROUP_END()
RISCV_STATCOUNTER(tagcache_load, hpmcounter25)
RISCV_STATCOUNTER(tagcache_load_miss, hpmcounter26)
RISCV_STATCOUNTER(tagcache_store, hpmcounter27)
RISCV_STATCOUNTER(tagcache_store_miss, hpmcounter28)
RISCV_STATCOUNTER(tagcache_evict, hpmcounter29)

#undef RISCV_STATCOUNTER
#undef STATCOUNTER_ITEM
#undef STATCOUNTERS_GROUP_END
