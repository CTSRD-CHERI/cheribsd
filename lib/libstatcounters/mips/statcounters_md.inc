/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016-2017 Alexandre Joannou
 * Copyright (c) 2019 Alex Richardson
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
#ifndef STATCOUNTER_ITEM
#error Must define STATCOUNTER_ITEM(name, field, args) when including this file.
#endif

#ifndef MIPS_STATCOUNTER
#define MIPS_STATCOUNTER(name, major, minor) \
	STATCOUNTER_ITEM(name, name, (major, minor))
#endif

#ifndef STATCOUNTERS_GROUP_END
#define STATCOUNTERS_GROUP_END()
#endif

/*
 * This list is derived from the BERI Hardware reference (SVN snapshot)
 * Table 8.4: "List of available STATCOUNTERS counters".
 * Note: Not included in the latest released version (UCAM-CL-TR-868.pdf).
 * The counters inst_user,inst_kernel,imprecise_setbounds,unrepresentable_caps
 * are not listed in that table but are available in CHERI-MIPS QEMU.
 */
STATCOUNTER_ITEM(cycles, cycles, (2, 0))
STATCOUNTER_ITEM(instructions, instructions, (4, 0))
STATCOUNTER_ITEM(instructions(user), inst_user, (4, 1))
STATCOUNTER_ITEM(instructions(kernel), inst_kernel, (4, 2))
MIPS_STATCOUNTER(itlb_miss, 5, 0)
MIPS_STATCOUNTER(dtlb_miss, 6, 0)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(icache_write_hit, 8, 0)
MIPS_STATCOUNTER(icache_write_miss, 8, 1)
MIPS_STATCOUNTER(icache_read_hit, 8, 2)
MIPS_STATCOUNTER(icache_read_miss, 8, 3)
MIPS_STATCOUNTER(icache_evict, 8, 6)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(dcache_write_hit, 9, 0)
MIPS_STATCOUNTER(dcache_write_miss, 9, 1)
MIPS_STATCOUNTER(dcache_read_hit, 9, 2)
MIPS_STATCOUNTER(dcache_read_miss, 9, 3)
MIPS_STATCOUNTER(dcache_evict, 9, 6)
MIPS_STATCOUNTER(dcache_set_tag_write, 9, 8)
MIPS_STATCOUNTER(dcache_set_tag_read, 9, 9)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(l2cache_write_hit, 10, 0)
MIPS_STATCOUNTER(l2cache_write_miss, 10, 1)
MIPS_STATCOUNTER(l2cache_read_hit, 10, 2)
MIPS_STATCOUNTER(l2cache_read_miss, 10, 3)
MIPS_STATCOUNTER(l2cache_evict, 10, 6)
MIPS_STATCOUNTER(l2cache_set_tag_write, 10, 8)
MIPS_STATCOUNTER(l2cache_set_tag_read, 10, 9)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(mem_byte_read, 11, 0)
MIPS_STATCOUNTER(mem_byte_write, 11, 1)
MIPS_STATCOUNTER(mem_hword_read, 11, 2)
MIPS_STATCOUNTER(mem_hword_write, 11, 3)
MIPS_STATCOUNTER(mem_word_read, 11, 4)
MIPS_STATCOUNTER(mem_word_write, 11, 5)
MIPS_STATCOUNTER(mem_dword_read, 11, 6)
MIPS_STATCOUNTER(mem_dword_write, 11, 7)
MIPS_STATCOUNTER(mem_cap_read, 11, 8)
MIPS_STATCOUNTER(mem_cap_write, 11, 9)
MIPS_STATCOUNTER(mem_cap_read_tag_set, 11, 10)
MIPS_STATCOUNTER(mem_cap_write_tag_set, 11, 11)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(l2cachemaster_read_req, 13, 0)
MIPS_STATCOUNTER(l2cachemaster_write_req, 13, 1)
MIPS_STATCOUNTER(l2cachemaster_write_req_flit, 13, 2)
MIPS_STATCOUNTER(l2cachemaster_read_rsp, 13, 3)
MIPS_STATCOUNTER(l2cachemaster_read_rsp_flit, 13, 4)
MIPS_STATCOUNTER(l2cachemaster_write_rsp, 13, 5)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(tagcache_write_hit, 12, 0)
MIPS_STATCOUNTER(tagcache_write_miss, 12, 1)
MIPS_STATCOUNTER(tagcache_read_hit, 12, 2)
MIPS_STATCOUNTER(tagcache_read_miss, 12, 3)
MIPS_STATCOUNTER(tagcache_evict, 12, 6)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(tagcachemaster_read_req, 14, 0)
MIPS_STATCOUNTER(tagcachemaster_write_req, 14, 1)
MIPS_STATCOUNTER(tagcachemaster_write_req_flit, 14, 2)
MIPS_STATCOUNTER(tagcachemaster_read_rsp, 14, 3)
MIPS_STATCOUNTER(tagcachemaster_read_rsp_flit, 14, 4)
MIPS_STATCOUNTER(tagcachemaster_write_rsp, 14, 5)
STATCOUNTERS_GROUP_END()
MIPS_STATCOUNTER(imprecise_setbounds, 4, 3)
MIPS_STATCOUNTER(unrepresentable_caps, 4, 4)

#undef MIPS_STATCOUNTER
#undef STATCOUNTER_ITEM
#undef STATCOUNTERS_GROUP_END
