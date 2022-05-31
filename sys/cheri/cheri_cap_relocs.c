/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
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

#include <sys/types.h>
#include <cheri_init_globals.h>

/* Invoked from locore. */
extern void init_cap_relocs(void *data_cap, void *code_cap);

void
init_cap_relocs(void *data_cap, void *code_cap)
{
	cheri_init_globals_3(data_cap, code_cap, data_cap);
}

/* Can't include <sys/cheri.h>. */
typedef void (cap_relocs_cb)(void *arg, bool function, bool constant,
    ptraddr_t object, void **src);

void	init_linker_file_cap_relocs(const void *start_relocs,
	    const void *stop_relocs, void *data_cap, ptraddr_t base_addr,
	    cap_relocs_cb *cb, void *cb_arg);

void
init_linker_file_cap_relocs(const void *start_relocs, const void *stop_relocs,
    void *data_cap, ptraddr_t base_addr, cap_relocs_cb *cb, void *cb_arg)
{
	/*
	 * Set code bounds if the ABI allows it.
	 * When building for hybrid or with the pc-relative captable ABI we do
	 * not further constrain the given code_cap.
	 */
#if !defined(__CHERI_PURE_CAPABILITY__) || __CHERI_CAPABILITY_TABLE__ == 3
	bool can_set_code_bounds = false;
#else
	bool can_set_code_bounds = true;
#endif

	/*
	 * This cannot use cheri_init_globals_impl directly as symbols
	 * for kernel modules in the vnet and dpcpu sets need to use
	 * alternate base addresses and capabilities.  Instead, we
	 * invoke a caller-supplied callback on each capability to
	 * request the base address and source capability.
	 */
	for (const struct capreloc *reloc = start_relocs;
	     reloc < (const struct capreloc *)stop_relocs; reloc++) {
		const void **dest = __builtin_cheri_address_set(data_cap,
		    reloc->capability_location + base_addr);
		void *src;
		bool function, constant;

		if (reloc->object == 0) {
			*dest = 0;
			continue;
		}
		function = (reloc->permissions & function_reloc_flag) ==
		    function_reloc_flag;
		constant = (reloc->permissions & constant_reloc_flag) ==
		    constant_reloc_flag;
		cb(cb_arg, function, constant, reloc->object, &src);
		if ((!function || can_set_code_bounds) && reloc->size != 0)
			src = __builtin_cheri_bounds_set(src, reloc->size);
		src = (char *)src + reloc->offset;
		if (function) {
			/* Convert function pointers to sentries: */
			src = __builtin_cheri_seal_entry(src);
		}
		*dest = src;	
	}
}
