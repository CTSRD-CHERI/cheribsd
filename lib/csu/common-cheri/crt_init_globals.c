/*-
 * Copyright (c) 2014 Robert N. M. Watson
 * Copyright (c) 2017-2018 Alex Richardson
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
 */
#include <sys/param.h>
#include <machine/elf.h>
#include <stdint.h>
#include <stdlib.h>

#include <cheri/cherireg.h>
#include <cheriintrin.h>

#ifdef PIC
#error "PIEs never need to initialise their own globals"
#endif

#ifdef CHERI_INIT_RELA
extern const Elf_Rela __weak_symbol __rela_dyn_start[] __hidden;
extern const Elf_Rela __weak_symbol __rela_dyn_end[] __hidden;

static __always_inline void
crt_init_rela(const void * __capability code_cap, void * __capability data_cap)
{
	const Elf_Rela *rela, *relalim;

	rela = CHERI_RODATA_PTR(__rela_dyn_start);
	relalim = CHERI_RODATA_PTR(__rela_dyn_end);
	for (; rela < relalim; rela++)
		elf_reloc(rela, data_cap, code_cap, 0);
}
#endif

#define CHERI_INIT_GLOBALS_GDC_ONLY
#if defined(__riscv) && defined(__CHERI_PURE_CAPABILITY__)
#define CHERI_INIT_GLOBALS_ALLOW_IFUNCS
#endif
#include <cheri_init_globals.h>
#if !defined(CHERI_INIT_GLOBALS_VERSION) || CHERI_INIT_GLOBALS_VERSION < 4
#error "cheri_init_globals.h is outdated. Please update LLVM"
#endif

/* This is __always_inline since it is called before globals have been set up */
static __always_inline void
crt_init_globals(const Elf_Phdr *phdr, long phnum __unused,
    void * __capability *data_cap_out,
    const void * __capability *code_cap_out)
{
	const struct capreloc *start_relocs;
	const struct capreloc *stop_relocs;
#ifndef __CHERI_PURE_CAPABILITY__
	const Elf_Phdr *phlimit = phdr + phnum;
	Elf_Addr base_addr = (Elf_Addr)-1l;
	Elf_Addr end_addr = 0;
#endif
	bool use_code_bounds = false;
	void * __capability data_cap;
	const void * __capability code_cap;
	const void * __capability rodata_cap;

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * The capabilities for `phdr` and the current PCC should be
	 * constrained to the executable for purecap.  Trust
	 * relocations to further narrow code bounds as needed.
	 */
	use_code_bounds = true;
	data_cap = __DECONST(void *, phdr);
#else
	/* Bound the data capability to the executable image */
	for (const Elf_Phdr *ph = phdr; ph < phlimit; ph++) {
		if (ph->p_type != PT_LOAD)
			continue;

		base_addr = MIN(base_addr, ph->p_vaddr);
		end_addr = MAX(end_addr, ph->p_vaddr + ph->p_memsz);
	}

	data_cap = cheri_ddc_get();
	data_cap = cheri_address_set(data_cap, base_addr);
	data_cap = cheri_bounds_set(data_cap, end_addr - base_addr);
#endif

	code_cap = cheri_pcc_get();
	data_cap = cheri_perms_clear(data_cap, CHERI_PERM_EXECUTE |
	    CHERI_PERM_SW_VMEM);
	rodata_cap = cheri_perms_clear(data_cap, CHERI_PERM_STORE |
#ifdef HAS_CHERI_PERM_LOAD_STORE_CAP
	    CHERI_PERM_STORE_CAP |
#endif
	    CHERI_PERM_STORE_LOCAL_CAP);

#ifdef CHERI_INIT_RELA
	crt_init_rela(code_cap, data_cap);
#endif

	start_relocs = CHERI_RODATA_PTR(__start___cap_relocs);
	stop_relocs = CHERI_RODATA_PTR(__stop___cap_relocs);

	cheri_init_globals_impl(start_relocs, stop_relocs, data_cap, code_cap,
	    rodata_cap, use_code_bounds, 0);
	if (data_cap_out)
		*data_cap_out = data_cap;
	if (code_cap_out)
		*code_cap_out = code_cap;
}
