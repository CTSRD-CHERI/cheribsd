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
#include <sys/cdefs.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef PIC
#error "PIEs never need to initialise their own globals"
#endif

#define CHERI_INIT_GLOBALS_GDC_ONLY
#include <cheri_init_globals.h>
#if !defined(CHERI_INIT_GLOBALS_VERSION) || CHERI_INIT_GLOBALS_VERSION < 4
#error "cheri_init_globals.h is outdated. Please update LLVM"
#endif

/* This is __always_inline since it is called before globals have been set up */
static __always_inline void
crt_init_globals(const Elf_Phdr *phdr, long phnum,
    void * __capability *data_cap_out,
    const void * __capability *code_cap_out,
    const void * __capability *rodata_cap_out)
{
	const Elf_Phdr *phlimit = phdr + phnum;
	Elf_Addr text_start = (Elf_Addr)-1l;
	Elf_Addr text_end = 0;
	Elf_Addr readonly_start = (Elf_Addr)-1l;
	Elf_Addr readonly_end = 0;
	Elf_Addr writable_start = (Elf_Addr)-1l;
	Elf_Addr writable_end = 0;
	bool have_rodata_segment = false;
	bool have_text_segment = false;
	bool have_data_segment = false;
	void * __capability data_cap;
	const void * __capability code_cap;
	const void * __capability rodata_cap;

	/* Attempt to bound the data capability to only the writable segment */
	for (const Elf_Phdr *ph = phdr; ph < phlimit; ph++) {
		if (ph->p_type != PT_LOAD && ph->p_type != PT_GNU_RELRO) {
			/* Static binaries should not have a PT_DYNAMIC phdr */
			if (ph->p_type == PT_DYNAMIC) {
				__builtin_trap();
				break;
			}
			continue;
		}
		/*
		 * We found a PT_LOAD or PT_GNU_RELRO phdr. PT_GNU_RELRO will
		 * be a subset of a matching PT_LOAD but we need to add the
		 * range from PT_GNU_RELRO to the constant capability since
		 * __cap_relocs could have some constants pointing to the relro
		 * section. The phdr for the matching PT_LOAD has PF_R|PF_W so
		 * it would not be added to the readonly if we didn't also
		 * parse PT_GNU_RELRO.
		 */
		Elf_Addr seg_start = ph->p_vaddr;
		Elf_Addr seg_end = seg_start + ph->p_memsz;
		if ((ph->p_flags & PF_X)) {
			/* text segment */
			have_text_segment = true;
			text_start = MIN(text_start, seg_start);
			text_end = MAX(text_end, seg_end);
		} else if ((ph->p_flags & PF_W)) {
			/* data segment */
			have_data_segment = true;
			writable_start = MIN(writable_start, seg_start);
			writable_end = MAX(writable_end, seg_end);
		} else {
			have_rodata_segment = true;
			/* read-only segment (not always present) */
			readonly_start = MIN(readonly_start, seg_start);
			readonly_end = MAX(readonly_end, seg_end);
		}
	}

	if (!have_text_segment) {
		/* No text segment??? Must be an error somewhere else. */
		__builtin_trap();
	}
	if (!have_rodata_segment) {
		/*
		 * Note: If we don't have a separate rodata segment we also
		 * need to include the text segment in the rodata cap. This is
		 * required since all constants will be part of the read/exec
		 * segment instead of a separate read-only one.
		 */
		readonly_start = text_start;
		readonly_end = text_end;
	}
	if (!have_data_segment) {
		/*
		 * There cannot be any capabilities to initialize if there
		 * is no data segment. Set all to NULL to catch errors.
		 *
		 * Note: RELRO segment will be part of a R/W PT_LOAD.
		 */
		code_cap = NULL;
		data_cap = NULL;
		rodata_cap = NULL;
	} else {
		/* Check that ranges are well-formed */
		if (writable_end < writable_start ||
		    readonly_end < readonly_start ||
		    text_end < text_start)
			__builtin_trap();

		/* Abort if text and writeable overlap: */
		if (MAX(writable_start, text_start) <
		    MIN(writable_end, text_end)) {
			/* TODO: should we allow a single RWX segment? */
			__builtin_trap();
		}

#ifdef __CHERI_PURE_CAPABILITY__
		data_cap = __DECONST(void *, phdr);
#else
		data_cap = cheri_getdefault();
#endif
		data_cap = cheri_clearperm(data_cap, CHERI_PERM_EXECUTE);

		code_cap = cheri_getpcc();
		rodata_cap = cheri_clearperm(data_cap,
		    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		    CHERI_PERM_STORE_LOCAL_CAP);

		data_cap = cheri_setaddress(data_cap, writable_start);
		rodata_cap = cheri_setaddress(rodata_cap, readonly_start);

		/* TODO: should we use exact setbounds? */
		data_cap =
		    cheri_setbounds(data_cap, writable_end - writable_start);
		rodata_cap =
		    cheri_setbounds(rodata_cap, readonly_end - readonly_start);

		if (!cheri_gettag(data_cap))
			__builtin_trap();
		if (!cheri_gettag(rodata_cap))
			__builtin_trap();
		if (!cheri_gettag(code_cap))
			__builtin_trap();
	}
	cheri_init_globals_3(data_cap, code_cap, rodata_cap);
	if (data_cap_out)
		*data_cap_out = data_cap;
	if (code_cap_out)
		*code_cap_out = code_cap;
	if (rodata_cap_out)
		*rodata_cap_out = rodata_cap;
}
