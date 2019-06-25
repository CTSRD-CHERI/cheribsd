/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright 2017,2018 Alex Richadson <arichardson@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181121,
 *   "target_type": "prog",
 *   "changes": [
 *     "support"
 *   ],
 *   "change_comment": "CHERI relocation"
 * }
 * CHERI CHANGES END
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#include <sys/types.h>
/* The clang-provided header is not warning-clean: */
__unused static void cheri_init_globals(void);
#include <cheri_init_globals.h>

#include "debug.h"
#include "rtld.h"

void _rtld_do___caprelocs_self(const struct capreloc *start_relocs,
    const struct capreloc* end_relocs, void *relocbase, Elf_Addr cheri_flags);

/* FIXME: replace this with cheri_init_globals_impl once everyone has updated clang */
static __attribute__((always_inline))
void _do___caprelocs(const struct capreloc *start_relocs,
    const struct capreloc * stop_relocs, void* gdc, const void* pcc,
    vaddr_t base_addr, bool tight_pcc_bounds)
{
#if defined(CHERI_INIT_GLOBALS_VERSION) && CHERI_INIT_GLOBALS_VERSION >= 2
	cheri_init_globals_impl(start_relocs, stop_relocs, /*data_cap=*/gdc,
	    /*code_cap=*/pcc, /*rodata_cap=*/pcc,
	    /*tight_code_bounds=*/tight_pcc_bounds, base_addr);
#else
#pragma message("LLVM cheri_init_globals.h is too old, please update LLVM")
	(void)base_addr;
	/*
	 * XXX: Aux args capabilities have base 0, but mmap gives us a tight
	 * base. Since reloc->object and (currently) reloc->capability_location
	 * are now absolute addresses, we must subtract the absolute address of
	 * gdc to avoid including mapbase twice.
	 */
	// vaddr_t mapbase = __builtin_cheri_address_get(gdc);
	gdc = cheri_clearperm(gdc, DATA_PTR_REMOVE_PERMS);
	pcc = cheri_clearperm(pcc, FUNC_PTR_REMOVE_PERMS);
	for (const struct capreloc *reloc = start_relocs; reloc < stop_relocs; reloc++) {
		_Bool isFunction = (reloc->permissions & function_reloc_flag) ==
		    function_reloc_flag;
		void **dest = __builtin_cheri_address_set(
		    gdc, reloc->capability_location);
		if (reloc->object == 0) {
			/*
			 * XXXAR: clang fills uninitialized capabilities with
			 * 0xcacaca..., so we we need to explicitly write NUL
			 * here.
			 */
			*dest = (void*)0;
			continue;
		}
		void *src;
		if (isFunction) {
			src = cheri_setaddress(pcc, reloc->object);
			if (tight_pcc_bounds)
				src = __builtin_cheri_bounds_set(src, reloc->size);
		} else {
			src = cheri_setaddress(gdc, reloc->object);
			if (reloc->size != 0)
				src = __builtin_cheri_bounds_set(src, reloc->size);
		}
		src = __builtin_cheri_offset_increment(src, reloc->offset);
		*dest = src;
	}
#endif
}

/*
 * XXXAR: We can't use cheri_init_globals since that uses dla and
 * therefore would cause text relocations. Instead use the PIC_LOAD_CODE_PTR()
 * macro in the assembly and pass in __start_cap_relocs/__stop_cap_relocs.
 *
 * TODO: We could also parse the DT_CHERI___CAPRELOCS and DT_CHERI___CAPRELOCSSZ
 * in _rtld_relocate_nonplt_self and save that to the stack instead. Might
 * save a few instructions but not sure it's worth the effort of writing more asm.
 */
void
_rtld_do___caprelocs_self(const struct capreloc *start_relocs,
    const struct capreloc* end_relocs, void *relocbase, Elf_Addr cheri_flags)
{
	void *pcc = __builtin_cheri_program_counter_get();
	// TODO: allow using tight bounds for RTLD by passing in the parameter
	//  from ASM if it was built for the PLT ABI

	bool relative_relocs = cheri_flags & DF_MIPS_CHERI_RELATIVE_CAPRELOCS;
#if CHERI_INIT_GLOBALS_VERSION < 3
#pragma message("Please update LLVM!")
	if (relative_relocs) {
		/* Not possible with the old <cheri_init_globals.h> */
		__builtin_trap();
	}
#endif
	// If the binary includes the RELATIVE_CAPRELOCS dynamic flag we have
	// to add getaddr(relocbase) to every __cap_reloc location and object.
	vaddr_t base_addr = relative_relocs ? cheri_getaddress(relocbase) : 0;
	_do___caprelocs(
	    start_relocs, end_relocs, relocbase, pcc, base_addr, false);
}

void
process___cap_relocs(Obj_Entry* obj)
{
	if (obj->cap_relocs_processed) {
		dbg("__cap_relocs for %s have already been processed!", obj->path);
		/* TODO: abort() to prevent this from happening? */
		return;
	}
	struct capreloc *start_relocs = (struct capreloc *)obj->cap_relocs;
	struct capreloc *end_relocs =
	    (struct capreloc *)(obj->cap_relocs + obj->cap_relocs_size);
	/*
	 * It would be nice if we could use a DDC and PCC with smaller bounds
	 * here. However, the target could be in a different shared library so
	 * while we are still using __cap_relocs just derive it from RTLD.
	 *
	 * TODO: reject those binaries and suggest relinking with the right flag
	 */
	void *data_base = obj->relocbase;
	const void *code_base = get_codesegment(obj);

	dbg("Processing %lu __cap_relocs for %s (code base = %-#p, data base = %-#p) \n",
	    (end_relocs - start_relocs), obj->path, code_base, data_base);

	/*
	 * We have dynamic relocations for the cap_relocs location, unless the
	 * binary has the DF_MIPS_CHERI_RELATIVE_CAPRELOCS flag set.
	 * In the non-relative case we do not need to add the base address since
	 * that value will already have been added by the relocation processing.
	 */
#if CHERI_INIT_GLOBALS_VERSION < 3
#pragma message("Please update LLVM!")
	if (obj->relative_cap_relocs) {
		rtld_fatal("Not possible with the old <cheri_init_globals.h>");
	}
#else
	if (!obj->relative_cap_relocs) {
		rtld_fdprintf(STDERR_FILENO,
		    "File '%s' still uses old __cap_relocs. Please recompile "
		    "it with a newer toolchain.\n", obj->path);
	}
#endif
	// If the binary includes the RELATIVE_CAPRELOCS dynamic flag we have
	// to add getaddr(relocbase) to every __cap_reloc location and object.
	vaddr_t base_addr = obj->relative_cap_relocs ? cheri_getaddress(obj->relocbase) : 0;

	_do___caprelocs(start_relocs, end_relocs, data_base, code_base, base_addr,
	    obj->restrict_pcc_strict);
#if RTLD_SUPPORT_PER_FUNCTION_CAPTABLE == 1
	// TODO: do this later
	if (obj->per_function_captable) {
		dbg_cheri_plt("Adding per-function plt stubs for %s", obj->path);
		for (const struct capreloc *reloc = start_relocs; reloc < end_relocs; reloc++) {
			_Bool isFunction = (reloc->permissions & function_reloc_flag) == function_reloc_flag;
			if (!isFunction)
				continue;
			// TODO: write location as a relative value
			dlfunc_t *dest = (dlfunc_t*)cheri_setaddress(obj->relocbase, reloc->capability_location);
			add_cgp_stub_for_local_function(obj, dest);
		}
	}
#endif
	obj->cap_relocs_processed = true;
}
