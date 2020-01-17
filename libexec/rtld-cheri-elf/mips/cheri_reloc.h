/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include <dlfcn.h>

extern bool add_cheri_plt_stub(const Obj_Entry *obj, const Obj_Entry *rtldobj,
    Elf_Word r_symndx, void **where);

static inline int
process_r_cheri_capability(Obj_Entry *obj, Elf_Word r_symndx,
    RtldLockState *lockstate, int flags, void *where)
{
	const Obj_Entry *defobj;
	const Elf_Sym *def =
	    find_symdef(r_symndx, obj, &defobj, flags, NULL, lockstate);
	if (__predict_false(def == NULL)) {
		_rtld_error("%s: Could not find symbol %s", obj->path,
		    symname(obj, r_symndx));
		return -1;
	}
#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE >= 2
	dbg("%s: found %s from obj=%s in defobj=%s", __func__,
	    symname(obj, r_symndx), obj->path, defobj->path);
#endif
	assert(ELF_ST_TYPE(def->st_info) != STT_GNU_IFUNC &&
	    "IFUNC not implemented!");

	const void *symval = NULL;
	bool is_undef_weak = false;
	/*
	 * The first 8 bytes of the target location contains the added since
	 * we are using Elf_Rel and not Elf_Rela.
	 */
	uint64_t addend = load_ptr(where, sizeof(uint64_t));
	if (def->st_shndx == SHN_UNDEF) {
		/* Verify that we are resolving a weak symbol */
#ifdef DEBUG
		const Elf_Sym *src_sym = obj->symtab + r_symndx;
		dbg("NOTE: found undefined R_CHERI_CAPABILITY "
		    "for %s (in %s): value=%ld, size=%ld, "
		    "type=%d, def bind=%d,sym bind=%d",
		    symname(obj, r_symndx), obj->path, def->st_value,
		    def->st_size, ELF_ST_TYPE(def->st_info),
		    ELF_ST_BIND(def->st_info), ELF_ST_BIND(src_sym->st_info));
		dbg_assert(ELF_ST_BIND(src_sym->st_info) == STB_WEAK);
#endif
		assert(def == &sym_zero && "Undef weak symbol is non-canonical!");
		is_undef_weak = true;
		if (__predict_false(addend != 0)) {
			_rtld_error("Should not have an added for undef weak "
			    "symbol %s (in %s)\n", symname(obj, r_symndx),
			    obj->path);
			return -1;
		}
	} else if (ELF_ST_TYPE(def->st_info) == STT_FUNC) {
		/* Only warn about the first ten bad relocations for now */
		static int nonzero_addend_warnings = 0;
		if (addend != 0 && nonzero_addend_warnings < 10) {
			rtld_fdprintf(STDERR_FILENO,
			    "Warning: %s: got relocation against function (%s) "
			    "with non-zero offset (%jd). This is deprecated!\n",
			    obj->path, symname(obj, r_symndx),
			    (uintmax_t)addend);
			nonzero_addend_warnings++;
			if (nonzero_addend_warnings >= 10) {
				rtld_fdprintf(STDERR_FILENO,
				    "Note: reached warning limit, will not warn"
				    "about further bad function relocations\n");
			}
		}
		/* Remove write permissions and set bounds */
		symval = make_function_pointer_with_addend(def, defobj, addend);
		if (__predict_false(symval == NULL)) {
			_rtld_error("Could not create function pointer for %s "
				    "(in %s)\n",
			    symname(obj, r_symndx), obj->path);
			return -1;
		}
	} else {
		/* Remove execute permissions and set bounds */
		symval = cheri_incoffset(make_data_pointer(def, defobj), addend);
	}
#ifdef DEBUG
	// FIXME: this warning breaks some tests that expect clean stdout/stderr
	// FIXME: See https://github.com/CTSRD-CHERI/cheribsd/issues/257
	// TODO: or use this approach:
	// https://github.com/CTSRD-CHERI/cheribsd/commit/c1920496c0086d9c5214fb0f491e4d6cdff3828e?
	if (__predict_false(symval != NULL && cheri_getlen(symval) <= 0)) {
		rtld_fdprintf(STDERR_FILENO,
		    "Warning: created zero length "
		    "capability for %s (in %s): %-#p\n",
		    symname(obj, r_symndx), obj->path, symval);
	}
#endif
	if (__predict_false(!cheri_gettag(symval) && !is_undef_weak)) {
		_rtld_error("%s: constructed invalid capability for %s: %#p",
		    obj->path, symname(obj, r_symndx), symval);
		return -1;
	}
	*((const void **)where) = symval;
#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE >= 2
	dbg("CAP(%p/0x%lx) %s in %s --> %-#p in %s", where,
	    (const char *)where - (const char *)obj->relocbase,
	    symname(obj, r_symndx), obj->path, *((void **)where), defobj->path);
#endif
	return 0;
}
