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
 *   "updated": 20180829,
 *   "target_type": "prog",
 *   "changes": [
 *     "support",
 *   ],
 *   "change_comment": "CHERI relocation"
 * }
 * CHERI CHANGES END
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#include <sys/types.h>
#include <cheri_init_globals.h>

#include "debug.h"
#include "rtld.h"


/*
 * LD_BIND_NOW was set - force relocation for all jump slots
 */
int
reloc_jmpslots(Obj_Entry *obj, int flags, RtldLockState *lockstate)
{
	/* Do nothing. TODO: needed once we have lazy binding */
	obj->jmpslots_done = true;
	return (0);
}

/*
 *  Process the PLT relocations.
 */
int
reloc_plt(Obj_Entry *obj)
{
	/* Do nothing. TODO: needed once we have lazy binding */
	return (0);
}

/* FIXME: replace this with cheri_init_globals_impl once everyone has updated clang */
static __attribute__((always_inline))
void _do___caprelocs(const struct capreloc *start_relocs,
    const struct capreloc * stop_relocs, void* gdc, void* pcc, vaddr_t base_addr)
{

	/*
	 * XXX: Aux args capabilities have base 0, but mmap gives us a tight
	 * base. Since reloc->object and (currently) reloc->capability_location
	 * are now absolute addresses, we must subtract the absolute address of
	 * gdc to avoid including mapbase twice.
	 */
	vaddr_t mapbase = __builtin_cheri_address_get(gdc);
	gdc = __builtin_cheri_perms_and(gdc, global_pointer_permissions);
	pcc = __builtin_cheri_perms_and(pcc, function_pointer_permissions);
	for (const struct capreloc *reloc = start_relocs; reloc < stop_relocs; reloc++) {
		_Bool isFunction = (reloc->permissions & function_reloc_flag) ==
		    function_reloc_flag;
		void **dest = __builtin_cheri_offset_increment(gdc,
		    reloc->capability_location + base_addr - mapbase);
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
			src = __builtin_cheri_offset_set(pcc, reloc->object);
		} else {
			src = __builtin_cheri_offset_increment(gdc,
			    reloc->object - mapbase);
			if (reloc->size != 0)
				src = __builtin_cheri_bounds_set(src, reloc->size);
		}
		src = __builtin_cheri_offset_increment(src, reloc->offset);
		*dest = src;
	}
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
    const struct capreloc* end_relocs, void *relocbase)
{
	void *pcc = __builtin_cheri_program_counter_get();

	_do___caprelocs(start_relocs, end_relocs, relocbase, pcc, 0);
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
	void *mapbase = obj->mapbase;
	void *pcc = __builtin_cheri_program_counter_get();

	dbg("Processing %lu __cap_relocs for %s\n", (end_relocs - start_relocs),
	    obj->path);

	/*
	 * We currently emit dynamic relocations for the cap_relocs location, so
	 * they will already have been processed when this function is called.
	 * This means the load address will already be included in
	 * reloc->capability_location.
	 */
#if 0
	/* TODO: don't emit dynamic relocations for obj->capability_location */
	vaddr_t base_addr = (vaddr_t)obj->relocbase;
#endif
	vaddr_t base_addr = 0;

	_do___caprelocs(start_relocs, end_relocs, mapbase, pcc, base_addr);

	obj->cap_relocs_processed = true;
}
