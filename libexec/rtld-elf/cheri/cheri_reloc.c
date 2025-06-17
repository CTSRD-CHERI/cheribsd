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
 */

/*
 * CHERI CHANGES START
 * {
 *   "updated": 20221129,
 *   "target_type": "prog",
 *   "changes": [
 *     "support"
 *   ],
 *   "change_comment": "CHERI relocation"
 * }
 * CHERI CHANGES END
 */

#include "cheri_reloc.h"
#include "debug.h"
#include "rtld.h"

#ifdef RTLD_HAS_CAPRELOCS
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

	char * __capability data_base = get_datasegment_cap(obj);

	dbg("Processing %lu __cap_relocs for %s (data base = %#lp)\n",
	    (end_relocs - start_relocs), obj->path, data_base);

	bool tight_pcc_bounds;
#ifdef __CHERI_PURE_CAPABILITY__
	tight_pcc_bounds = can_use_tight_pcc_bounds(obj);
#else
	tight_pcc_bounds = false;
#endif

	for (const struct capreloc *reloc = start_relocs; reloc < end_relocs;
	     reloc++) {
		uintcap_t *dest =
		    (uintcap_t *)(obj->relocbase + reloc->capability_location);
		uintcap_t cap;
		bool can_set_bounds = true;

		if (reloc->object == 0) {
			/*
			 * XXXAR: clang fills uninitialized
			 * capabilities with 0xcacaca..., so we we
			 * need to explicitly write NULL here.
			 */
			*dest = 0;
			continue;
		}

		if ((reloc->permissions & function_reloc_flag) ==
		    function_reloc_flag) {
			/* code pointer */
			cap = (uintcap_t)pcc_cap(obj, reloc->object);
			cap = cheri_clearperm(cap, FUNC_PTR_REMOVE_PERMS);

			/*
			 * Do not set tight bounds for functions
			 * (unless we are in the plt ABI).
			 */
			can_set_bounds = tight_pcc_bounds;
		} else if ((reloc->permissions & constant_reloc_flag) ==
		    constant_reloc_flag) {
			 /* read-only data pointer */
			cap = (uintcap_t)pcc_cap(obj, reloc->object);
			cap = cheri_clearperm(cap, FUNC_PTR_REMOVE_PERMS);
			cap = cheri_clearperm(cap, DATA_PTR_REMOVE_PERMS);
		} else {
			/* read-write data */
			cap = (uintcap_t)data_base + reloc->object;
			cap = cheri_clearperm(cap, DATA_PTR_REMOVE_PERMS);
		}
		cap = cheri_clearperm(cap, CAP_RELOC_REMOVE_PERMS);
		if (can_set_bounds && (reloc->size != 0)) {
			cap = cheri_setbounds(cap, reloc->size);
		}
		cap += reloc->offset;
		if ((reloc->permissions & function_reloc_flag) ==
		    function_reloc_flag) {
			/* Convert function pointers to sentries: */
			cap = cheri_sealentry(cap);
#ifdef CHERI_LIB_C18N
			cap = (uintcap_t)tramp_intern(NULL, RTLD_COMPART_ID,
			    &(struct tramp_data) {
				.target = (void *)cap,
				.defobj = obj
			});
#endif
		}
		*dest = cap;
	}

	obj->cap_relocs_processed = true;
}
#endif
