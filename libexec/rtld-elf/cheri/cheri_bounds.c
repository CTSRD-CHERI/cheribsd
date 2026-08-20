/*-
 * Copyright (c) 2024 John Baldwin
 # Copyright (c) 2018 Alex Richardson
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/types.h>

#include "rtld.h"
#include "rtld_malloc.h"

bool
create_pcc_caps(Obj_Entry *obj, const char *name)
{
	const Elf_Phdr *ph;
	const char *pcc_cap;
	unsigned long i, j;

	for (ph = obj->phdr; ph < obj->phdr + obj->phnum; ph++) {
		switch (ph->p_type) {
		case PT_CHERI_PCC:
			obj->npcc_caps++;
			break;
		}
	}

	if (obj->npcc_caps == 0)
		return (true);

	i = 0;
	obj->pcc_caps = xcalloc(obj->npcc_caps, sizeof(*obj->pcc_caps));
	for (ph = obj->phdr; ph < obj->phdr + obj->phnum; ph++) {
		switch (ph->p_type) {
		case PT_CHERI_PCC:
			pcc_cap = obj->text_rodata_cap + ph->p_vaddr;
			pcc_cap = cheri_bounds_set_exact(pcc_cap, ph->p_memsz);
			if (!cheri_tag_get(pcc_cap)) {
				_rtld_error("pcc_cap %#p is not exact for %s",
				    pcc_cap, name);
				return (false);
			}
			obj->pcc_caps[i] = pcc_cap;
			i++;
			break;
		}
	}

	/*
	 * Require each PCC capability to be non-overlapping with
	 * other PCC capabilities.
	 */
	for (i = 1; i < obj->npcc_caps; i++) {
		pcc_cap = obj->pcc_caps[i];
		for (j = 0; j < i; j++) {
			if (cheri_is_address_inbounds(pcc_cap,
				cheri_base_get(obj->pcc_caps[j])) ||
			    cheri_is_address_inbounds(obj->pcc_caps[j],
				cheri_base_get(pcc_cap))) {
				_rtld_error(
				    "Overlapping PCC capabilities for %s",
				    name);
				return (false);
			}
		}
	}
	return (true);
}

/*
 * Returns a code pointer to the instruction at the relative offset
 * into the mapped object.  The pointer uses the bounds from the
 * relevant PT_CHERI_PCC segment.
 */
const char *
pcc_cap(const Obj_Entry *obj, Elf_Off offset)
{
	Elf_Addr addr;
	const char *pcc_cap;

	addr = (Elf_Addr)(uintptr_t)obj->relocbase + offset;
	for (unsigned long i = 0; i < obj->npcc_caps; i++) {
		pcc_cap = obj->pcc_caps[i];
		if (addr >= (ptraddr_t)pcc_cap &&
		    addr < cheri_top_get(pcc_cap)) {
			pcc_cap = cheri_address_set(pcc_cap, addr);
			return (cheri_perms_clear(pcc_cap,
			    CAP_RELOC_REMOVE_PERMS));
		}
	}
	return (NULL);
}

void
narrow_object_bounds(Obj_Entry *obj)
{
	/*
	 * Set tight bounds on the individual members now (for the ones that
	 * we iterate over) instead of inheriting the relocbase bounds to avoid
	 * any overflows at runtime.
	 */
	set_bounds_if_nonnull(obj->rel, obj->relsize);
	set_bounds_if_nonnull(obj->rela, obj->relasize);
	for (unsigned long i = 0; i < obj->nplts; i++) {
		Plt_Entry *plt = &obj->plts[i];
		set_bounds_if_nonnull(plt->rel, plt->relsize);
		set_bounds_if_nonnull(plt->rela, plt->relasize);
	}
#ifdef CHERI_LIB_C18N
	set_bounds_if_nonnull(obj->c18nstrtab, obj->c18nstrsize);
#endif
	set_bounds_if_nonnull(obj->strtab, obj->strsize);
	set_bounds_if_nonnull(obj->phdr, obj->phnum * sizeof(*obj->phdr));

	set_bounds_if_nonnull(obj->preinit_array,
	    obj->preinit_array_num * sizeof(*obj->preinit_array));
	set_bounds_if_nonnull(obj->init_array,
	    obj->init_array_num * sizeof(*obj->init_array));
	set_bounds_if_nonnull(obj->fini_array,
	    obj->fini_array_num * sizeof(*obj->fini_array));

#ifdef RTLD_HAS_CAPRELOCS
	set_bounds_if_nonnull(obj->cap_relocs, obj->cap_relocs_size);
#endif
}
