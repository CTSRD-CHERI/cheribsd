/*-
 * Copyright 2018-2020 Alex Richardson <arichardson@FreeBSD.org>
 * Copyright 2020 Jessica Clarke <jrtc27@FreeBSD.org>
 * Copyright 2020 Brett F. Gutstein
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
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

#ifndef RTLD_CHERI_MACHDEP_H
#define RTLD_CHERI_MACHDEP_H	1

#define	FUNC_PTR_REMOVE_PERMS						\
	(CHERI_PERM_SEAL | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |	\
	CHERI_PERM_STORE_LOCAL_CAP)

#define	DATA_PTR_REMOVE_PERMS						\
	(CHERI_PERM_SEAL | CHERI_PERM_EXECUTE)

#define	CAP_RELOC_REMOVE_PERMS						\
	(CHERI_PERM_SW_VMEM)

#ifdef __CHERI_PURE_CAPABILITY__
/* TODO: ABIs with tight bounds */
#define can_use_tight_pcc_bounds(obj) ((void)(obj), false)
#endif

/*
 * Create a pointer to a function.
 */
static inline dlfunc_t __capability
make_code_cap(const Elf_Sym *def, const struct Struct_Obj_Entry *defobj,
    bool tight_bounds, size_t addend)
{
	const void * __capability ret;

	ret = get_codesegment_cap(defobj) + def->st_value;
	/* Remove store and seal permissions */
	ret = cheri_clearperm(ret, FUNC_PTR_REMOVE_PERMS);
	if (tight_bounds) {
		ret = cheri_setbounds(ret, def->st_size);
	}
	/*
	 * Note: The addend is required for C++ exceptions since capabilities
	 * for catch blocks point to the middle of a function.
	 */
	ret = cheri_incoffset(ret, addend);
	/* All code pointers should be sentries: */
	ret = __builtin_cheri_seal_entry(ret);
	return __DECONST_CAP(dlfunc_t __capability, ret);
}

/*
 * Create a function pointer that can be called anywhere
 */
static inline dlfunc_t __capability
make_function_cap_with_addend(const Elf_Sym *def,
    const struct Struct_Obj_Entry *defobj, size_t addend)
{
	/* TODO: ABIs with tight bounds */
	return make_code_cap(def, defobj, /*tight_bounds=*/false, addend);
}

static inline dlfunc_t __capability
make_function_cap(const Elf_Sym *def, const struct Struct_Obj_Entry *defobj)
{
	return make_function_cap_with_addend(def, defobj, /*addend=*/0);
}

static inline void * __capability
make_data_cap(const Elf_Sym *def, const struct Struct_Obj_Entry *defobj)
{
	void * __capability ret;
	ret = get_datasegment_cap(defobj) + def->st_value;
	/* Remove execute and seal permissions */
	ret = cheri_clearperm(ret, DATA_PTR_REMOVE_PERMS);
	ret = cheri_setbounds(ret, def->st_size);
	return ret;
}

#define set_bounds_if_nonnull(cap, size)	\
	do { if (cap) { cap = cheri_setbounds(cap, size); } } while(0)

#ifdef __CHERI_PURE_CAPABILITY__
static inline void
fix_obj_mapping_cap_permissions(Obj_Entry *obj, const char *path __unused)
{
	obj->text_rodata_cap = (const char*)cheri_clearperm(obj->text_rodata_cap, FUNC_PTR_REMOVE_PERMS);
	obj->relocbase = (char*)cheri_clearperm(obj->relocbase, DATA_PTR_REMOVE_PERMS);
	obj->mapbase = (char*)cheri_clearperm(obj->mapbase, DATA_PTR_REMOVE_PERMS);
}
#endif

#endif
