/*-
 * Copyright (c) 1999, 2000 John D. Polstra.
 * Copyright (c) 2014 the FreeBSD Foundation
 * Copyright 2018-2020 Alex Richardson <arichardson@FreeBSD.org>
 * Copyright 2020 Jessica Clarke <jrtc27@FreeBSD.org>
 * Copyright 2020 Brett F. Gutstein
 * All rights reserved.
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation.
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
 *
 * $FreeBSD$
 */

#ifndef RTLD_MACHDEP_H
#define	RTLD_MACHDEP_H	1

#include <sys/types.h>
#include <machine/atomic.h>
#include <machine/tls.h>

struct Struct_Obj_Entry;

/* Return the address of the .dynamic section in the dynamic linker. */
#ifdef __CHERI_PURE_CAPABILITY__
#define rtld_dynamic(obj) (&_DYNAMIC)
#else
#define	rtld_dynamic(obj)						\
({									\
	Elf_Addr _dynamic_addr;						\
	asm volatile("adr	%0, _DYNAMIC" : "=&r"(_dynamic_addr));	\
	(const Elf_Dyn *)_dynamic_addr;					\
})
#endif

uintptr_t reloc_jmpslot(uintptr_t *where, uintptr_t target,
    const struct Struct_Obj_Entry *defobj, const struct Struct_Obj_Entry *obj,
    const Elf_Rel *rel);

#if __has_feature(capabilities)

#define	FUNC_PTR_REMOVE_PERMS						\
	(CHERI_PERM_SEAL | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |	\
	CHERI_PERM_STORE_LOCAL_CAP)

#define	DATA_PTR_REMOVE_PERMS						\
	(CHERI_PERM_SEAL | CHERI_PERM_EXECUTE)

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

#endif /* __has_feature(capabilities) */

#ifdef __CHERI_PURE_CAPABILITY__

#define make_function_pointer(def, defobj) \
	make_function_cap(def, defobj)

/* ignore _init/_fini */
#define call_initfini_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)
#define call_init_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)

/* TODO: Per-function captable/PLT/FNDESC support */
#ifdef RTLD_SANDBOX
#define make_rtld_function_pointer(target_func)	(tramp_pgs_append((target_func), NULL, NULL))

#define call_init_array_pointer(obj, target)				\
	(((InitArrFunc)tramp_pgs_append((void *)(target).value, obj, NULL))(main_argc, main_argv, environ))

#define call_fini_array_pointer(obj, target)				\
	(((InitFunc)tramp_pgs_append((void *)(target).value, obj, NULL))())
#else
#define call_init_array_pointer(obj, target)				\
	(((InitArrFunc)(target).value)(main_argc, main_argv, environ))

#define call_fini_array_pointer(obj, target)				\
	(((InitFunc)(target).value)())
#endif

#else /* __CHERI_PURE_CAPABILITY__ */

#define	make_function_pointer(def, defobj) \
	((defobj)->relocbase + (def)->st_value)

#define	call_initfini_pointer(obj, target) \
	(((InitFunc)(target))())

#define	call_init_pointer(obj, target) \
	(((InitArrFunc)(target))(main_argc, main_argv, environ))

#endif /* __CHERI_PURE_CAPABILITY__ */

/*
 * Pass zeros into the ifunc resolver so we can change them later. The first
 * 8 arguments on arm64 are passed in registers so make them known values
 * if we decide to use them later. Because of this ifunc resolvers can assume
 * no arguments are passeed in, and if this changes later will be able to
 * compare the argument with 0 to see if it is set.
 */
#define	call_ifunc_resolver(ptr) \
	(((uintptr_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, \
	    uint64_t, uint64_t, uint64_t))ptr)(0, 0, 0, 0, 0, 0, 0, 0))

#define	round(size, align)				\
	(((size) + (align) - 1) & ~((align) - 1))
#define	calculate_first_tls_offset(size, align, offset)	\
	round(TLS_TCB_SIZE, align)
#define	calculate_tls_offset(prev_offset, prev_size, size, align, offset) \
	round(prev_offset + prev_size, align)
#define calculate_tls_post_size(align) \
	round(TLS_TCB_SIZE, align) - TLS_TCB_SIZE

typedef struct {
    unsigned long ti_module;
    unsigned long ti_offset;
} tls_index;

extern void *__tls_get_addr(tls_index *ti);

#define	RTLD_DEFAULT_STACK_PF_EXEC	PF_X
#define	RTLD_DEFAULT_STACK_EXEC		PROT_EXEC

#define md_abi_variant_hook(x)

#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
void *tramp_pgs_append(void *, const Obj_Entry *, const Elf_Sym *);
#endif

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
