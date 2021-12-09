/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999, 2000 John D. Polstra.
 * All rights reserved.
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
#define RTLD_MACHDEP_H	1

#include <sys/types.h>
#include <sys/sysctl.h>
#include <machine/atomic.h>
#include <machine/tls.h>

#include <stdlib.h>

#ifdef IN_RTLD
/* Don't pull this in when building libthr */
#include "debug.h"
#else
#include <assert.h>
#define dbg_assert(cond) assert(cond)
#define dbg_cheri(...)
#define dbg(...)
#endif

__BEGIN_DECLS

struct Struct_Obj_Entry;

/* Return the address of the .dynamic section in the dynamic linker. */
#define rtld_dynamic(obj) (&_DYNAMIC)

#ifdef __CHERI_PURE_CAPABILITY__
dlfunc_t _mips_rtld_bind(void* plt_stub);
#else
Elf_Addr reloc_jmpslot(Elf_Addr *where, Elf_Addr target,
    const struct Struct_Obj_Entry *defobj, const struct Struct_Obj_Entry *obj,
    const Elf_Rel *rel);
Elf_Addr _mips_rtld_bind(struct Struct_Obj_Entry *obj, Elf_Size reloff);
#endif

#if __has_feature(capabilities)

#define FUNC_PTR_REMOVE_PERMS	(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |	\
	__CHERI_CAP_PERMISSION_PERMIT_STORE__ |				\
	__CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ |		\
	__CHERI_CAP_PERMISSION_PERMIT_STORE_LOCAL__)

#define TARGET_CGP_REMOVE_PERMS	(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |	\
	__CHERI_CAP_PERMISSION_PERMIT_STORE__ |				\
	__CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ |		\
	__CHERI_CAP_PERMISSION_PERMIT_STORE_LOCAL__)

#define DATA_PTR_REMOVE_PERMS	(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |	\
	__CHERI_CAP_PERMISSION_PERMIT_EXECUTE__)

#ifdef __CHERI_PURE_CAPABILITY__
extern bool add_cheri_plt_stub(const Obj_Entry *obj, const Obj_Entry *rtldobj,
    Elf_Word r_symndx, void **where);

extern dlfunc_t find_external_call_thunk(const Elf_Sym* def, const Obj_Entry* defobj, size_t addend);

static inline bool
can_use_tight_pcc_bounds(const struct Struct_Obj_Entry *defobj)
{
	switch (defobj->cheri_captable_abi) {
	case DF_MIPS_CHERI_ABI_PLT:
	case DF_MIPS_CHERI_ABI_FNDESC:
		return true;
	case DF_MIPS_CHERI_ABI_PCREL:
		return false;
	default:
		dbg_assert(false && "Invalid abi");
		__builtin_unreachable();
		__builtin_trap();
	}
}
#endif

/*
 * Create a pointer to a function.
 * Important: this is not necessarily callable! For the PLT ABI we need a
 * to load $cgp first -> use make_function_pointer() instead.
 */
static inline dlfunc_t __capability
make_code_cap(const Elf_Sym *def, const struct Struct_Obj_Entry *defobj,
    bool tight_bounds, size_t addend)
{
	const void * __capability ret;

	ret = get_codesegment_cap(defobj) + def->st_value;
	/* Remove store and seal permissions */
	ret = cheri_clearperm(ret, FUNC_PTR_REMOVE_PERMS);
#ifdef __CHERI_PURE_CAPABILITY__
	dbg_assert(defobj->cheri_captable_abi != DF_MIPS_CHERI_ABI_LEGACY);
	dbg_assert(tight_bounds ==
	    (defobj->cheri_captable_abi != DF_MIPS_CHERI_ABI_PCREL));
#endif
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
 * Create a function pointer that can be called anywhere (i.e. for the PLT ABI
 * this will be a pointer to a trampoline that loads the correct $cgp).
 */

static inline dlfunc_t __capability
make_function_cap_with_addend(const Elf_Sym *def,
    const struct Struct_Obj_Entry *defobj, size_t addend)
{
#ifdef __CHERI_PURE_CAPABILITY__
	// Add a trampoline if the target ABI is not PCREL
	if (can_use_tight_pcc_bounds(defobj)) {
		return find_external_call_thunk(def, defobj, addend);
	}
#endif
	/* No need for a function pointer trampoline in the legacy/pcrel ABI */
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

/* Create a callable function pointer (needed for PLT ABI)  */
extern dlfunc_t
allocate_function_pointer_trampoline(dlfunc_t target_func, const Obj_Entry *obj);

/* Create a callable function pointer to a rtld-internal function */
static inline dlfunc_t
_make_rtld_function_pointer(dlfunc_t target_func) {
	extern struct Struct_Obj_Entry obj_rtld;
#if __CHERI_CAPABILITY_TABLE__ == 3
	/* PC-relative */
	dbg_assert(!can_use_tight_pcc_bounds(&obj_rtld));
	return target_func;
#else
	/* Need a trampoline in PLT ABI */
	dbg_assert(can_use_tight_pcc_bounds(&obj_rtld));
	return allocate_function_pointer_trampoline(target_func, &obj_rtld);
#endif
}

#if __CHERI_CAPABILITY_TABLE__ == 3
/* PC-relative can just use &func since there is no need for a trampoline */
#define _make_local_only_fn_pointer(func) (dlfunc_t)(&func)
#else
/*
 * In the PLT ABI we need to load the function pointer and pretend that we are
 * using it for a call only to avoid generating a R_CHERI_CAPABILITY relocation:
 */
#define _make_local_only_fn_pointer(func) (dlfunc_t)(__extension__ ({		\
	void* result = NULL;							\
	__asm__("clcbi %0, %%capcall20(" #func ")($cgp)" : "=C"(result));	\
	result;									\
}))
#endif

/* Define this as a macro to allow a single definition for non-CHERI architectures */
#define make_rtld_function_pointer(target_func)	\
	(__typeof__(&target_func))_make_rtld_function_pointer(_make_local_only_fn_pointer(target_func))
/*
 * Create a function pointer that can only be called from the context of rtld
 * (i.e. $cgp is set to the RTLD $cgp)
 */
#define make_rtld_local_function_pointer(target_func)	\
	(__typeof__(&target_func))_make_local_only_fn_pointer(target_func)

#if RTLD_SUPPORT_PER_FUNCTION_CAPTABLE == 1
/* Implemented as a C++ function to use std::lower_bound */
const void* find_per_function_cgp(const struct Struct_Obj_Entry *obj, const void* func);
void add_cgp_stub_for_local_function(Obj_Entry *obj, dlfunc_t* dest);
#endif

static inline const void* target_cgp_for_func(const struct Struct_Obj_Entry *obj, const dlfunc_t func)
{
#if RTLD_SUPPORT_PER_FUNCTION_CAPTABLE == 1
	if (obj->per_function_captable)
		return find_per_function_cgp(obj, (const void*)func);
#else
	(void)func;
#endif
	return obj->_target_cgp;
}

#define make_function_pointer(def, defobj) \
	make_function_cap(def, defobj)

// ignore _init/_fini
#define call_initfini_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)
#define call_init_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)

static inline void
_call_init_fini_array_pointer(const struct Struct_Obj_Entry *obj, InitArrayEntry entry, int argc, char** argv, char** env) {

	InitArrFunc func = (InitArrFunc)entry.value;
	/* Set the target object $cgp when calling the pointer:
	 * Note: we use target_cgp_for_func() to support per-function captable */
	const void *init_fini_cgp = target_cgp_for_func(obj, (dlfunc_t)func);
	dbg_cheri("Setting init function $cgp to %#p for call to %#p. "
	    "Current $cgp: %#p\n", init_fini_cgp, (void*)func, cheri_getidc());
	/*
	 * Invoke the function from assembly to ensure that the $cgp value is
	 * correct and the compiler can't reorder things.
	 * When I was calling the function from C, it broke at -O2.
	 * Note: we need the memory clobber here to ensure that the setting of
	 * $cgp is not ignored due to reordering of instructions (e.g. by adding
	 * a $cgp restore after external function calls).
	 */
	__asm__ volatile("cmove $cgp, %[cgp_val]\n\t"
	    :/*out*/
	    :/*in*/[cgp_val]"C"(init_fini_cgp)
	    :/*clobber*/"$c26", "memory");
	func(argc, argv, env);
	/* Ensure that the function call is not reordered before/after asm */
	__compiler_membar();
}

#define call_init_array_pointer(obj, target)			\
	_call_init_fini_array_pointer(obj, (target), main_argc, main_argv, environ)
#define call_fini_array_pointer(obj, target)			\
	_call_init_fini_array_pointer(obj, (target), main_argc, main_argv, environ)

#else /* __CHERI_PURE_CAPABILITY__ */

#define make_function_pointer(def, defobj) \
	((defobj)->relocbase + (def)->st_value)

#define call_initfini_pointer(obj, target) \
	(((InitFunc)(target))())

#define call_init_pointer(obj, target) \
	(((InitArrFunc)(target))(main_argc, main_argv, environ))

#endif /* __CHERI_PURE_CAPABILITY__ */

#define	call_ifunc_resolver(ptr) \
	(((uintptr_t (*)(void))ptr)())

typedef struct {
	unsigned long ti_module;
	unsigned long ti_offset;
} tls_index;

#define round(size, align) \
    (((size) + (align) - 1) & ~((align) - 1))
#define calculate_first_tls_offset(size, align, offset)	\
    TLS_TCB_SIZE
#define calculate_tls_offset(prev_offset, prev_size, size, align, offset) \
    round(prev_offset + prev_size, align)
#define calculate_tls_post_size(align)  0

extern void *__tls_get_addr(tls_index *ti);

#define	RTLD_DEFAULT_STACK_PF_EXEC	PF_X
#define	RTLD_DEFAULT_STACK_EXEC		PROT_EXEC

#define md_abi_variant_hook(x)

#define	TLS_VARIANT_I	1

#ifdef __CHERI_PURE_CAPABILITY__
/* Add function not used by CHERI as inlines here so that the compiler can
 * omit the call */

static inline void init_pltgot(Obj_Entry *obj __unused) { /* Do nothing */ }

static inline  int
reloc_iresolve(Obj_Entry *obj __unused, struct Struct_RtldLockState *lockstate __unused)
{
	_rtld_error("%s: not implemented!", __func__);
	return (0);
}

static inline int
reloc_iresolve_nonplt(Obj_Entry *obj __unused,
    struct Struct_RtldLockState *lockstate __unused)
{
	_rtld_error("%s: not implemented!", __func__);
	return (0);
}

static inline  int
reloc_gnu_ifunc(Obj_Entry *obj __unused, int flags __unused,
    struct Struct_RtldLockState *lockstate __unused)
{
	_rtld_error("%s: not implemented!", __func__);
	return (0);
}

static inline uintptr_t
reloc_jmpslot(uintptr_t *where __unused, uintptr_t target, const Obj_Entry *defobj __unused,
    const Obj_Entry *obj __unused, const Elf_Rel *rel __unused)
{
	_rtld_error("%s: not implemented!", __func__);
	return (target);
}
#endif

#if __has_feature(capabilities)
static_assert(_MIPS_SZCAP == 128, "CHERI bits != 128?");
#endif

/* Validating e_flags (and ABI version): */
#define rtld_validate_target_eflags(path, hdr, main_path)	\
	_rtld_validate_target_eflags(path, hdr, main_path)
static inline bool
_rtld_validate_target_eflags(const char* path, Elf_Ehdr *hdr, const char* main_path)
{
	size_t machine = (hdr->e_flags & EF_MIPS_MACH);

	/* Catch bogus non-CHERI CheriABI and any CHERI-256 */
#ifdef __CHERI_PURE_CAPABILITY__
	if (machine != EF_MIPS_MACH_CHERI128)
#else
	if (machine == EF_MIPS_MACH_CHERI256)
#endif
	{
		_rtld_error("%s: cannot load %s since its capability "
		    "size is not 128 bits (e_flags=0x%zx)",
		    main_path, path, (size_t)hdr->e_flags);
		return false;
	}

#ifdef __CHERI_PURE_CAPABILITY__
	if (hdr->e_ident[EI_ABIVERSION] != ELF_CHERIABI_ABIVERSION) {
		const char* allow_mismatch = getenv("LD_CHERI_ALLOW_ABIVERSION_MISMATCH");
		if (allow_mismatch == NULL || *allow_mismatch == '\0' ||
		    *allow_mismatch == '0') {
			_rtld_error("%s: cannot load %s since it is CheriABI "
			    "version %d and not %d. Set "
			    "LD_CHERI_ALLOW_ABIVERSION_MISMATCH to ignore this "
			    "error.", main_path, path,
			    hdr->e_ident[EI_ABIVERSION], ELF_CHERIABI_ABIVERSION);
			return false;
		}
	}
#endif
	return true;
}

#ifdef __CHERI_PURE_CAPABILITY__
static inline void
fix_obj_mapping_cap_permissions(Obj_Entry *obj, const char* path __unused)
{
	obj->text_rodata_cap = (const char*)cheri_clearperm(obj->text_rodata_cap, FUNC_PTR_REMOVE_PERMS);
	obj->relocbase = (char*)cheri_clearperm(obj->relocbase, DATA_PTR_REMOVE_PERMS);
	obj->mapbase = (char*)cheri_clearperm(obj->mapbase, DATA_PTR_REMOVE_PERMS);
	dbg("%s:\n\tmapbase=%-#p\n\trelocbase=%-#p\n\ttext_rodata=%-#p", path,
	    obj->mapbase, obj->relocbase, obj->text_rodata_cap);
}
#endif

__END_DECLS

#endif
