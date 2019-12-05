/*-
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
#include <cheri/cheric.h>
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

static inline Elf_Addr reloc_jmpslot(Elf_Addr *where, Elf_Addr target,
    const struct Struct_Obj_Entry *defobj, const struct Struct_Obj_Entry *obj,
    const Elf_Rel *rel);
dlfunc_t _mips_rtld_bind(void* plt_stub);

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

static inline const char*
get_codesegment(const struct Struct_Obj_Entry *obj) {
	/* TODO: we should have a separate member for .text/rodata */
	dbg_assert(cheri_getperm(obj->text_rodata_cap) & __CHERI_CAP_PERMISSION_PERMIT_EXECUTE__);
	dbg_assert(!(cheri_getperm(obj->text_rodata_cap) & __CHERI_CAP_PERMISSION_PERMIT_STORE__));
	return obj->text_rodata_cap;
}

extern dlfunc_t find_external_call_thunk(const Elf_Sym* def, const Obj_Entry* defobj);

static inline bool
can_use_tight_pcc_bounds(const struct Struct_Obj_Entry *defobj)
{
	switch (defobj->cheri_captable_abi) {
	case DF_MIPS_CHERI_ABI_PLT:
	case DF_MIPS_CHERI_ABI_FNDESC:
		return true;
#ifndef __CHERI_CAPABILITY_TABLE__
	case DF_MIPS_CHERI_ABI_LEGACY:
#endif
	case DF_MIPS_CHERI_ABI_PCREL:
		return false;
	default:
		dbg_assert(false && "Invalid abi");
		__builtin_unreachable();
		__builtin_trap();
	}
}

/* Create a callable function pointer (needed for PLT ABI)  */
extern dlfunc_t
allocate_function_pointer_trampoline(dlfunc_t target_func, const Obj_Entry *obj);

/* Create a callable function pointer to a rtld-internal function */
static inline dlfunc_t
_make_rtld_function_pointer(dlfunc_t target_func) {
	extern struct Struct_Obj_Entry obj_rtld;
#if !defined(__CHERI_CAPABILITY_TABLE__) || __CHERI_CAPABILITY_TABLE__ == 3
	/* PC-rel/legacy */
	dbg_assert(!can_use_tight_pcc_bounds(&obj_rtld));
	return target_func;
#else
	/* Need a trampoline in PLT ABI */
	dbg_assert(can_use_tight_pcc_bounds(&obj_rtld));
	return allocate_function_pointer_trampoline(target_func, &obj_rtld);
#endif
}

#if !defined(__CHERI_CAPABILITY_TABLE__) || __CHERI_CAPABILITY_TABLE__ == 3
/* Legacy/pc-rel can just use &func since there is no need for a trampoline */
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

/*
 * Create a pointer to a function.
 * Important: this is not necessarily callable! For the PLT ABI we need a
 * to load $cgp first -> use make_function_pointer() instead.
 */
static inline dlfunc_t
make_code_pointer(const Elf_Sym *def, const struct Struct_Obj_Entry *defobj,
    bool tight_bounds)
{
	const void *ret = get_codesegment(defobj) + def->st_value;
#ifndef __CHERI_CAPABILITY_TABLE__
	if (defobj->cheri_captable_abi == DF_MIPS_CHERI_ABI_LEGACY) {
		/*
		 * Legacy abi: we need to give it full address space range
		 * (including the full permissions mask) to support legacy binaries.
		 */
		assert(cheri_getbase(cheri_getpcc()) == 0);
		return (dlfunc_t)cheri_setaddress(cheri_getpcc(), (vaddr_t)ret);
	}
#endif
	/* Remove store and seal permissions */
	ret = cheri_clearperm(ret, FUNC_PTR_REMOVE_PERMS);
	dbg_assert(defobj->cheri_captable_abi != DF_MIPS_CHERI_ABI_LEGACY);
	if (tight_bounds) {
		dbg_assert(defobj->cheri_captable_abi != DF_MIPS_CHERI_ABI_PCREL);
		ret = cheri_csetbounds(ret, def->st_size);
	} else {
		/* PC-relative ABI needs full DSO bounds */
		dbg_assert(defobj->cheri_captable_abi == DF_MIPS_CHERI_ABI_PCREL);
	}
	/* All code pointers should be sentries: */
#if __has_builtin(__builtin_cheri_seal_entry)
	ret = __builtin_cheri_seal_entry(ret);
#else
#warning "__builtin_cheri_seal_entry not supported, please update LLVM"
#endif
	return __DECONST(dlfunc_t, ret);
}

/*
 * Create a function pointer that can be called anywhere (i.e. for the PLT ABI
 * this will be a pointer to a trampoline that loads the correct $cgp.
 */
static inline dlfunc_t
make_function_pointer(const Elf_Sym *def, const struct Struct_Obj_Entry *defobj)
{
	// Add a trampoline if the target ABI is not PCREL
	if (can_use_tight_pcc_bounds(defobj)) {
		return find_external_call_thunk(def, defobj);
	} else {
		/* No need for a function pointer trampoline in the legacy/pcrel ABI */
		return make_code_pointer(def, defobj, /*tight_bounds=*/false);
	}
}

static inline void*
make_data_pointer(const Elf_Sym* def, const struct Struct_Obj_Entry *defobj)
{
	void* ret = defobj->relocbase + def->st_value;
	/* Remove execute and seal permissions */
	ret = cheri_clearperm(ret, DATA_PTR_REMOVE_PERMS);
	/* TODO: can we always set bounds here or does it break compat? */
	ret = cheri_csetbounds(ret, def->st_size);
	return ret;
}

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

static inline dlfunc_t
vaddr_to_code_pointer(const struct Struct_Obj_Entry *obj, vaddr_t code_addr) {
	const void* text = get_codesegment(obj);
	dbg_assert(code_addr >= (vaddr_t)text);
	dbg_assert(code_addr < (vaddr_t)text + cheri_getlen(text));
	return (dlfunc_t)cheri_copyaddress(text, cheri_fromint(code_addr));
}

#define set_bounds_if_nonnull(ptr, size)	\
	do { if (ptr) { ptr = cheri_csetbounds_sametype(ptr, size); } } while(0)

// ignore _init/_fini
#define call_initfini_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)

static inline void
_call_init_fini_array_pointer(const struct Struct_Obj_Entry *obj, vaddr_t target, int argc, char** argv, char** env) {

	InitArrFunc func = (InitArrFunc)vaddr_to_code_pointer(obj, target);
#if defined(__CHERI_CAPABILITY_TABLE__)
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
#else
	func(argc, argv, env);
#endif
}

#define call_init_array_pointer(obj, target)			\
	_call_init_fini_array_pointer(obj, (target), main_argc, main_argv, environ)
#define call_fini_array_pointer(obj, target)			\
	_call_init_fini_array_pointer(obj, (target), main_argc, main_argv, environ)

// Not implemented for CHERI:
// #define	call_ifunc_resolver(ptr) \
// 	(((Elf_Addr (*)(void))ptr)())

typedef struct {
	unsigned long ti_module;
	unsigned long ti_offset;
} tls_index;

#define round(size, align) \
    (((size) + (align) - 1) & ~((align) - 1))
#define calculate_first_tls_offset(size, align) \
    TLS_TCB_SIZE
#define calculate_tls_offset(prev_offset, prev_size, size, align) \
    round(prev_offset + prev_size, align)
#define calculate_tls_end(off, size)    ((off) + (size))
#define	calculate_tls_post_size(align)	0

/*
 * Lazy binding entry point, called via PLT.
 */
void _rtld_bind_start(void);
void *_mips_get_tls(void);
extern void *__tls_get_addr(tls_index *ti);

#define	RTLD_DEFAULT_STACK_PF_EXEC	PF_X
#define	RTLD_DEFAULT_STACK_EXEC		PROT_EXEC

#define md_abi_variant_hook(x)


/* Add function not used by CHERI as inlines here so that the compiler can
 * omit the call */

static inline void init_pltgot(Obj_Entry *obj __unused) { /* Do nothing */ }

static inline  int
reloc_iresolve(Obj_Entry *obj __unused, struct Struct_RtldLockState *lockstate __unused)
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

static inline Elf_Addr
reloc_jmpslot(Elf_Addr *where __unused, Elf_Addr target, const Obj_Entry *defobj __unused,
    const Obj_Entry *obj __unused, const Elf_Rel *rel __unused)
{
	_rtld_error("%s: not implemented!", __func__);
	return (target);
}

// Validating e_flags (and ABI version):
#if _MIPS_SZCAP == 128
#define _RTLD_EXPECTED_MIPS_MACH EF_MIPS_MACH_CHERI128
#else
static_assert(_MIPS_SZCAP == 256, "CHERI bits != 256?");
#define _RTLD_EXPECTED_MIPS_MACH EF_MIPS_MACH_CHERI256
#endif

#define rtld_validate_target_eflags(path, hdr, main_path)	\
	_rtld_validate_target_eflags(path, hdr, main_path)
static inline bool
_rtld_validate_target_eflags(const char* path, Elf_Ehdr *hdr, const char* main_path)
{
	if ((hdr->e_flags & EF_MIPS_MACH) != _RTLD_EXPECTED_MIPS_MACH) {
		_rtld_error("%s: cannot load %s since it is not CHERI-" __XSTRING(_MIPS_SZCAP)
		    " (e_flags=0x%zx)", main_path, path, (size_t)hdr->e_flags);
		return false;
	}
	if ((hdr->e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_CHERIABI) {
		_rtld_error("%s: cannot load %s since it is not CheriABI"
		    " (e_flags=0x%zx)", main_path, path, (size_t)hdr->e_flags);
		return false;
	}
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
	return true;
}

static inline void
fix_obj_mapping_cap_permissions(Obj_Entry *obj, const char* path __unused)
{
	obj->text_rodata_cap = (const char*)cheri_clearperm(obj->text_rodata_cap, FUNC_PTR_REMOVE_PERMS);
	obj->relocbase = (char*)cheri_clearperm(obj->relocbase, DATA_PTR_REMOVE_PERMS);
	obj->mapbase = (char*)cheri_clearperm(obj->mapbase, DATA_PTR_REMOVE_PERMS);
	dbg("%s:\n\tmapbase=%-#p\n\trelocbase=%-#p\n\ttext_rodata=%-#p", path,
	    obj->mapbase, obj->relocbase, obj->text_rodata_cap);
}

__END_DECLS


#endif
