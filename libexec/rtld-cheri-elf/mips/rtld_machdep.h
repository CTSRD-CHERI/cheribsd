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

#include <assert.h>

struct Struct_Obj_Entry;

/* Return the address of the .dynamic section in the dynamic linker. */
#define rtld_dynamic(obj) (&_DYNAMIC)

Elf_Addr reloc_jmpslot(Elf_Addr *where, Elf_Addr target,
		       const struct Struct_Obj_Entry *defobj,
		       const struct Struct_Obj_Entry *obj,
		       const Elf_Rel *rel);

#define FUNC_PTR_REMOVE_PERMS	(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |	\
	__CHERI_CAP_PERMISSION_PERMIT_STORE__ |				\
	__CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ |		\
	__CHERI_CAP_PERMISSION_PERMIT_STORE_LOCAL__)

#define DATA_PTR_REMOVE_PERMS	(__CHERI_CAP_PERMISSION_PERMIT_SEAL__ |	\
	__CHERI_CAP_PERMISSION_PERMIT_EXECUTE__)

static inline void*
make_function_pointer(const Elf_Sym* def, const struct Struct_Obj_Entry *defobj)
{
	void* ret = defobj->relocbase + def->st_value;

	/* Remove store and seal permissions */
	cheri_andperm(ret, ~FUNC_PTR_REMOVE_PERMS);
	if (defobj->restrict_pcc_strict)
		return cheri_csetbounds(ret, def->st_size);
	if (defobj->restrict_pcc_basic)
		return ret;

	/*
	 * Otherwise we need to give it full address space range (including
	 * the full permissions mask) to support legacy binaries.
	 *
	 * TODO: remove once we have decided on a sane(r) ABI
	 */
	assert(cheri_getbase(cheri_getpcc()) == 0);
	return cheri_setoffset(cheri_getpcc(), (vaddr_t)ret);
}

static inline void*
make_data_pointer(const Elf_Sym* def, const struct Struct_Obj_Entry *defobj)
{
	void* ret = defobj->relocbase + def->st_value;

	/* Remove execute and seal permissions */
	cheri_andperm(ret, ~DATA_PTR_REMOVE_PERMS);
	/* TODO: can we always set bounds here or does it break compat? */
	ret = cheri_csetbounds(ret, def->st_size);
	return ret;
}

#define call_initfini_pointer(obj, target)				\
	(((InitFunc)(target))())
/*	(((InitFunc)(cheri_setoffset(cheri_getppcc(), (target))))()) */

/*
 * XXXAR: FIXME: this should not be using cheri_getppc()/obj->relocbase, we want
 * a obj->text_segment_only or similar
 */
#define call_init_array_pointer(obj, target)				\
	(((InitArrFunc)(cheri_setoffset(cheri_getpcc(), (target))))	\
	    (main_argc, main_argv, environ))
#define call_fini_array_pointer(obj, target)				\
	(((InitArrFunc)(cheri_setoffset(cheri_getpcc(), (target))))	\
	    (main_argc, main_argv, environ))

#define	call_ifunc_resolver(ptr) \
	(((Elf_Addr (*)(void))ptr)())

typedef struct {
	unsigned long ti_module;
	unsigned long ti_offset;
} tls_index;

#define round(size, align) \
    (((size) + (align) - 1) & ~((align) - 1))
#define calculate_first_tls_offset(size, align) \
    round(TLS_TCB_SIZE, align)
#define calculate_tls_offset(prev_offset, prev_size, size, align) \
    round(prev_offset + prev_size, align)
#define calculate_tls_end(off, size)    ((off) + (size))

/*
 * Lazy binding entry point, called via PLT.
 */
void _rtld_bind_start(void);

extern void *__tls_get_addr(tls_index *ti);

#define	RTLD_DEFAULT_STACK_PF_EXEC	PF_X
#define	RTLD_DEFAULT_STACK_EXEC		PROT_EXEC

#define md_abi_variant_hook(x)

#endif
