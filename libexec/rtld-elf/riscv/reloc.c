/*-
 * Copyright (c) 2015-2017 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CTSRD Project, with support from the UK Higher
 * Education Innovation Fund (HEIF).
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

#include <sys/types.h>

#include <stdlib.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_printf.h"

#ifdef __CHERI_PURE_CAPABILITY__
#include "cheri_reloc.h"
#endif

/*
 * It is possible for the compiler to emit relocations for unaligned data.
 * We handle this situation with these inlines.
 */
#define	RELOC_ALIGNED_P(x) \
	(((uintptr_t)(x) & (sizeof(void *) - 1)) == 0)

#ifndef __CHERI_PURE_CAPABILITY__
uint64_t
set_gp(Obj_Entry *obj)
{
	uint64_t old;
	SymLook req;
	uint64_t gp;
	int res;

	__asm __volatile("mv    %0, gp" : "=r"(old));

	symlook_init(&req, "__global_pointer$");
	req.ventry = NULL;
	req.flags = SYMLOOK_EARLY;
	res = symlook_obj(&req, obj);

	if (res == 0) {
		gp = req.sym_out->st_value;
		__asm __volatile("mv    gp, %0" :: "r"(gp));
	}

	return (old);
}
#endif

void
init_pltgot(Plt_Entry *plt)
{

	if (plt->pltgot != NULL) {
		plt->pltgot[0] = (uintptr_t)&_rtld_bind_start;
		plt->pltgot[1] = (uintptr_t)plt;
	}
}

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * Plain RISC-V can rely on PC-relative addressing early in rtld startup.
 * However, pure capability code requires capabilities from the captable for
 * function calls, and so we must perform early self-relocation before calling
 * the general _rtld C entry point.
 *
 * TODO: For now we use __cap_relocs. Instead we should use normal ELF
 *       relocations that are all assumed to be relative capability
 *       relocations, ditching the ad-hoc __cap_relocs format and using
 *       CBuildCap.
 */
void _rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Auxinfo *aux);

void
_rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Auxinfo *aux)
{
	caddr_t relocbase = NULL;
	const struct capreloc *caprelocs = NULL, *caprelocslim;
	Elf_Addr caprelocssz = 0;
	void *pcc;

	for (; aux->a_type != AT_NULL; aux++) {
		if (aux->a_type == AT_BASE) {
			relocbase = aux->a_un.a_ptr;
			break;
		}
	}

	for (; dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_RISCV_CHERI___CAPRELOCS:
			caprelocs = (const struct capreloc *)(relocbase + dynp->d_un.d_ptr);
			break;
		case DT_RISCV_CHERI___CAPRELOCSSZ:
			caprelocssz = dynp->d_un.d_val;
			break;
		}
	}
	caprelocs = cheri_setbounds(caprelocs, caprelocssz);
	caprelocslim = (const struct capreloc *)((const char *)caprelocs + caprelocssz);
	pcc = __builtin_cheri_program_counter_get();
	/* TODO: allow using tight bounds for RTLD */
	cheri_init_globals_impl(caprelocs, caprelocslim,
	    /*data_cap=*/relocbase, /*code_cap=*/pcc, /*rodata_cap=*/pcc,
	    /*tight_code_bounds=*/false, (Elf_Addr)relocbase);
}
#endif /* __CHERI_PURE_CAPABILITY__ */

int
do_copy_relocations(Obj_Entry *dstobj)
{
	const Obj_Entry *srcobj, *defobj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	const Elf_Sym *srcsym;
	const Elf_Sym *dstsym;
	const void *srcaddr;
	const char *name;
	void *dstaddr;
	SymLook req;
	size_t size;
	int res;

	/*
	 * COPY relocs are invalid outside of the main program
	 */
	assert(dstobj->mainprog);

	relalim = (const Elf_Rela *)((const char *)dstobj->rela +
	    dstobj->relasize);
	for (rela = dstobj->rela; rela < relalim; rela++) {
		if (ELF_R_TYPE(rela->r_info) != R_RISCV_COPY)
			continue;

		dstaddr = (void *)(dstobj->relocbase + rela->r_offset);
		dstsym = dstobj->symtab + ELF_R_SYM(rela->r_info);
		name = dstobj->strtab + dstsym->st_name;
		size = dstsym->st_size;

		symlook_init(&req, name);
		req.ventry = fetch_ventry(dstobj, ELF_R_SYM(rela->r_info));
		req.flags = SYMLOOK_EARLY;

		for (srcobj = globallist_next(dstobj); srcobj != NULL;
		     srcobj = globallist_next(srcobj)) {
			res = symlook_obj(&req, srcobj);
			if (res == 0) {
				srcsym = req.sym_out;
				defobj = req.defobj_out;
				break;
			}
		}
		if (srcobj == NULL) {
			_rtld_error(
"Undefined symbol \"%s\" referenced from COPY relocation in %s",
			    name, dstobj->path);
			return (-1);
		}

		srcaddr = (const void *)(defobj->relocbase + srcsym->st_value);
		memcpy(dstaddr, srcaddr, size);
	}

	return (0);
}

/*
 * Process the PLT relocations.
 */
int
reloc_plt(Plt_Entry *plt, int flags __unused, RtldLockState *lockstate __unused)
{
	Obj_Entry *obj = plt->obj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;

	relalim = (const Elf_Rela *)((const char *)plt->rela +
	    plt->relasize);
	for (rela = plt->rela; rela < relalim; rela++) {
		uintptr_t *where;

		where = (uintptr_t *)(obj->relocbase + rela->r_offset);

		switch (ELF_R_TYPE(rela->r_info)) {
		case R_RISCV_JUMP_SLOT:
#ifdef __CHERI_PURE_CAPABILITY__
			/* Relocated by __cap_relocs for CHERI */
			(void)where;
#else
			*where += (Elf_Addr)obj->relocbase;
#endif
			break;
		case R_RISCV_IRELATIVE:
			obj->irelative = true;
			break;
		default:
			_rtld_error("Unknown relocation type %u in PLT",
			    (unsigned int)ELF_R_TYPE(rela->r_info));
			return (-1);
		}
	}

	return (0);
}

/*
 * LD_BIND_NOW was set - force relocation for all jump slots
 */
int
reloc_jmpslots(Plt_Entry *plt, int flags, RtldLockState *lockstate)
{
	Obj_Entry *obj = plt->obj;
	const Obj_Entry *defobj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	const Elf_Sym *def;

	relalim = (const Elf_Rela *)((const char *)plt->rela +
	    plt->relasize);
	for (rela = plt->rela; rela < relalim; rela++) {
		uintptr_t *where;

		where = (uintptr_t *)(obj->relocbase + rela->r_offset);
		switch(ELF_R_TYPE(rela->r_info)) {
		case R_RISCV_JUMP_SLOT:
			def = find_symdef(ELF_R_SYM(rela->r_info), obj,
			    &defobj, SYMLOOK_IN_PLT | flags, NULL, lockstate);
			if (def == NULL) {
				dbg("reloc_jmpslots: sym not found");
				return (-1);
			}

			if (ELF_ST_TYPE(def->st_info) == STT_GNU_IFUNC) {
				obj->gnu_ifunc = true;
				continue;
			}

			*where = (uintptr_t)make_function_pointer(def, defobj);
			break;
		default:
			_rtld_error("Unknown relocation type %x in jmpslot",
			    (unsigned int)ELF_R_TYPE(rela->r_info));
			return (-1);
		}
	}

	return (0);
}

static void
reloc_iresolve_one(Obj_Entry *obj, const Elf_Rela *rela,
    RtldLockState *lockstate)
{
	Elf_Addr *where, target, *ptr;

	ptr = (Elf_Addr *)(obj->relocbase + rela->r_addend);
	where = (Elf_Addr *)(obj->relocbase + rela->r_offset);
	lock_release(rtld_bind_lock, lockstate);
	target = call_ifunc_resolver(ptr);
	wlock_acquire(rtld_bind_lock, lockstate);
	*where = target;
}

static void
reloc_iresolve_plt(Plt_Entry *plt, struct Struct_RtldLockState *lockstate)
{
	const Elf_Rela *relalim;
	const Elf_Rela *rela;

	relalim = (const Elf_Rela *)((const char *)plt->rela + plt->relasize);
	for (rela = plt->rela; rela < relalim; rela++) {
		if (ELF_R_TYPE(rela->r_info) == R_RISCV_IRELATIVE)
			reloc_iresolve_one(plt->obj, rela, lockstate);
	}
}

int
reloc_iresolve(Obj_Entry *obj, struct Struct_RtldLockState *lockstate)
{
	unsigned long i;

	if (!obj->irelative)
		return (0);

	obj->irelative = false;
	for (i = 0; i < obj->nplts; i++)
		reloc_iresolve_plt(&obj->plts[i], lockstate);
	return (0);
}

int
reloc_iresolve_nonplt(Obj_Entry *obj, struct Struct_RtldLockState *lockstate)
{
	const Elf_Rela *relalim;
	const Elf_Rela *rela;

	if (!obj->irelative_nonplt)
		return (0);

	obj->irelative_nonplt = false;
	relalim = (const Elf_Rela *)((const char *)obj->rela + obj->relasize);
	for (rela = obj->rela; rela < relalim; rela++) {
		if (ELF_R_TYPE(rela->r_info) == R_RISCV_IRELATIVE)
			reloc_iresolve_one(obj, rela, lockstate);
	}
	return (0);
}

static bool
reloc_gnu_ifunc_plt(Plt_Entry *plt, int flags, RtldLockState *lockstate)
{
	Obj_Entry *obj = plt->obj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	uintptr_t *where, target;
	const Elf_Sym *def;
	const Obj_Entry *defobj;

	relalim = (const Elf_Rela *)((const char *)plt->rela + plt->relasize);
	for (rela = plt->rela; rela < relalim; rela++) {
		if (ELF_R_TYPE(rela->r_info) == R_RISCV_JUMP_SLOT) {
			where = (uintptr_t *)(obj->relocbase + rela->r_offset);
			def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
			    SYMLOOK_IN_PLT | flags, NULL, lockstate);
			if (def == NULL)
				return (false);
			if (ELF_ST_TYPE(def->st_info) != STT_GNU_IFUNC)
				continue;

			lock_release(rtld_bind_lock, lockstate);
			target = (Elf_Addr)rtld_resolve_ifunc(defobj, def);
			wlock_acquire(rtld_bind_lock, lockstate);
			reloc_jmpslot(where, target, defobj, obj,
			    (const Elf_Rel *)rela);
		}
	}
	return (true);
}

int
reloc_gnu_ifunc(Obj_Entry *obj, int flags,
   struct Struct_RtldLockState *lockstate)
{
	unsigned long i;

	if (!obj->gnu_ifunc)
		return (0);
	for (i = 0; i < obj->nplts; i++)
		if (!reloc_gnu_ifunc_plt(&obj->plts[i], flags, lockstate))
			return (-1);
	obj->gnu_ifunc = false;
	return (0);
}

uintptr_t
reloc_jmpslot(uintptr_t *where, uintptr_t target,
    const Obj_Entry *defobj __unused, const Obj_Entry *obj __unused,
    const Elf_Rel *rel)
{

	assert(ELF_R_TYPE(rel->r_info) == R_RISCV_JUMP_SLOT ||
	    ELF_R_TYPE(rel->r_info) == R_RISCV_IRELATIVE);

	if (*where != target && !ld_bind_not)
		*where = target;
	return (target);
}

/*
 * Process non-PLT relocations
 */
int
reloc_non_plt(Obj_Entry *obj, Obj_Entry *obj_rtld, int flags,
    RtldLockState *lockstate)
{
	const Obj_Entry *defobj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	const Elf_Sym *def;
	SymCache *cache;
	Elf_Addr *where, symval;
	unsigned long symnum;

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * The __cap_relocs for the dynamic loader have already been done, and
	 * there should be no normal ELF relocations.
	 */
	if (obj == obj_rtld) {
		assert(obj->relasize == 0);
		return (0);
	}
#endif

	/*
	 * The dynamic loader may be called from a thread, we have
	 * limited amounts of stack available so we cannot use alloca().
	 */
	if (obj == obj_rtld)
		cache = NULL;
	else
		cache = calloc(obj->dynsymcount, sizeof(SymCache));
		/* No need to check for NULL here */

	relalim = (const Elf_Rela *)((const char *)obj->rela + obj->relasize);
	for (rela = obj->rela; rela < relalim; rela++) {
		where = (Elf_Addr *)(obj->relocbase + rela->r_offset);
		symnum = ELF_R_SYM(rela->r_info);

		switch (ELF_R_TYPE(rela->r_info)) {
		case R_RISCV_JUMP_SLOT:
			/* This will be handled by the plt/jmpslot routines */
			break;
		case R_RISCV_NONE:
			break;
		case R_RISCV_64:
			def = find_symdef(symnum, obj, &defobj, flags, cache,
			    lockstate);
			if (def == NULL)
				return (-1);

			/*
			 * If symbol is IFUNC, only perform relocation
			 * when caller allowed it by passing
			 * SYMLOOK_IFUNC flag.  Skip the relocations
			 * otherwise.
			 */
			if (ELF_ST_TYPE(def->st_info) == STT_GNU_IFUNC) {
				if ((flags & SYMLOOK_IFUNC) == 0) {
					obj->non_plt_gnu_ifunc = true;
					continue;
				}
				symval = (Elf_Addr)rtld_resolve_ifunc(defobj,
				    def);
			} else {
				if ((flags & SYMLOOK_IFUNC) != 0)
					continue;
				symval = (Elf_Addr)(defobj->relocbase +
				    def->st_value);
			}

			*where = symval + rela->r_addend;
			break;
		case R_RISCV_TLS_DTPMOD64:
			def = find_symdef(symnum, obj, &defobj, flags, cache,
			    lockstate);
			if (def == NULL)
				return -1;

			*where += (Elf_Addr)defobj->tlsindex;
			break;
		case R_RISCV_COPY:
			/*
			 * These are deferred until all other relocations have
			 * been done. All we do here is make sure that the
			 * COPY relocation is not in a shared library. They
			 * are allowed only in executable files.
			 */
			if (!obj->mainprog) {
				_rtld_error("%s: Unexpected R_RISCV_COPY "
				    "relocation in shared library", obj->path);
				return (-1);
			}
			break;
		case R_RISCV_TLS_DTPREL64:
			def = find_symdef(symnum, obj, &defobj, flags, cache,
			    lockstate);
			if (def == NULL)
				return (-1);

			*where += (Elf_Addr)(def->st_value + rela->r_addend
			    - TLS_DTV_OFFSET);
			break;
		case R_RISCV_TLS_TPREL64:
			def = find_symdef(symnum, obj, &defobj, flags, cache,
			    lockstate);
			if (def == NULL)
				return (-1);

			/*
			 * We lazily allocate offsets for static TLS as we
			 * see the first relocation that references the
			 * TLS block. This allows us to support (small
			 * amounts of) static TLS in dynamically loaded
			 * modules. If we run out of space, we generate an
			 * error.
			 */
			if (!defobj->tls_static) {
				if (!allocate_tls_offset(
				    __DECONST(Obj_Entry *, defobj))) {
					_rtld_error(
					    "%s: No space available for static "
					    "Thread Local Storage", obj->path);
					return (-1);
				}
			}

			*where = (def->st_value + rela->r_addend +
			    defobj->tlsoffset - TLS_TP_OFFSET - TLS_TCB_SIZE);
			break;
		case R_RISCV_RELATIVE:
			*where = (Elf_Addr)(obj->relocbase + rela->r_addend);
			break;
		case R_RISCV_IRELATIVE:
			obj->irelative_nonplt = true;
			break;
#ifdef __CHERI_PURE_CAPABILITY__
		case R_RISCV_CHERI_CAPABILITY:
			if (process_r_cheri_capability(obj, symnum, lockstate,
			    flags, where, rela->r_addend) != 0)
				return (-1);
			break;
#endif /* __CHERI_PURE_CAPABILITY__ */
		default:
			rtld_printf("%s: Unhandled relocation %lu\n",
			    obj->path, ELF_R_TYPE(rela->r_info));
			return (-1);
		}
	}

	return (0);
}

unsigned long elf_hwcap;

void
ifunc_init(Elf_Auxinfo *aux_info[__min_size(AT_COUNT)])
{
	if (aux_info[AT_HWCAP] != NULL)
		elf_hwcap = aux_info[AT_HWCAP]->a_un.a_val;
}

void
allocate_initial_tls(Obj_Entry *objs)
{

	/*
	 * Fix the size of the static TLS block by using the maximum
	 * offset allocated so far and adding a bit for dynamic modules to
	 * use.
	 */
	tls_static_space = tls_last_offset + tls_last_size +
	    ld_static_tls_extra;

	_tcb_set(allocate_tls(objs, NULL, TLS_TCB_SIZE, TLS_TCB_ALIGN));
}

void *
__tls_get_addr(tls_index* ti)
{
	return (tls_get_addr_common(_tcb_get(), ti->ti_module, ti->ti_offset +
	    TLS_DTV_OFFSET));
}
