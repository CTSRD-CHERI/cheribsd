/*-
 * Copyright (c) 2014-2015 The FreeBSD Foundation
 * Copyright 2020 Brett F. Gutstein
 * All rights reserved.
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation.
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

#include <sys/param.h>
#include <sys/mman.h>

#include <machine/sysarch.h>

#include <stdlib.h>
#include <ucontext.h>

#include "debug.h"
#include "rtld.h"
#ifdef CHERI_LIB_C18N
#include "rtld_c18n.h"
#endif
#include "rtld_printf.h"

#if __has_feature(capabilities)
#include "cheri_reloc.h"
#endif

/*
 * It is possible for the compiler to emit relocations for unaligned data.
 * We handle this situation with these inlines.
 */
#define	RELOC_ALIGNED_P(x) \
	(((uintptr_t)(x) & (sizeof(void *) - 1)) == 0)

/*
 * This is not the correct prototype, but we only need it for
 * a function pointer to a simple asm function.
 */
void *_rtld_tlsdesc_static(void *);
void *_rtld_tlsdesc_undef(void *);
void *_rtld_tlsdesc_dynamic(void *);

bool
arch_digest_dynamic(struct Struct_Obj_Entry *obj, const Elf_Dyn *dynp)
{
	if (dynp->d_tag == DT_AARCH64_VARIANT_PCS) {
		obj->variant_pcs = true;
		return (true);
	}

	return (false);
}

bool
arch_digest_note(struct Struct_Obj_Entry *obj __unused, const Elf_Note *note)
{
	const char *note_name;
	const uint32_t *note_data;

	note_name = (const char *)(note + 1);
	/* Only handle GNU notes */
	if (note->n_namesz != sizeof(ELF_NOTE_GNU) ||
	    strncmp(note_name, ELF_NOTE_GNU, sizeof(ELF_NOTE_GNU)) != 0)
		return (false);

	/* Only handle GNU property notes */
	if (note->n_type != NT_GNU_PROPERTY_TYPE_0)
		return (false);

	/*
	 * note_data[0] - Type
	 * note_data[1] - Length
	 * note_data[2] - Data
	 * note_data[3] - Padding?
	 */
	note_data = (const uint32_t *)(note_name + note->n_namesz);

	/* Only handle AArch64 feature notes */
	if (note_data[0] != GNU_PROPERTY_AARCH64_FEATURE_1_AND)
		return (false);

	/* We expect at least 4 bytes of data */
	if (note_data[1] < 4)
		return (false);

	/* TODO: Only guard if HWCAP2_BTI is set */
	if ((note_data[2] & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) != 0) {
		struct arm64_guard_page_args guard;

		guard.addr = (uintptr_t)obj->mapbase;
		guard.len = obj->mapsize;

		sysarch(ARM64_GUARD_PAGE, &guard);
	}

	return (true);
}

void
init_pltgot(Obj_Entry *obj)
{

	if (obj->pltgot != NULL) {
#ifdef CHERI_LIB_C18N
		if (C18N_ENABLED) {
#ifdef CHERI_LIB_C18N_NO_OTYPE
			obj->pltgot[2] = (uintptr_t)plt_tramp_make(obj);
#else
			obj->pltgot[1] = (uintptr_t)cheri_seal(obj,
			    sealer_pltgot);
			obj->pltgot[2] = (uintptr_t)&_rtld_bind_start_c18n;
#endif
			return;
		}
#endif
		obj->pltgot[1] = (uintptr_t)obj;
		obj->pltgot[2] = (uintptr_t)&_rtld_bind_start;
	}
}

#if __has_feature(capabilities)
/*
 * Fragments consist of a 64-bit address followed by a 56-bit length and an
 * 8-bit permission field.
 */
static uintcap_t
init_cap_from_fragment(const Elf_Addr *fragment, void * __capability data_cap,
    const void * __capability text_rodata_cap, Elf_Addr base_addr,
    Elf_Size addend)
{
	uintcap_t cap;
	Elf_Addr address, len;
	uint8_t perms;

	address = fragment[0];
	len = fragment[1] & ((1UL << (8 * sizeof(*fragment) - 8)) - 1);
	perms = fragment[1] >> (8 * sizeof(*fragment) - 8);

	cap = perms == MORELLO_FRAG_EXECUTABLE ?
	    (uintcap_t)text_rodata_cap : (uintcap_t)data_cap;
	cap = cheri_setaddress(cap, base_addr + address);
	cap = cheri_clearperm(cap, CAP_RELOC_REMOVE_PERMS);

	if (perms == MORELLO_FRAG_EXECUTABLE || perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, FUNC_PTR_REMOVE_PERMS);
	}
	if (perms == MORELLO_FRAG_RWDATA || perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, DATA_PTR_REMOVE_PERMS);
		cap = cheri_setbounds(cap, len);
	}

	cap += addend;

	if (perms == MORELLO_FRAG_EXECUTABLE) {
		/*
		 * TODO tight bounds: lower bound and len should be set
		 * with LSB == 0 for C64 code.
		 */
		cap = cheri_sealentry(cap);
	}

	return (cap);
}
#endif /* __has_feature(capabilities) */

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * Plain aarch64 can rely on PC-relative addressing early in rtld startup.
 * However, pure capability code requires capabilities from the captable for
 * function calls, and so we must perform early self-relocation before calling
 * the general _rtld C entry point.
 */
void _rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Auxinfo *aux);

void
_rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Auxinfo *aux)
{
	caddr_t relocbase = NULL;
	const Elf_Rela *rela = NULL, *relalim;
	unsigned long relasz;
	Elf_Addr *where;
	void *pcc;

	for (; aux->a_type != AT_NULL; aux++) {
		if (aux->a_type == AT_BASE) {
			relocbase = aux->a_un.a_ptr;
			break;
		}
	}

	for (; dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_RELA:
			rela = (const Elf_Rela *)(relocbase + dynp->d_un.d_ptr);
			break;
		case DT_RELASZ:
			relasz = dynp->d_un.d_val;
			break;
		}
	}

	rela = cheri_setbounds(rela, relasz);
	relalim = (const Elf_Rela *)((const char *)rela + relasz);
	pcc = __builtin_cheri_program_counter_get();

	/* Self-relocations should all be local, i.e. R_MORELLO_RELATIVE. */
	for (; rela < relalim; rela++) {
		if (ELF_R_TYPE(rela->r_info) != R_MORELLO_RELATIVE)
			__builtin_trap();

		where = (Elf_Addr *)(relocbase + rela->r_offset);
		*(uintcap_t *)where = init_cap_from_fragment(where, relocbase,
		    pcc, (Elf_Addr)(uintptr_t)relocbase, rela->r_addend);
	}
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
		if (ELF_R_TYPE(rela->r_info) != R_AARCH64_COPY)
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
			_rtld_error("Undefined symbol \"%s\" referenced from "
			    "COPY relocation in %s", name, dstobj->path);
			return (-1);
		}

		srcaddr = (const void *)(defobj->relocbase + srcsym->st_value);
		memcpy(dstaddr, srcaddr, size);
	}

	return (0);
}

struct tls_data {
	uintptr_t	dtv_gen;
	int		tls_index;
	Elf_Addr	tls_offs;
#ifdef __CHERI_PURE_CAPABILITY__
	Elf_Addr	tls_size;
#endif
};

static struct tls_data *
#ifdef __CHERI_PURE_CAPABILITY__
reloc_tlsdesc_alloc(int tlsindex, Elf_Addr tlsoffs, Elf_Addr tlssize)
#else
reloc_tlsdesc_alloc(int tlsindex, Elf_Addr tlsoffs)
#endif
{
	struct tls_data *tlsdesc;

	tlsdesc = xmalloc(sizeof(struct tls_data));
	tlsdesc->dtv_gen = tls_dtv_generation;
	tlsdesc->tls_index = tlsindex;
	tlsdesc->tls_offs = tlsoffs;
#ifdef __CHERI_PURE_CAPABILITY__
	tlsdesc->tls_size = tlssize;
#endif

	return (tlsdesc);
}

struct tlsdesc_entry {
	void	*(*func)(void *);
	union {
		Elf_Ssize	addend;
		struct {
			Elf_Size	offset;
#ifdef __CHERI_PURE_CAPABILITY__
			Elf_Size	size;
#endif
		};
		struct tls_data	*data;
	};
};

static void
reloc_tlsdesc(const Obj_Entry *obj, const Elf_Rela *rela,
    struct tlsdesc_entry *where, int flags, RtldLockState *lockstate)
{
	const Elf_Sym *def;
	const Obj_Entry *defobj;
	Elf_Addr offs;
#ifdef __CHERI_PURE_CAPABILITY__
	Elf_Addr size = where->size;
#endif

	offs = 0;
	if (ELF_R_SYM(rela->r_info) != 0) {
		def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj, flags,
			    NULL, lockstate);
		if (def == NULL)
			rtld_die();
		offs = def->st_value;
#ifdef __CHERI_PURE_CAPABILITY__
		if (size == 0)
			size = def->st_size;
#endif
		obj = defobj;
		if (def->st_shndx == SHN_UNDEF) {
			/* Weak undefined thread variable */
#ifdef CHERI_LIB_C18N
			if (C18N_ENABLED)
				where->func = _rtld_tlsdesc_undef_c18n;
			else
#endif
				where->func = _rtld_tlsdesc_undef;
			where->addend = rela->r_addend;
			return;
		}
	}
	offs += rela->r_addend;

	if (obj->tlsoffset != 0) {
		/* Variable is in initially allocated TLS segment */
#ifdef CHERI_LIB_C18N
		if (C18N_ENABLED)
			where->func = _rtld_tlsdesc_static_c18n;
		else
#endif
			where->func = _rtld_tlsdesc_static;
		where->offset = obj->tlsoffset + offs;
#ifdef __CHERI_PURE_CAPABILITY__
		where->size = size;
#endif
	} else {
		/* TLS offset is unknown at load time, use dynamic resolving */
#ifdef CHERI_LIB_C18N
		if (C18N_ENABLED)
			where->func = _rtld_tlsdesc_dynamic_c18n;
		else
#endif
			where->func = _rtld_tlsdesc_dynamic;
#ifdef __CHERI_PURE_CAPABILITY__
		where->data = reloc_tlsdesc_alloc(obj->tlsindex, offs, size);
#else
		where->data = reloc_tlsdesc_alloc(obj->tlsindex, offs);
#endif
	}
}

/*
 * Process the PLT relocations.
 */
int
reloc_plt(Obj_Entry *obj, int flags, RtldLockState *lockstate)
{
	const Obj_Entry *defobj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	const Elf_Sym *def, *sym;
#ifdef __CHERI_PURE_CAPABILITY__
	uintptr_t jump_slot_base;
#endif
	bool lazy;

	relalim = (const Elf_Rela *)((const char *)obj->pltrela +
	    obj->pltrelasize);
#ifdef __CHERI_PURE_CAPABILITY__
	jump_slot_base = (uintptr_t)cheri_clearperm(obj->text_rodata_cap,
	    FUNC_PTR_REMOVE_PERMS);
#endif
	for (rela = obj->pltrela; rela < relalim; rela++) {
		uintptr_t *where, target;
#ifdef __CHERI_PURE_CAPABILITY__
		Elf_Addr *fragment;
#endif

		where = (uintptr_t *)(obj->relocbase + rela->r_offset);
#ifdef __CHERI_PURE_CAPABILITY__
		fragment = (Elf_Addr *)where;
#endif

		switch(ELF_R_TYPE(rela->r_info)) {
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_JUMP_SLOT:
#else
		case R_AARCH64_JUMP_SLOT:
#endif
			lazy = true;
			if (obj->variant_pcs) {
				sym = &obj->symtab[ELF_R_SYM(rela->r_info)];
				/*
				 * Variant PCS functions don't follow the
				 * standard register convention. Because of
				 * this we can't use lazy relocation and
				 * need to set the target address.
				 */
				if ((sym->st_other & STO_AARCH64_VARIANT_PCS) !=
				    0)
					lazy = false;
			}
			if (lazy) {
#ifdef __CHERI_PURE_CAPABILITY__
				/*
				 * Old ABI:
				 *   - Treat as R_AARCH64_JUMP_SLOT
				 *
				 * New ABI:
				 *   - Same representation as
				 *     R_MORELLO_RELATIVE
				 *
				 * Determine which this is based on
				 * whether there's non-zero metadata
				 * next to the address. Remove once
				 * the new ABI is old enough that we
				 * can assume it is in use.
				 */
				if (fragment[1] == 0)
					*where = cheri_sealentry(
					    jump_slot_base + fragment[0]);
				else
					*where = init_cap_from_fragment(
					    fragment, obj->relocbase,
					    obj->text_rodata_cap,
					    (Elf_Addr)(uintptr_t)obj->relocbase,
					    rela->r_addend);
#else
				*where += (Elf_Addr)obj->relocbase;
#endif
			} else {
				def = find_symdef(ELF_R_SYM(rela->r_info), obj,
				    &defobj, SYMLOOK_IN_PLT | flags, NULL,
				    lockstate);
				if (def == NULL)
					return (-1);
				if (ELF_ST_TYPE(def->st_info) == STT_GNU_IFUNC){
					obj->gnu_ifunc = true;
					continue;
				}
				target = (uintptr_t)make_function_pointer(def,
				    defobj);
#ifdef CHERI_LIB_C18N
				target = (uintptr_t)tramp_intern(obj,
				    &(struct tramp_data) {
					.target = (void *)target,
					.defobj = defobj,
					.def = def,
					.sig = sigtab_get(obj,
					    ELF_R_SYM(rela->r_info))
				    });
#endif
				/*
				 * Ignore ld_bind_not as it requires lazy
				 * binding
				 */
				*where = target;
			}
			break;
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_TLSDESC:
#else
		case R_AARCH64_TLSDESC:
#endif
			reloc_tlsdesc(obj, rela, (struct tlsdesc_entry *)where,
			    SYMLOOK_IN_PLT | flags, lockstate);
			break;
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_IRELATIVE:
#else
		case R_AARCH64_IRELATIVE:
#endif
			obj->irelative = true;
			break;
		case R_AARCH64_NONE:
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
reloc_jmpslots(Obj_Entry *obj, int flags, RtldLockState *lockstate)
{
	const Obj_Entry *defobj;
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	const Elf_Sym *def;

	if (obj->jmpslots_done)
		return (0);

	relalim = (const Elf_Rela *)((const char *)obj->pltrela +
	    obj->pltrelasize);
	for (rela = obj->pltrela; rela < relalim; rela++) {
		uintptr_t *where, target;

		where = (uintptr_t *)(obj->relocbase + rela->r_offset);
		switch(ELF_R_TYPE(rela->r_info)) {
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_JUMP_SLOT:
#else
		case R_AARCH64_JUMP_SLOT:
#endif
			def = find_symdef(ELF_R_SYM(rela->r_info), obj,
			    &defobj, SYMLOOK_IN_PLT | flags, NULL, lockstate);
			if (def == NULL)
				return (-1);
			if (ELF_ST_TYPE(def->st_info) == STT_GNU_IFUNC) {
				obj->gnu_ifunc = true;
				continue;
			}
			target = (uintptr_t)make_function_pointer(def, defobj);
#ifdef CHERI_LIB_C18N
			target = (uintptr_t)tramp_intern(obj, &(struct tramp_data) {
				.target = (void *)target,
				.defobj = defobj,
				.def = def,
				.sig = sigtab_get(obj, ELF_R_SYM(rela->r_info))
			});
#endif
			reloc_jmpslot(where, target, defobj, obj,
			    (const Elf_Rel *)rela);
			break;
		}
	}
	obj->jmpslots_done = true;

	return (0);
}

static void
reloc_iresolve_one(Obj_Entry *obj, const Elf_Rela *rela,
    RtldLockState *lockstate)
{
	uintptr_t *where, target, ptr;
#ifdef __CHERI_PURE_CAPABILITY__
	Elf_Addr *fragment;
#endif

	where = (uintptr_t *)(obj->relocbase + rela->r_offset);
#ifdef __CHERI_PURE_CAPABILITY__
	fragment = (Elf_Addr *)where;
	/*
	 * XXX: Morello LLVM commit 94e1dbac broke R_MORELLO_IRELATIVE ABI.
	 * This horrible hack exists to support both old and new ABIs.
	 *
	 * Old ABI:
	 *   - Treat as R_AARCH64_IRELATIVE (addend is symbol value)
	 *   - Fragment contents either all zero (for ET_DYN) or base set to
	 *     the addend and length set to the symbol size (which we don't
	 *     have to hand).
	 *
	 * New ABI:
	 *   - Same representation as R_MORELLO_RELATIVE
	 *
	 * Thus, probe for something that looks like the old ABI and hope
	 * that's reliable enough until the commit is old enough that we can
	 * assume the new ABI and ditch this.
	 *
	 * See also: lib/csu/aarch64c/reloc.c and sys/arm64/arm64/elf_machdep.c
	 */
	if ((fragment[0] == 0 && fragment[1] == 0) ||
	    (Elf_Ssize)fragment[0] == rela->r_addend)
		ptr = (uintptr_t)(obj->text_rodata_cap + (rela->r_addend -
		    (obj->text_rodata_cap - obj->relocbase)));
	else
		ptr = init_cap_from_fragment(fragment, obj->relocbase,
		    obj->text_rodata_cap,
		    (Elf_Addr)(uintptr_t)obj->relocbase,
		    rela->r_addend);
#else
	ptr = (uintptr_t)(obj->relocbase + rela->r_addend);
#endif
	lock_release(rtld_bind_lock, lockstate);
#ifdef CHERI_LIB_C18N
	ptr = (uintptr_t)tramp_intern(NULL, &(struct tramp_data) {
		.target = (void *)ptr,
		.defobj = obj,
		.sig = (struct func_sig) { .valid = true,
		    .reg_args = 8, .mem_args = false, .ret_args = ONE }
	});
#endif
	target = call_ifunc_resolver(ptr);
	wlock_acquire(rtld_bind_lock, lockstate);
	*where = target;
}

int
reloc_iresolve(Obj_Entry *obj, struct Struct_RtldLockState *lockstate)
{
	const Elf_Rela *relalim;
	const Elf_Rela *rela;

	if (!obj->irelative)
		return (0);
	obj->irelative = false;
	relalim = (const Elf_Rela *)((const char *)obj->pltrela +
	    obj->pltrelasize);
	for (rela = obj->pltrela;  rela < relalim;  rela++) {
		switch (ELF_R_TYPE(rela->r_info)) {
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_IRELATIVE:
#else
		case R_AARCH64_IRELATIVE:
#endif
			reloc_iresolve_one(obj, rela, lockstate);
			break;
		}
	}
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
	for (rela = obj->rela;  rela < relalim;  rela++) {
		switch (ELF_R_TYPE(rela->r_info)) {
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_IRELATIVE:
#else
		case R_AARCH64_IRELATIVE:
#endif
			reloc_iresolve_one(obj, rela, lockstate);
			break;
		}
	}
	return (0);
}

int
reloc_gnu_ifunc(Obj_Entry *obj, int flags,
   struct Struct_RtldLockState *lockstate)
{
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
	uintptr_t *where, target;
	const Elf_Sym *def;
	const Obj_Entry *defobj;

	if (!obj->gnu_ifunc)
		return (0);
	relalim = (const Elf_Rela *)((const char *)obj->pltrela + obj->pltrelasize);
	for (rela = obj->pltrela;  rela < relalim;  rela++) {
		where = (uintptr_t *)(obj->relocbase + rela->r_offset);
		switch (ELF_R_TYPE(rela->r_info)) {
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_JUMP_SLOT:
#else
		case R_AARCH64_JUMP_SLOT:
#endif
			def = find_symdef(ELF_R_SYM(rela->r_info), obj, &defobj,
			    SYMLOOK_IN_PLT | flags, NULL, lockstate);
			if (def == NULL)
				return (-1);
			if (ELF_ST_TYPE(def->st_info) != STT_GNU_IFUNC)
				continue;
			lock_release(rtld_bind_lock, lockstate);
			target = (uintptr_t)rtld_resolve_ifunc(defobj, def);
#ifdef CHERI_LIB_C18N
			target = (uintptr_t)tramp_intern(obj, &(struct tramp_data) {
				.target = (void *)target,
				.defobj = defobj,
				.def = def,
				.sig = sigtab_get(obj, ELF_R_SYM(rela->r_info))
			});
#endif
			wlock_acquire(rtld_bind_lock, lockstate);
			reloc_jmpslot(where, target, defobj, obj,
			    (const Elf_Rel *)rela);
		}
	}
	obj->gnu_ifunc = false;
	return (0);
}

uintptr_t
reloc_jmpslot(uintptr_t *where, uintptr_t target,
    const Obj_Entry *defobj __unused, const Obj_Entry *obj __unused,
    const Elf_Rel *rel)
{

#ifdef __CHERI_PURE_CAPABILITY__
	assert(ELF_R_TYPE(rel->r_info) == R_MORELLO_JUMP_SLOT ||
	    ELF_R_TYPE(rel->r_info) == R_MORELLO_IRELATIVE);
#else
	assert(ELF_R_TYPE(rel->r_info) == R_AARCH64_JUMP_SLOT ||
	    ELF_R_TYPE(rel->r_info) == R_AARCH64_IRELATIVE);
#endif

	if (*where != target && !ld_bind_not)
		*where = target;
	return (target);
}

void
ifunc_init(Elf_Auxinfo aux_info[__min_size(AT_COUNT)] __unused)
{

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
#if __has_feature(capabilities)
	void * __capability data_cap;
	const void * __capability text_rodata_cap;
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * The dynamic linker should only have R_MORELLO_RELATIVE (local)
	 * relocations, which were processed in _rtld_relocate_nonplt_self.
	 */
	if (obj == obj_rtld)
		return (0);
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	data_cap = obj->relocbase;
	text_rodata_cap = obj->text_rodata_cap;
#elif __has_feature(capabilities)
	data_cap = cheri_getdefault();
	text_rodata_cap = cheri_getpcc();
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
		/*
		 * First, resolve symbol for relocations which
		 * reference symbols.
		 */
		switch (ELF_R_TYPE(rela->r_info)) {
		case R_AARCH64_ABS64:
		case R_AARCH64_GLOB_DAT:
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_TLS_TPREL128:
#else
		case R_AARCH64_TLS_TPREL64:
		case R_AARCH64_TLS_DTPREL64:
		case R_AARCH64_TLS_DTPMOD64:
#endif
			def = find_symdef(ELF_R_SYM(rela->r_info), obj,
			    &defobj, flags, cache, lockstate);
			if (def == NULL)
				return (-1);
			/*
			 * If symbol is IFUNC, only perform relocation
			 * when caller allowed it by passing
			 * SYMLOOK_IFUNC flag.  Skip the relocations
			 * otherwise.
			 *
			 * Also error out in case IFUNC relocations
			 * are specified for TLS, which cannot be
			 * usefully interpreted.
			 */
			if (ELF_ST_TYPE(def->st_info) == STT_GNU_IFUNC) {
				switch (ELF_R_TYPE(rela->r_info)) {
				case R_AARCH64_ABS64:
				case R_AARCH64_GLOB_DAT:
					if ((flags & SYMLOOK_IFUNC) == 0) {
						obj->non_plt_gnu_ifunc = true;
						continue;
					}
					symval = (Elf_Addr)rtld_resolve_ifunc(
					    defobj, def);
					break;
				default:
					_rtld_error("%s: IFUNC for TLS reloc",
					    obj->path);
					return (-1);
				}
			} else {
				if ((flags & SYMLOOK_IFUNC) != 0)
					continue;
				symval = (Elf_Addr)defobj->relocbase +
				    def->st_value;
			}
			break;
		default:
			if ((flags & SYMLOOK_IFUNC) != 0)
				continue;
		}

		where = (Elf_Addr *)(obj->relocbase + rela->r_offset);

		switch (ELF_R_TYPE(rela->r_info)) {
#if __has_feature(capabilities)
		/*
		 * XXXBFG According to the spec, for R_MORELLO_CAPINIT there
		 * *can* be a fragment containing extra information for the
		 * symbol. How does this interact with symbol table
		 * information?
		 */
		case R_MORELLO_CAPINIT:
		case R_MORELLO_GLOB_DAT:
			if (process_r_cheri_capability(obj,
			    ELF_R_SYM(rela->r_info), lockstate, flags,
			    where, rela->r_addend) != 0)
				return (-1);
			break;
		case R_MORELLO_RELATIVE:
			*(uintcap_t *)(void *)where =
			    init_cap_from_fragment(where, data_cap,
				text_rodata_cap,
				(Elf_Addr)(uintptr_t)obj->relocbase,
				rela->r_addend);
			break;
#endif /* __has_feature(capabilities) */
		case R_AARCH64_ABS64:
		case R_AARCH64_GLOB_DAT:
			*where = symval + rela->r_addend;
			break;
		case R_AARCH64_COPY:
			/*
			 * These are deferred until all other relocations have
			 * been done. All we do here is make sure that the
			 * COPY relocation is not in a shared library. They
			 * are allowed only in executable files.
			 */
			if (!obj->mainprog) {
				_rtld_error("%s: Unexpected R_AARCH64_COPY "
				    "relocation in shared library", obj->path);
				return (-1);
			}
			break;
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_TLSDESC:
#else
		case R_AARCH64_TLSDESC:
#endif
			reloc_tlsdesc(obj, rela, (struct tlsdesc_entry *)where,
			    flags, lockstate);
			break;
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_TLS_TPREL128:
#else
		case R_AARCH64_TLS_TPREL64:
#endif
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
			where[0] = def->st_value + rela->r_addend +
			    defobj->tlsoffset;
#ifdef __CHERI_PURE_CAPABILITY__
			if (where[1] == 0)
				where[1] = def->st_size;
#endif
			break;

#ifndef __CHERI_PURE_CAPABILITY__
		/*
		 * !!! BEWARE !!!
		 * ARM ELF ABI defines TLS_DTPMOD64 as 1029, and TLS_DTPREL64
		 * as 1028. But actual bfd linker and the glibc RTLD linker
		 * treats TLS_DTPMOD64 as 1028 and TLS_DTPREL64 1029.
		 */
		case R_AARCH64_TLS_DTPREL64: /* efectively is TLS_DTPMOD64 */
			*where += (Elf_Addr)defobj->tlsindex;
			break;
		case R_AARCH64_TLS_DTPMOD64: /* efectively is TLS_DTPREL64 */
			*where += (Elf_Addr)(def->st_value + rela->r_addend);
			break;
#endif
		case R_AARCH64_RELATIVE:
			*where = (Elf_Addr)(obj->relocbase + rela->r_addend);
			break;
		case R_AARCH64_NONE:
			break;
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_IRELATIVE:
#else
		case R_AARCH64_IRELATIVE:
#endif
			obj->irelative_nonplt = true;
			break;
		default:
			rtld_printf("%s: Unhandled relocation %lu\n",
			    obj->path, ELF_R_TYPE(rela->r_info));
			return (-1);
		}
	}

	return (0);
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
	uintptr_t **dtvp;

	dtvp = &_tcb_get()->tcb_dtv;
	return (tls_get_addr_common(dtvp, ti->ti_module, ti->ti_offset));
}
