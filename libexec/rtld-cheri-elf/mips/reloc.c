/*	$NetBSD: mips_reloc.c,v 1.58 2010/01/14 11:57:06 skrll Exp $	*/

/*
 * Copyright 1997 Michael L. Hitch <mhitch@montana.edu>
 * Portions copyright 2002 Charles M. Hannum <root@ihack.net>
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/endian.h>

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <cheri/cheric.h>

#include <machine/sysarch.h>
#include <machine/tls.h>

#include "debug.h"
#include "rtld.h"

#include <cheri_init_globals.h>

#define	GOT1_MASK	0x8000000000000000UL

/*
 * Determine if the second GOT entry is reserved for rtld or if it is
 * the first "real" GOT entry.
 *
 * This must be a macro rather than a function so that
 * _rtld_relocate_nonplt_self doesn't trigger a GOT invocation trying
 * to use it before the local GOT entries in rtld are adjusted.
 */
/* Old binutils uses the 32-bit GOT1 mask value for N64. */
#define GOT1_RESERVED_FOR_RTLD(got)					\
	(((got)[1] == 0x80000000) || (got)[1] & GOT1_MASK)

void
init_pltgot(Obj_Entry *obj)
{
	if (obj->pltgot != NULL) {
		obj->pltgot[0] = (Elf_Addr) &_rtld_bind_start;
		if (GOT1_RESERVED_FOR_RTLD(obj->pltgot))
			obj->pltgot[1] = (Elf_Addr) obj | GOT1_MASK;
	}
}

int
do_copy_relocations(Obj_Entry *dstobj)
{
	/* Do nothing */
	return 0;
}

void _rtld_relocate_nonplt_self(Elf_Dyn *, caddr_t);

/*
 * It is possible for the compiler to emit relocations for unaligned data.
 * We handle this situation with these inlines.
 */
/*
 * ELF64 MIPS encodes the relocs uniquely.  The first 32-bits of info contain
 * the symbol index.  The top 32-bits contain three relocation types encoded
 * in big-endian integer with first relocation in LSB.  This means for little
 * endian we have to byte swap that integer (r_type).
 */
#define	Elf_Sxword			Elf64_Sxword
#define	ELF_R_NXTTYPE_64_P(r_type)	((((r_type) >> 8) & 0xff) == R_TYPE(64))
#if BYTE_ORDER == LITTLE_ENDIAN
#undef ELF_R_SYM
#undef ELF_R_TYPE
#define ELF_R_SYM(r_info)		((r_info) & 0xffffffff)
#define ELF_R_TYPE(r_info)		bswap32((r_info) >> 32)
#endif

static __inline __always_inline Elf_Sxword
load_ptr(void *where, size_t len)
{
	Elf_Sxword val;

	if (__predict_true(((size_t)where & (len - 1)) == 0)) {
#ifdef __mips_n64
		if (len == sizeof(Elf_Sxword))
			return *(Elf_Sxword *)where;
#endif
		return *(Elf_Sword *)where;
	}

	val = 0;
#if BYTE_ORDER == LITTLE_ENDIAN
	(void)memcpy(&val, where, len);
#endif
#if BYTE_ORDER == BIG_ENDIAN
	(void)memcpy((uint8_t *)((&val)+1) - len, where, len);
#endif
	return (len == sizeof(Elf_Sxword)) ? val : (Elf_Sword)val;
}

static __inline __always_inline void
store_ptr(void *where, Elf_Sxword val, size_t len)
{
	if (__predict_true(((size_t)where & (len - 1)) == 0)) {
#ifdef __mips_n64
		if (len == sizeof(Elf_Sxword)) {
			*(Elf_Sxword *)where = val;
			return;
		}
#endif
		*(Elf_Sword *)where = val;
		return;
	}
#if BYTE_ORDER == LITTLE_ENDIAN
	(void)memcpy(where, &val, len);
#endif
#if BYTE_ORDER == BIG_ENDIAN
	(void)memcpy(where, (const uint8_t *)((&val)+1) - len, len);
#endif
}

void
_rtld_relocate_nonplt_self(Elf_Dyn *dynp, caddr_t relocbase)
{
	/*
	 * Warning: global capabilities have not been initialized yet so we
	 * can't call any functions here (only ones with __always_inline)
	 *
	 * FIXME: all the debug printfs will crash
	 * TODO: change __cap_relocs emission in lld so that we can process
	 * __cap_relocs before this function (add a flag to say this entry does
	 * not need any relocations)
	 */
	const Elf_Rel *rel = NULL, *rellim;
	Elf_Addr relsz = 0;
	const Elf_Sym *symtab = NULL, *sym;
#ifdef DEBUG
	const char* strtab = NULL;
#endif
	Elf_Addr *where;
	Elf_Addr *got = NULL;
	Elf_Word local_gotno = 0, symtabno = 0, gotsym = 0;
	size_t i;

	for (; dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_REL:
			rel = (const Elf_Rel *)(relocbase + dynp->d_un.d_ptr);
			break;
		case DT_RELSZ:
			relsz = dynp->d_un.d_val;
			break;
		case DT_SYMTAB:
			symtab = (const Elf_Sym *)(relocbase + dynp->d_un.d_ptr);
			break;
#ifdef DEBUG
		case DT_STRTAB:
			strtab = (const char *)(relocbase + dynp->d_un.d_ptr);
			break;
#endif
		case DT_PLTGOT:
			got = (Elf_Addr *)(relocbase + dynp->d_un.d_ptr);
			break;
		case DT_MIPS_LOCAL_GOTNO:
			local_gotno = dynp->d_un.d_val;
			break;
		case DT_MIPS_SYMTABNO:
			symtabno = dynp->d_un.d_val;
			break;
		case DT_MIPS_GOTSYM:
			gotsym = dynp->d_un.d_val;
			break;
		}
	}

	i = GOT1_RESERVED_FOR_RTLD(got) ? 2 : 1;
	/* Relocate the local GOT entries */
	got += i;
	for (; i < local_gotno; i++) {
		*got++ += (vaddr_t)relocbase;
	}

	sym = symtab + gotsym;
	/* Now do the global GOT entries */
	for (i = gotsym; i < symtabno; i++) {
		*got = sym->st_value + (vaddr_t)relocbase;
		++sym;
		++got;
	}

	rellim = (const Elf_Rel *)((char *)rel + relsz);
	for (; rel < rellim; rel++) {
		Elf_Word r_symndx, r_type;

		where = (void *)(relocbase + rel->r_offset);

		r_symndx = ELF_R_SYM(rel->r_info);
		r_type = ELF_R_TYPE(rel->r_info);

		switch (r_type & 0xff) {
		case R_TYPE(REL32): {
			const size_t rlen =
			    ELF_R_NXTTYPE_64_P(r_type)
				? sizeof(Elf_Sxword)
				: sizeof(Elf_Sword);
			Elf_Sxword old = load_ptr(where, rlen);
			Elf_Sxword val = old;
#ifdef __mips_n64
			assert(r_type == R_TYPE(REL32)
			    || r_type == (R_TYPE(REL32)|(R_TYPE(64) << 8)));
#endif
			assert(r_symndx < gotsym);
			sym = symtab + r_symndx;
			assert(ELF_ST_BIND(sym->st_info) == STB_LOCAL);
			val += (vaddr_t)relocbase;
#ifdef DEBUG_VERBOSE_SELF
			/*
			 * FIXME dbg() can never work since the debug var only
			 * gets initialized later -> use rtld_printf for now
			 */
			rtld_printf("REL32/L(%p) %p -> %p in <self>\n",
			    where, (void *)(uintptr_t)old,
			    (void *)(uintptr_t)val);
#endif
			store_ptr(where, val, rlen);
			break;
		}

	/*
	 * There should be no dynamic CHERI_SIZE/CHERI_ABSPTR/CHERI_CAPABILITY
	 * relocations inside rtld since there are no global capabilities that
	 * are initialized to point to something.
	 *
	 * The reason this code is still here is that this may change at some
	 * point in the future.
	 */
#if 0
		case R_TYPE(CHERI_SIZE):
		case R_TYPE(CHERI_ABSPTR): {
			/* This is needed for __auxargs, otherwise there
			 * are no initialized globals
			 */
			const size_t rlen =
			    ELF_R_NXTTYPE_64_P(r_type)
				? sizeof(Elf_Sxword)
				: sizeof(Elf_Sword);
			Elf_Sxword old = load_ptr(where, rlen);
			Elf_Sxword val = old;
			sym = symtab + r_symndx;
			assert(ELF_ST_BIND(sym->st_info) == STB_LOCAL ||
			    ELF_ST_BIND(sym->st_info) == STB_WEAK);
			if ((r_type & 0xff) == R_TYPE(CHERI_SIZE)) {
				val += sym->st_size;
			} else {
				Elf_Addr symval = (Elf_Addr)relocbase + sym->st_value;
				val += symval;
			}
#ifdef DEBUG_VERBOSE_SELF
			/*
			 * FIXME dbg() can never work since the debug var only
			 * gets initialized later -> use rtld_printf for now
			 */
			rtld_printf("%s/L(%p) %p -> %p in <self>\n",
			    (r_type & 0xff) == R_TYPE(CHERI_SIZE) ? "SIZE" : "ABS",
			    where, (void *)(uintptr_t)old,
			    (void *)(uintptr_t)val);
#endif
			store_ptr(where, val, rlen);
			break;
		}
		case R_TYPE(CHERI_CAPABILITY): {
			sym = symtab + r_symndx;
			/* This is a hack for the undef weak __auxargs */
			/* TODO: try to remove __auxargs dependency */
			assert(ELF_ST_BIND(sym->st_info) == STB_WEAK);
			assert(sym->st_shndx == SHN_UNDEF);
			*((void**)where) = NULL;
		}
#endif

		case R_TYPE(GPREL32):
		case R_TYPE(NONE):
			break;


		default:
			/*
			 * XXXAR: the printf will fault in cap-table mode since
			 * the __cap_relocs have not been processed yet!
			 */
#ifdef DEBUG
			rtld_printf("sym = %lu, type = %lu, offset = %p, "
			    "contents = %p, symbol = %s\n",
			    (u_long)r_symndx, (u_long)ELF_R_TYPE(rel->r_info),
			    (void *)(uintptr_t)rel->r_offset,
			    (void *)(uintptr_t)load_ptr(where, sizeof(Elf_Sword)),
			    strtab + symtab[r_symndx].st_name);
#endif
			rtld_printf("%s: Unsupported relocation type %ld "
			    "in non-PLT relocations\n",
			    __func__, (u_long) ELF_R_TYPE(rel->r_info));
			/* Abort won't work yet since it needs global caps */
			/* abort(); */
			__builtin_trap();
			break;
		}
	}
}

Elf_Addr
_mips_rtld_bind(Obj_Entry *obj, Elf_Size reloff)
{
        Elf_Addr *got = obj->pltgot;
        const Elf_Sym *def;
        const Obj_Entry *defobj;
        Elf_Addr *where;
        Elf_Addr target;
        RtldLockState lockstate;

	rlock_acquire(rtld_bind_lock, &lockstate);
	if (sigsetjmp(lockstate.env, 0) != 0)
		lock_upgrade(rtld_bind_lock, &lockstate);

	where = &got[obj->local_gotno + reloff - obj->gotsym];
        def = find_symdef(reloff, obj, &defobj, SYMLOOK_IN_PLT, NULL,
           &lockstate);
        if (def == NULL)
		rtld_die();

        target = (Elf_Addr)(defobj->relocbase + def->st_value);
        dbg("bind now/fixup at %s sym # %jd in %s --> was=%p new=%p",
	    obj->path,
	    (intmax_t)reloff, defobj->strtab + def->st_name, 
	    (void *)(uintptr_t)*where, (void *)(uintptr_t)target);
	*where = target;
	lock_release(rtld_bind_lock, &lockstate);
	return (Elf_Addr)target;
}

static inline const char*
symname(Obj_Entry* obj, size_t r_symndx) {
	return obj->strtab + obj->symtab[r_symndx].st_name;
}

int
reloc_non_plt(Obj_Entry *obj, Obj_Entry *obj_rtld, int flags,
    RtldLockState *lockstate)
{
	const Elf_Rel *rel;
	const Elf_Rel *rellim;
	Elf_Addr *got = obj->pltgot;
	const Elf_Sym *sym, *def;
	const Obj_Entry *defobj;
	Elf_Word i;
	char symbuf[64];
	SymLook req, defreq;
#ifdef SUPPORT_OLD_BROKEN_LD
	int broken;
#endif

	/* The relocation for the dynamic loader has already been done. */
	if (obj == obj_rtld)
		return (0);

	if ((flags & SYMLOOK_IFUNC) != 0)
		/* XXX not implemented */
		return (0);

#ifdef SUPPORT_OLD_BROKEN_LD
	broken = 0;
	sym = obj->symtab;
	for (i = 1; i < 12; i++)
		if (sym[i].st_info == ELF_ST_INFO(STB_LOCAL, STT_NOTYPE))
			broken = 1;
	dbg("%s: broken=%d", obj->path, broken);
#endif

	i = GOT1_RESERVED_FOR_RTLD(got) ? 2 : 1;

	/* Relocate the local GOT entries */
	got += i;
	dbg("got:%p for %d entries adding %p",
	    got, obj->local_gotno, obj->relocbase);
	for (; i < obj->local_gotno; i++) {
		*got += (Elf_Addr)obj->relocbase;
		got++;
	}
	sym = obj->symtab + obj->gotsym;

	dbg("got:%p for %d entries",
	    got, obj->symtabno);
	/* Now do the global GOT entries */
	for (i = obj->gotsym; i < obj->symtabno; i++) {
#if defined(DEBUG_VERBOSE) || defined(DEBUG_MIPS_GOT)
		dbg(" doing got %d sym %p (%s, %lx)", i - obj->gotsym, sym,
		    sym->st_name + obj->strtab, (u_long) *got);
#endif

#ifdef SUPPORT_OLD_BROKEN_LD
		if (ELF_ST_TYPE(sym->st_info) == STT_FUNC &&
		    broken && sym->st_shndx == SHN_UNDEF) {
			/*
			 * XXX DANGER WILL ROBINSON!
			 * You might think this is stupid, as it intentionally
			 * defeats lazy binding -- and you'd be right.
			 * Unfortunately, for lazy binding to work right, we
			 * need to a way to force the GOT slots used for
			 * function pointers to be resolved immediately.  This
			 * is supposed to be done automatically by the linker,
			 * by not outputting a PLT slot and setting st_value
			 * to 0 if there are non-PLT references, but older
			 * versions of GNU ld do not do this.
			 */
			def = find_symdef(i, obj, &defobj, flags, NULL,
			    lockstate);
			if (def == NULL)
				return -1;
			*got = def->st_value + (Elf_Addr)defobj->relocbase;
		} else
#endif
		if (ELF_ST_TYPE(sym->st_info) == STT_FUNC &&
		    sym->st_value != 0 && sym->st_shndx == SHN_UNDEF) {
			/*
			 * If there are non-PLT references to the function,
			 * st_value should be 0, forcing us to resolve the
			 * address immediately.
			 *
			 * XXX DANGER WILL ROBINSON!
			 * The linker is not outputting PLT slots for calls to
			 * functions that are defined in the same shared
			 * library.  This is a bug, because it can screw up
			 * link ordering rules if the symbol is defined in
			 * more than one module.  For now, if there is a
			 * definition, we fail the test above and force a full
			 * symbol lookup.  This means that all intra-module
			 * calls are bound immediately.  - mycroft, 2003/09/24
			 */
			*got = sym->st_value + (Elf_Addr)obj->relocbase;
			if ((Elf_Addr)(*got) == (Elf_Addr)obj->relocbase) {
				dbg("Warning2, i:%d maps to relocbase address:%p",
				    i, obj->relocbase);
			}

		} else if (sym->st_info == ELF_ST_INFO(STB_GLOBAL, STT_SECTION)) {
			/* Symbols with index SHN_ABS are not relocated. */
			if (sym->st_shndx != SHN_ABS) {
				*got = sym->st_value +
				    (Elf_Addr)obj->relocbase;
				if ((Elf_Addr)(*got) == (Elf_Addr)obj->relocbase) {
					dbg("Warning3, i:%d maps to relocbase address:%p",
					    i, obj->relocbase);
				}
			}
		} else {
			/* TODO: add cache here */
			def = find_symdef(i, obj, &defobj, flags, NULL,
			    lockstate);

			/*
			 * XXX-BD: Undefined variables currently end up with
			 * defined, but zero, .size.<var> variables.  This is
			 * a linker bug.  Work around it by finding the one in
			 * the object that provided <var>.
			 */
			if ((ELF_ST_TYPE(sym->st_info) == STT_NOTYPE ||
			     ELF_ST_TYPE(sym->st_info) == STT_OBJECT) &&
			    defobj != obj &&
			    strncmp(sym->st_name + obj->strtab, ".size.",
			    6) != 0) {
				strcpy(symbuf, ".size.");
				strlcat(symbuf, sym->st_name + obj->strtab,
				    sizeof(symbuf) - strlen(".size."));
				dbg("looking for %s in %s and %s", symbuf,
				    obj->path, defobj->path);
				symlook_init(&req, symbuf);
				symlook_init(&defreq, symbuf);
				if (symlook_obj(&req, obj) == 0 &&
				    symlook_obj(&defreq, defobj) == 0) {
					size_t osize, nsize;
					osize = *((size_t*)(obj->relocbase +
					    req.sym_out->st_value));
					nsize = *((size_t* )(defobj->relocbase +
					    defreq.sym_out->st_value));
					dbg("found %s in %s and %s", symbuf,
					    obj->path, defobj->path);
					if (osize == 0) {
						dbg("%zx -> %zx", osize, nsize);
						*((size_t*)(obj->relocbase +
						    req.sym_out->st_value)) =
						    nsize;
					}
				}
			}
			if (def == NULL) {
				dbg("Warning4, can't find symbole %d", i);
				return -1;
			}
			*got = def->st_value + (Elf_Addr)defobj->relocbase;
			if ((Elf_Addr)(*got) == (Elf_Addr)obj->relocbase) {
				dbg("Warning4, i:%d maps to relocbase address:%p",
				    i, obj->relocbase);
				dbg("via first obj symbol %s",
				    obj->strtab + obj->symtab[i].st_name);
				dbg("found in obj %p:%s",
				    defobj, defobj->path);
			}
		}

#if defined(DEBUG_VERBOSE) || defined(DEBUG_MIPS_GOT)
		dbg("  --> now %lx", (u_long) *got);
#endif
		++sym;
		++got;
	}

	got = obj->pltgot;
	rellim = (const Elf_Rel *)((caddr_t)obj->rel + obj->relsize);
	for (rel = obj->rel; rel < rellim; rel++) {
		Elf_Word	r_symndx, r_type;
		void		*where;

		where = obj->relocbase + rel->r_offset;
		r_symndx = ELF_R_SYM(rel->r_info);
		r_type = ELF_R_TYPE(rel->r_info);

		switch (r_type & 0xff) {
		case R_TYPE(NONE):
			break;

		case R_TYPE(REL32): {
			/* 32-bit PC-relative reference */
			const size_t rlen =
			    ELF_R_NXTTYPE_64_P(r_type)
				? sizeof(Elf_Sxword)
				: sizeof(Elf_Sword);
			Elf_Sxword old = load_ptr(where, rlen);
			Elf_Sxword val = old;

			def = obj->symtab + r_symndx;

			if (r_symndx >= obj->gotsym) {
				val += got[obj->local_gotno + r_symndx - obj->gotsym];
#if defined(DEBUG_VERBOSE) || defined(DEBUG_MIPS_GOT)
				dbg("REL32/G(%p/0x%lx) %p --> %p (%s) in %s",
				    where, (caddr_t)where - obj->relocbase,
				    (void *)(uintptr_t)old, (void *)(uintptr_t)val,
				    obj->strtab + def->st_name,
				    obj->path);
#endif
			} else {
#if 0
				/*
				 * XXX: ABI DIFFERENCE!
				 *
				 * Old NetBSD binutils would generate shared
				 * libs with section-relative relocations being
				 * already adjusted for the start address of
				 * the section.
				 *
				 * New binutils, OTOH, generate shared libs
				 * with the same relocations being based at
				 * zero, so we need to add in the start address
				 * of the section.
				 *
				 * --rkb, Oct 6, 2001
				 */

				if (def->st_info ==
				    ELF_ST_INFO(STB_LOCAL, STT_SECTION)
#ifdef SUPPORT_OLD_BROKEN_LD
				    && !broken
#endif
				    )
#endif
				/* XXXAR: always adding st_value seems to be required (also glibc does it)*/
				val += (Elf_Addr)def->st_value;

				if (r_symndx != 0) {
					_rtld_error("%s: local R_MIPS_REL32 relocation references symbol %s (%d). st_value=0x%lx, st_info=%x, st_shndx=%d",
					    obj->path, obj->strtab + def->st_name, r_symndx, def->st_value, def->st_info, def->st_shndx);
					return (-1);
				}
				val += (Elf_Addr)obj->relocbase;
#if defined(DEBUG)
				_Bool print_local_reloc_dbg = false;
				if (def->st_value != 0) {
					print_local_reloc_dbg = true;
				}
#if defined(DEBUG_VERBOSE)
				print_local_reloc_dbg = true;
#endif
				if (print_local_reloc_dbg)
					dbg("REL32/L(%p/0x%lx) %p -> %p (%s) in %s, st_value = 0x%lx, st_info=%x, r_symndx=%d, st_shndx=%d",
					    where, rel->r_offset, (void *)(uintptr_t)old, (void *)(uintptr_t)val,
					    obj->strtab + def->st_name, obj->path, def->st_value, def->st_info, r_symndx, def->st_shndx);
#endif
			}
			store_ptr(where, val, rlen);
			break;
		}

#ifdef __mips_n64
		case R_TYPE(TLS_DTPMOD64):
#else
		case R_TYPE(TLS_DTPMOD32):
#endif
		{

			const size_t rlen = sizeof(Elf_Addr);
			Elf_Addr old = load_ptr(where, rlen);
			Elf_Addr val = old;

			def = find_symdef(r_symndx, obj, &defobj, flags, NULL,
			    lockstate);
			if (def == NULL)
				return -1;

			val += (Elf_Addr)defobj->tlsindex;

			store_ptr(where, val, rlen);
			dbg("DTPMOD %s in %s %p --> %p in %s",
			    symname(obj, r_symndx),
			    obj->path, (void *)(uintptr_t)old, (void*)(uintptr_t)val, defobj->path);
			break;
		}

#ifdef __mips_n64
		case R_TYPE(TLS_DTPREL64):
#else
		case R_TYPE(TLS_DTPREL32):
#endif
		{
			const size_t rlen = sizeof(Elf_Addr);
			Elf_Addr old = load_ptr(where, rlen);
			Elf_Addr val = old;

			def = find_symdef(r_symndx, obj, &defobj, flags, NULL,
			    lockstate);
			if (def == NULL)
				return -1;

			if (!defobj->tls_done && allocate_tls_offset(obj))
				return -1;

			val += (Elf_Addr)def->st_value - TLS_DTP_OFFSET;
			store_ptr(where, val, rlen);

			dbg("DTPREL %s in %s %p --> %p in %s",
			    symname(obj, r_symndx),
			    obj->path, (void*)(uintptr_t)old, (void *)(uintptr_t)val, defobj->path);
			break;
		}

#ifdef __mips_n64
		case R_TYPE(TLS_TPREL64):
#else
		case R_TYPE(TLS_TPREL32):
#endif
		{
			const size_t rlen = sizeof(Elf_Addr);
			Elf_Addr old = load_ptr(where, rlen);
			Elf_Addr val = old;

			def = find_symdef(r_symndx, obj, &defobj, flags, NULL,
			    lockstate);

			if (def == NULL)
				return -1;

			if (!defobj->tls_done && allocate_tls_offset(obj))
				return -1;

			val += (Elf_Addr)(def->st_value + defobj->tlsoffset
			    - TLS_TP_OFFSET - TLS_TCB_SIZE);
			store_ptr(where, val, rlen);

			dbg("TPREL %s in %s %p --> %p in %s",
			    symname(obj, r_symndx),
			    obj->path, (void*)(uintptr_t)old, (void *)(uintptr_t)val, defobj->path);
			break;
		}

		case R_TYPE(CHERI_ABSPTR):
		{
			def = find_symdef(r_symndx, obj,
			    &defobj, flags, NULL, lockstate);
			if (def == NULL) {
				_rtld_error("%s: Could not find symbol %s",
				    obj->path, symname(obj, r_symndx));
				return -1;
			}
			assert(ELF_ST_TYPE(def->st_info) != STT_GNU_IFUNC &&
			    "IFUNC not implemented!");
			Elf_Addr symval = (Elf_Addr)defobj->relocbase + def->st_value;
			const size_t rlen =
			    ELF_R_NXTTYPE_64_P(r_type)
				? sizeof(Elf_Sxword)
				: sizeof(Elf_Sword);
			Elf_Addr old = load_ptr(where, rlen);
			Elf_Addr val = old;
			val += symval;
			store_ptr(where, val, rlen);
			dbg("ABS(%p/0x%lx) %s in %s %p --> %p in %s",
			    where, rel->r_offset, symname(obj, r_symndx),
			    obj->path, (void*)(uintptr_t)old, (void *)(uintptr_t)val, defobj->path);
			break;
		}


		case R_TYPE(CHERI_SIZE):
		{
			def = find_symdef(r_symndx, obj,
			    &defobj, flags, NULL, lockstate);
			if (def == NULL) {
				_rtld_error("%s: Could not find symbol %s",
				    obj->path, symname(obj, r_symndx));
				return -1;
			}
			assert(ELF_ST_TYPE(def->st_info) != STT_GNU_IFUNC &&
			    "IFUNC not implemented!");
			Elf_Sxword size = def->st_size;
			const size_t rlen =
			    ELF_R_NXTTYPE_64_P(r_type)
				? sizeof(Elf_Sxword)
				: sizeof(Elf_Sword);
			Elf_Addr old = load_ptr(where, rlen);
			Elf_Addr val = old;
			val += size;
			store_ptr(where, val, rlen);
			dbg("SIZE(%p/0x%lx) %s in %s %p --> %p in %s",
			    where, rel->r_offset, symname(obj, r_symndx),
			    obj->path, (void*)(uintptr_t)old, (void *)(uintptr_t)val, defobj->path);
			break;
		}

		case R_TYPE(CHERI_CAPABILITY):
		{
			def = find_symdef(r_symndx, obj, &defobj, flags, NULL,
			    lockstate);
			if (def == NULL) {
				_rtld_error("%s: Could not find symbol %s",
				    obj->path, symname(obj, r_symndx));
				return -1;
			}
			assert(ELF_ST_TYPE(def->st_info) != STT_GNU_IFUNC &&
			    "IFUNC not implemented!");

			void* symval = NULL;
			bool is_undef_weak = false;
			if (def->st_shndx == SHN_UNDEF) {
				/* Verify that we are resolving a weak symbol */
				const Elf_Sym* src_sym = obj->symtab + r_symndx;
#ifdef DEBUG
				dbg("NOTE: found undefined R_CHERI_CAPABILITY "
				    "for %s (in %s): value=%ld, size=%ld, "
				    "type=%d, def bind=%d,sym bind=%d",
				    symname(obj, r_symndx), obj->path,
				    def->st_value, def->st_size,
				    ELF_ST_TYPE(def->st_info),
				    ELF_ST_BIND(def->st_info),
				    ELF_ST_BIND(src_sym->st_info));
#endif
				assert(ELF_ST_BIND(src_sym->st_info) == STB_WEAK);
				assert(def->st_value == 0);
				assert(def->st_size == 0);
				is_undef_weak = true;
			}
			else if (ELF_ST_TYPE(def->st_info) == STT_FUNC) {
				/* Remove write permissions and set bounds */
				symval = make_function_pointer(def, defobj);
			} else {
				/* Remove execute permissions and set bounds */
				symval = make_data_pointer(def, defobj);
			}
#if 0
			// FIXME: this warning breaks some tests that expect clean stdout/stderr
			// FIXME: See https://github.com/CTSRD-CHERI/cheribsd/issues/257
			// TODO: or use this approach: https://github.com/CTSRD-CHERI/cheribsd/commit/c1920496c0086d9c5214fb0f491e4d6cdff3828e?
			if (symval != NULL && cheri_getlen(symval) <= 0) {
				rtld_fdprintf(STDERR_FILENO, "Warning: created "
				    "zero length capability for %s (in %s): %-#p\n",
				    symname(obj, r_symndx), obj->path, symval);
			}
#endif
			/*
			 * The capability offset is the addend for the
			 * relocation. Since we are using Elf_Rel this is the
			 * first 8 bytes of the target location (which is the
			 * virtual address for both 128 and 256-bit CHERI).
			 */
			uint64_t src_offset = load_ptr(where, sizeof(uint64_t));
			symval += src_offset;
			if (!cheri_gettag(symval) && !is_undef_weak) {
				_rtld_error("%s: constructed invalid capability"
				   "for %s: %#p",  obj->path,
				    symname(obj, r_symndx), symval);
				return -1;
			}
			*((void**)where) = symval;
#if defined(DEBUG_VERBOSE)
			dbg("CAP(%p/0x%lx) %s in %s --> %-#p in %s",
			    where, rel->r_offset, symname(obj, r_symndx),
			    obj->path, *((void**)where), defobj->path);
#endif
			break;
		}

		default:
			dbg("sym = %lu, type = %lu, offset = %p, "
			    "contents = %p, symbol = %s",
			    (u_long)r_symndx, (u_long)ELF_R_TYPE(rel->r_info),
			    (void *)(uintptr_t)rel->r_offset,
			    (void *)(uintptr_t)load_ptr(where, sizeof(Elf_Sword)),
			    symname(obj, r_symndx));
			_rtld_error("%s: Unsupported relocation type %ld "
			    "in non-PLT relocations",
			    obj->path, (u_long) ELF_R_TYPE(rel->r_info));
			return -1;
		}
	}

	return 0;
}

/*
 *  Process the PLT relocations.
 */
int
reloc_plt(Obj_Entry *obj)
{
#if 0
	const Elf_Rel *rellim;
	const Elf_Rel *rel;

	dbg("reloc_plt obj:%p pltrel:%p sz:%s", obj, obj->pltrel, (int)obj->pltrelsize);
	dbg("gottable %p num syms:%s", obj->pltgot, obj->symtabno );
	dbg("*****************************************************");
	rellim = (const Elf_Rel *)((char *)obj->pltrel +
	    obj->pltrelsize);
	for (rel = obj->pltrel;  rel < rellim;  rel++) {
		Elf_Addr *where;
		where = (Elf_Addr *)(obj->relocbase + rel->r_offset);
		*where += (Elf_Addr )obj->relocbase;
	}

#endif
	/* PLT fixups were done above in the GOT relocation. */
	return (0);
}

/*
 * LD_BIND_NOW was set - force relocation for all jump slots
 */
int
reloc_jmpslots(Obj_Entry *obj, int flags, RtldLockState *lockstate)
{
	/* Do nothing */
	obj->jmpslots_done = true;

	return (0);
}

int
reloc_iresolve(Obj_Entry *obj, struct Struct_RtldLockState *lockstate)
{

	/* XXX not implemented */
	return (0);
}

int
reloc_gnu_ifunc(Obj_Entry *obj, int flags,
    struct Struct_RtldLockState *lockstate)
{

	/* XXX not implemented */
	return (0);
}

Elf_Addr
reloc_jmpslot(Elf_Addr *where, Elf_Addr target, const Obj_Entry *defobj,
    const Obj_Entry *obj, const Elf_Rel *rel)
{

	/* Do nothing */

	return target;
}

void
ifunc_init(Elf_Auxinfo aux_info[__min_size(AT_COUNT)] __unused)
{
}

void
allocate_initial_tls(Obj_Entry *objs)
{
	char *tls;

	/*
	 * Fix the size of the static TLS block by using the maximum
	 * offset allocated so far and adding a bit for dynamic modules to
	 * use.
	 */
	tls_static_space = tls_last_offset + tls_last_size + RTLD_STATIC_TLS_EXTRA;

	tls = (char *) allocate_tls(objs, NULL, TLS_TCB_SIZE, 8);

	sysarch(MIPS_SET_TLS, tls);
}

void *
_mips_get_tls(void)
{
#ifdef __CHERI_CAPABILITY_TLS__
	uintcap_t _rv;

	__asm__ __volatile__ (
	    "creadhwr\t%0, $chwr_userlocal"
	    : "=C" (_rv));
#else
	uint64_t _rv;

	/* XXX-BD: need capability rdhwr */
	__asm__ __volatile__ (
	    ".set\tpush\n\t"
	    ".set\tmips64r2\n\t"
	    "rdhwr\t%0, $29\n\t"
	    ".set\tpop"
	    : "=r" (_rv));
#endif

	/*
	 * XXXSS See 'git show c6be4f4d2d1b71c04de5d3bbb6933ce2dbcdb317'
	 *
	 * Remove the offset since this really a request to get the TLS
	 * pointer via sysarch() (in theory).  Of course, this may go away
	 * once the TLS code is rewritten.
	 */
	_rv = _rv - TLS_TP_OFFSET - TLS_TCB_SIZE;

#ifdef __CHERI_CAPABILITY_TLS__
	return (void *)_rv;
#else
	return cheri_setoffset(cheri_getdefault(), _rv);
#endif
}

void *
__tls_get_addr(tls_index* ti)
{
	intptr_t** tls;
	char *p;

#ifdef TLS_USE_SYSARCH
	sysarch(MIPS_GET_TLS, &tls);
#else
	tls = _mips_get_tls();
#endif

	p = tls_get_addr_common(tls, ti->ti_module, ti->ti_offset + TLS_DTP_OFFSET);

	return (p);
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
