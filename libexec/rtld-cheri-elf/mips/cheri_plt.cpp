/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

// This file includes all the infrastructure necessary to build
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <errno.h>
#include <uthash.h>
#include <new>

#include "rtld.h"

// Simple PLT stub with data + code embedded. Currently this will be updated to
// dispatch directly to the resulting function
// Note: currently this structure is used both for the stub that branches to
// the rtld resolver as well as for the unique thunks used for function pointers
struct CheriPltStub {
	// TODO: this is not necessary, but makes it so much easier to implemented
	// We should either place this at offset 0 of $pcc or make the bind
	// stub fetch it.
	const void* rtld_cgp; // FIXME: remove
	const void* captable_entry; // FIXME: remove

	// This will contain a pointer to the beginning of the struct prior
	// to resolving. This could be made a lot more efficient and the first
	// two capabilities could be removed from the struct but for now the
	// goal is just to get something that works...
	const void* cgp;
	const void* target;
	uint32_t plt_code[4]; // Three instructions + delay slot nop
	// Code:
	//
	// clc $cgp, $zero, -(2* CAP_SIZE) ($c12)
	// clc $c12, $zero, -CAP_SIZE($c12)
	// cjr $c12
	// nop
};

struct CheriPlt {
private:
	uint8_t* current_allocation = nullptr;
	const Obj_Entry* obj; // for debugging and assertion

	// TODO: ideally we would just get the maximum size from the
	// library and do a single mmap but for now we just allocate
	// 16k chunks each time
	// FIXME: this needs changes in LLD to emit DT_PLTRELSZ/DT_JMPREL
	constexpr static size_t BLOCK_SIZE = 16 * 1024 * 1024;
	size_t current_offset = 0;
	size_t num_plt_stubs = 0;

	uint8_t* allocate_new_block() {
		int mmap_flags = MAP_PRIVATE | MAP_ANON | MAP_NOCORE;
		// For now just keep it always mapped as RWX since we will
		// need to update the data capability and calling mprotect()
		// every time would be expensive. Only rtld will ever hold a
		// writable capability to this region so this should be safe
		void* result = mmap(nullptr, BLOCK_SIZE, PROT_ALL | PROT_MAX(PROT_ALL),
		    mmap_flags, -1, 0);
		dbg("Allocated PLT block for %s: %-#p", obj->path, result);
		if (result == MAP_FAILED) {
			dbg("mmap failed: %s", strerror(errno));
			return nullptr;
		}
		current_offset = 0;
		return reinterpret_cast<uint8_t*>(result);
	}
public:
	CheriPltStub* get_next_free_slot() {
		if (current_allocation == nullptr ||
		    current_offset + sizeof(CheriPltStub) > BLOCK_SIZE) {
			current_allocation = allocate_new_block();
			if (current_allocation == nullptr) {
				_rtld_error("%s: failed to allocate new PLT"
				    " block", obj->path);
				return nullptr;
			}
		}
		uint8_t *next = current_allocation + current_offset;
		current_offset += sizeof(CheriPltStub);
		num_plt_stubs++;
		return reinterpret_cast<CheriPltStub*>(
		    __builtin_assume_aligned(next, sizeof(void*)));
	}

	size_t count() const { return num_plt_stubs; }

	CheriPlt(const Obj_Entry* obj) : obj(obj) {}
};

#if 0
static void _lazy_binding_resolver(void);
__asm__(
".text\n"
".hidden _lazy_binding_resolver\n"
"_lazy_binding_resolver:\n"
"cmove $c3, $cgp\n"
"clc $cgp, $zero, 0($cgp)\n"
// TODO:
"b resolve_lazy_binding\n"
"nop\n"
)
#endif

static void
_lazy_binding_resolver()
{
	// TODO: write all of this in assembly
	CheriPltStub* plt_stub;
	__asm__ volatile("cmove %0, $cgp" :"=C"(plt_stub));
	const void* rtld_cgp = plt_stub->rtld_cgp;
	__asm__ volatile("cmove $cgp, %0" : : "C"(rtld_cgp));
	// Now that $cgp has been restored we can call functions again
	dbg("%s: rtld $cgp=%p, stub=%#p", __func__, rtld_cgp, plt_stub);
	__builtin_trap();
}

static constexpr uint8_t plt_code[] = {
#include "plt_code.inc"
};

static_assert(sizeof(plt_code) == sizeof(((CheriPltStub*)0)->plt_code), "");

extern "C" bool
add_cheri_plt_stub(const Obj_Entry* obj, const Obj_Entry *rtldobj,
    Elf_Word r_symndx, void** where)
{
	(void)where;
	if (!obj->cheri_plt_stubs) {
		// TODO: remove this
		dbg("%s: warning: called %s before reloc_plt()."
		    " Please updated LLD and rebuild world!", obj->path, __func__);
		const_cast<Obj_Entry*>(obj)->cheri_plt_stubs = new (NEW(struct CheriPlt)) CheriPlt(obj);
	}

	assert(obj->cheri_plt_stubs); // Should be setup be reloc_plt()

	// TODO: cheri_setaddr + ctestsubset instead of this check?
	if ((vaddr_t)where < (vaddr_t)obj->captable ||
	    (vaddr_t)where >= ((vaddr_t)obj->captable + cheri_getlen(obj->captable))) {
		_rtld_error("%s: plt stub target capability %p for %s not "
		    "inside captable %#p", obj->path, where,
		    symname(obj, r_symndx), obj->captable);
		return false;
	}

	CheriPltStub* plt = obj->cheri_plt_stubs->get_next_free_slot();
	if (!plt) {
		// _rtld_error("%s: could not add plt stub for %s", obj->path,
		//      symname(obj, r_symndx));
		return false;
	}
	dbg("%s: plt stub for %s: %#p", obj->path, symname(obj, r_symndx), plt);

	plt->captable_entry = where;
	plt->rtld_cgp = rtldobj->captable;
	plt->target = (const void*)&_lazy_binding_resolver;
	__builtin_memcpy(plt->plt_code, plt_code, sizeof(plt->plt_code));
	void* target_cap = cheri_csetbounds(plt, sizeof(CheriPltStub));
	plt->cgp = target_cap; // currently self-reference (to beginning of struct)
	// but the actual target that is written to the PLT should point to the code:
	target_cap = cheri_incoffset(target_cap, offsetof(CheriPltStub, plt_code));
	dbg("where=%p <- plt_code=%#p", where, target_cap);
	*where = target_cap;
	return true;
}


/*
 * LD_BIND_NOW was set - force relocation for all jump slots
 */
extern "C" int
reloc_jmpslots(Obj_Entry *obj, int flags __unused, RtldLockState *lockstate __unused)
{
	// FIXME: this needs changes in LLD to emit DT_PLTRELSZ/DT_JMPREL
	/* Do nothing. TODO: needed once we have lazy binding */
	obj->jmpslots_done = true;
	return (0);
}

/*
 *  Process the PLT relocations.
 */
extern "C" int
reloc_plt(Obj_Entry *obj, const Obj_Entry *rtldobj)
{
	// FIXME: this needs changes in LLD to emit DT_PLTRELSZ/DT_JMPREL
	// TODO: assert(!obj->cheri_plt_stubs)
	if (!obj->cheri_plt_stubs) {
		// Note: this is done before reloc_non_plt so it is safe to initialize
		// obj->cheri_plt_stubs here even while we still allow plt relocations
		// as part of .rel.dyn
		obj->cheri_plt_stubs = new (NEW(struct CheriPlt)) CheriPlt(obj);
	}
	assert(obj->cheri_plt_stubs);

	// .rel.plt should only ever contain CHERI_CAPABILITY_CALL relocs!
	const Elf_Rel *pltrellim = (const Elf_Rel *)((const char *)obj->pltrel +
	    obj->pltrelsize);
	for (const Elf_Rel *rel = obj->pltrel; rel < pltrellim; rel++) {
		void **where = (void **)(obj->relocbase + rel->r_offset);
		Elf_Word r_symndx = ELF_R_SYM(rel->r_info);
		Elf_Word r_type = ELF_R_TYPE(rel->r_info);

		if ((r_type & 0xff) == R_TYPE(CHERI_CAPABILITY_CALL)) {
			if (!add_cheri_plt_stub(obj, rtldobj, r_symndx, where))
				return (-1);
		} else {
			_rtld_error("Unknown relocation type %x in PLT",
			    (unsigned int)r_type);
			return (-1);
		}
	}
	dbg("%s: done relocating %zd PLT entries: ", obj->path,
	    obj->cheri_plt_stubs->count());
	for (size_t i = 0; i < obj->captable_size / sizeof(void*); i++) {
		dbg("%s->captable[%zd]:%p = %#p", obj->path, i, &obj->captable[i], obj->captable[i]);
	}
	return (0);
}

// Note: the use of uthash here is highly inefficient but for now it works.
struct ThunkHash {
	const Elf_Sym *id;		// key (TODO: use symbol table index)
#ifdef DEBUG
	const char* name;
#endif
	CheriPltStub* thunk;	// TODO: make this an index to save space
	UT_hash_handle hh;		// makes this structure hashable
};

// A list of exported functions to allow uniquifying function pointers
struct CheriExports {
	struct ThunkHash *existing_thunks = NULL;
public:
	ThunkHash* getOrAddThunk(const Obj_Entry* obj, const Elf_Sym *sym);
private:
	ThunkHash* addThunk(const Obj_Entry* obj, const Elf_Sym *sym);

};

extern "C" dlfunc_t
find_external_call_thunk(const Obj_Entry* obj, const Elf_Sym* symbol)
{
	dbg("Looking for thunk for %s (obj %s)", strtab_value(obj, symbol->st_name), obj->path);
	if (!obj->cheri_exports) {
		// Use placement-new here to use rtld xmalloc() instead of malloc
		// FIXME: const_cast should not be needed
		const_cast<Obj_Entry*>(obj)->cheri_exports =
			new (NEW(struct CheriExports)) CheriExports;
	}
	return nullptr;
}

ThunkHash*
CheriExports::addThunk(const Obj_Entry* obj, const Elf_Sym *sym)
{
	assert(ELF_ST_TYPE(sym->st_info) == STT_FUNC);
	struct ThunkHash *s = NEW(struct ThunkHash);
	s->id = sym;
#ifdef DEBUG
	s->name = strtab_value(obj, sym->st_name);
	dbg("Adding thunk for %s (obj %s)", s->name, obj->path);
#endif
	HASH_ADD_PTR(this->existing_thunks, id, s);  /* id: name of key field */
	return s;
};

ThunkHash*
CheriExports::getOrAddThunk(const Obj_Entry* obj, const Elf_Sym *sym)
{
	struct ThunkHash *s = nullptr;
	HASH_FIND_PTR(this->existing_thunks, &sym, s);
	if (!s)
		s = addThunk(obj, sym);
#ifdef DEBUG
	else {
		dbg("Found thunk for %s in %s: %p", s->name, obj->path, s);
	}
	// A second find should return the same value
	struct ThunkHash *s2 = nullptr;
	HASH_FIND_PTR(this->existing_thunks, &sym, s2);
	assert(s2 != nullptr);
	assert(s2 == s);
#endif
	return s;
}
