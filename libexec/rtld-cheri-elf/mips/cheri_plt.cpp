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
    const void* cgp;
    const void* target;
    uint32_t thunk_code[4]; // Three instructions + delay slot nop
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
		current_offset += sizeof(CheriPlt);
		return reinterpret_cast<CheriPltStub*>(
		    __builtin_assume_aligned(next, sizeof(void*)));
	}
	CheriPlt(const Obj_Entry* obj) : obj(obj) {}
};

extern "C" bool
add_cheri_plt_stub(const Obj_Entry* obj, Elf_Word r_symndx, void** where)
{
	(void)where;
	assert(obj->cheri_plt_stubs); // Should be setup be reloc_plt()
	CheriPltStub* plt = obj->cheri_plt_stubs->get_next_free_slot();
	if (!plt)
		return false;
	_rtld_error("%s: could not add plt stub for %s", obj->path,
	    symname(obj, r_symndx));
	return false;
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
reloc_plt(Obj_Entry *obj)
{
	// FIXME: this needs changes in LLD to emit DT_PLTRELSZ/DT_JMPREL
	assert(!obj->cheri_plt_stubs);
	// Note: this is done before reloc_non_plt so it is safe to initialize
	// obj->cheri_plt_stubs here even while we still allow plt relocations
	// as part of .rel.dyn
	obj->cheri_plt_stubs = new (NEW(struct CheriPlt)) CheriPlt(obj);
	assert(obj->cheri_plt_stubs);

	// .rel.plt should only ever contain CHERI_CAPABILITY_CALL relocs!
	const Elf_Rel *pltrellim = (const Elf_Rel *)((const char *)obj->pltrel +
	    obj->pltrelsize);
	for (const Elf_Rel *rel = obj->pltrel; rel < pltrellim; rel++) {
		void **where = (void **)(obj->relocbase + rel->r_offset);
		Elf_Word r_symndx = ELF_R_SYM(rel->r_info);
		Elf_Word r_type = ELF_R_TYPE(rel->r_info);

		if ((r_type & 0xff) == R_TYPE(CHERI_CAPABILITY_CALL)) {
			if (!add_cheri_plt_stub(obj, r_symndx, where))
				return (-1);
		} else {
			_rtld_error("Unknown relocation type %x in PLT",
			    (unsigned int)r_type);
			return (-1);
		}
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
