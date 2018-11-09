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

static constexpr uint8_t simple_plt_code[] = {
#include "plt_code.inc"
};

// A simple external call trampoline that has the target function and data
//embedded just before the code
struct SimpleExternalCallTrampoline {
	const void* cgp;
	dlfunc_t target;
	uint32_t code[4]; // Three instructions + delay slot nop
	// Code:
	//
	// clc $cgp, $zero, -(2* CAP_SIZE) ($c12)
	// clc $c12, $zero, -CAP_SIZE($c12)
	// cjr $c12
	// nop
	void init(const void* target_cgp, dlfunc_t target_func) {
		this->cgp = target_cgp;
		this->target = target_func;
		static_assert(sizeof(this->code) == sizeof(simple_plt_code), "");
		__builtin_memcpy(code, simple_plt_code, sizeof(simple_plt_code));
	}
};

// Simple PLT stub with data + code embedded. Currently this will be updated to
// dispatch directly to the resulting function
// Note: currently this structure is used both for the stub that branches to
// the rtld resolver as well as for the unique thunks used for function pointers
struct CheriPltStub {
	// TODO: this is not necessary, but makes it so much easier to implemented
	// We should either place this at offset 0 of $pcc or make the bind
	// stub fetch it.
	const void* rtld_cgp; // FIXME: remove (could use privileged TLS register
	// This will contain a pointer to the beginning of the struct prior
	// to resolving. This could be made a lot more efficient and the first
	// two capabilities could be removed from the struct but for now the
	// goal is just to get something that works...
	struct SimpleExternalCallTrampoline trampoline;

public:
	// TODO: remove the members and derive these sensibly
	Elf_Word r_symndx() const { return _r_symndx; }
	const Obj_Entry *obj() const { return _obj; }
public:
	const Obj_Entry *_obj; // FIXME: remove (one trampoline function per object)
	Elf_Word _r_symndx; // FIXME: remove
};

// We need lots of RWX memory mappings for these stubs. Use a non-freeing
// allocator that just mmap()s RWX memory and does bump-the-pointer
// FIXME: this is not thread safe!
class RWXAllocator {
private:
	constexpr static size_t BLOCK_SIZE = 16 * 1024 * 1024;
	size_t current_offset = 0;
	uint8_t* current_allocation = nullptr;
	uint8_t* allocate_new_block() {
		int mmap_flags = MAP_PRIVATE | MAP_ANON | MAP_NOCORE;
		// For now just keep it always mapped as RWX since we will
		// need to update the data capability and calling mprotect()
		// every time would be expensive. Only rtld will ever hold a
		// writable capability to this region so this should be safe
		void* result = mmap(nullptr, BLOCK_SIZE, PROT_ALL | PROT_MAX(PROT_ALL),
		    mmap_flags, -1, 0);
		dbg("Allocated new RWX block: %-#p", result);
		if (result == MAP_FAILED) {
			dbg("mmap failed: %s", strerror(errno));
			return nullptr;
		}
		current_offset = 0;
		return reinterpret_cast<uint8_t*>(result);
	}
	void* allocate(size_t size) {
		// Can only allocate multiples of sizeof(void*)
		assert(__builtin_is_aligned(size, sizeof(void*)));
		if (current_allocation == nullptr ||
		    current_offset + size > BLOCK_SIZE) {
			current_allocation = allocate_new_block();
			if (current_allocation == nullptr) {
				_rtld_error("failed to allocate new RWX block");
				return nullptr;
			}
		}
		uint8_t *next = current_allocation + current_offset;
		assert(__builtin_is_aligned(next, sizeof(void*)));
		current_offset += size;
		assert(current_offset <= BLOCK_SIZE);
		return cheri_csetbounds(next, size);
	}
public:
	template<typename T> T* allocate() {
		constexpr size_t allocation_size =
		    __builtin_align_up(sizeof(T), sizeof(void*));
		return static_cast<T*>(
		    __builtin_assume_aligned(allocate(allocation_size), sizeof(void*)));
	}
};

// TODO: should probably be per-object to allow freeing on unload?
// This would also make it easier to share multiple data pointers between stubs
// since currently we set tight bounds
static RWXAllocator globalRwxAllocator;

struct CheriPlt {
private:
	const Obj_Entry* obj __unused; // for debugging and assertion

	// TODO: ideally we would just get the maximum size from the
	// library and do a single mmap but for now we just use the bump allocator
	//  RWXAllocator allocator;
	size_t num_plt_stubs = 0;
public:
	CheriPltStub* get_next_free_slot() {
		num_plt_stubs++;
		// return allocator.allocate<CheriPltStub>();
		return globalRwxAllocator.allocate<CheriPltStub>();
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

dlfunc_t
_mips_rtld_bind(void* _plt_stub)
{
	CheriPltStub *plt_stub = static_cast<CheriPltStub*>(_plt_stub);
	dbg("%s: rtld $cgp=%p, stub=%#p", __func__, cheri_getidc(), plt_stub);
	RtldLockState lockstate;
	const Elf_Word r_symndx = plt_stub->r_symndx();
	const Obj_Entry *obj = plt_stub->obj();

	rlock_acquire(rtld_bind_lock, &lockstate);
	if (sigsetjmp(lockstate.env, 0) != 0)
		lock_upgrade(rtld_bind_lock, &lockstate);

	const Obj_Entry *defobj;
	const Elf_Sym *def = find_symdef(r_symndx, obj, &defobj, SYMLOOK_IN_PLT, NULL, &lockstate);
	if (def == NULL) {
		rtld_fatal("Could not find symbol definition for PLT symbol %s"
		    " in %s", symname(obj, r_symndx), obj->path);
	}

	dlfunc_t target = make_function_pointer(def, defobj);
	const void* target_cgp = defobj->target_cgp;
	assert(cheri_gettag(target_cgp));
	dbg("bind now/fixup at %s (sym #%jd) in %s --> was=%p new=%p",
	    defobj->strtab + def->st_name, (intmax_t)r_symndx, obj->path,
	    (void *)plt_stub->trampoline.target, (void *)target);

	if (!ld_bind_not) {
		plt_stub->trampoline.target = target;
		plt_stub->trampoline.cgp = target_cgp;
	}
	lock_release(rtld_bind_lock, &lockstate);
	// Setup the target $cgp so that we can actually call the function
	// TODO: return two values instead (will a 2 cap struct use $c3/$c4?)
	__asm__ volatile("cmove $cgp, %0"::"C"(target_cgp));
	return target;
}

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
	if ((vaddr_t)where < (vaddr_t)obj->writable_captable ||
	    (vaddr_t)where >= ((vaddr_t)obj->writable_captable + cheri_getlen(obj->writable_captable))) {
		_rtld_error("%s: plt stub target capability %p for %s not "
		    "inside captable %#p", obj->path, where,
		    symname(obj, r_symndx), obj->writable_captable);
		return false;
	}

	CheriPltStub* plt = obj->cheri_plt_stubs->get_next_free_slot();
	if (!plt) {
		// _rtld_error("%s: could not add plt stub for %s", obj->path,
		//      symname(obj, r_symndx));
		return false;
	}
	dbg("%s: plt stub for %s: %#p", obj->path, symname(obj, r_symndx), plt);

	// TODO: if we decide to directly update captable entries for the pc-relative ABI:
	// plt->captable_entry = where;
	plt->rtld_cgp = rtldobj->target_cgp;
	plt->_obj = obj;	// FIXME: remove
	plt->_r_symndx = r_symndx; // FIXME: remove
	// The target cap will span the whole plt stub:

	// void* target_cap = cheri_csetbounds(plt, sizeof(CheriPltStub));
	void* target_cap = plt;
	// currently use a self-reference (to beginning of struct) as data cap
	plt->trampoline.init(target_cap, (dlfunc_t)&_rtld_bind_start);
	// but the actual target that is written to the PLT should point to the code:
	target_cap = cheri_incoffset(target_cap, offsetof(CheriPltStub, trampoline.code));
	target_cap = cheri_clearperm(target_cap, FUNC_PTR_REMOVE_PERMS);
	dbg("where=%p <- plt_code=%#p", where, target_cap);
	assert(cheri_getperm(target_cap) & CHERI_PERM_EXECUTE);
	assert(cheri_getlen(target_cap) == sizeof(CheriPltStub) &&
	    "stub should have tight bounds");
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
#if defined(DEBUG_VERBOSE) && DEBUG_VERBOSE >= 3
	for (size_t i = 0; i < obj->captable_size / sizeof(void*); i++) {
		dbg("%s->captable[%zd]:%p = %#p", obj->path, i,
		    &obj->writable_captable[i], obj->writable_captable[i].value);
	}
#endif
	return (0);
}

// Note: the use of uthash here is highly inefficient but for now it works.
struct ThunkHash {
	const Elf_Sym *id;		// key (TODO: use symbol table index)
#ifdef DEBUG
	const char* name;
#endif
	SimpleExternalCallTrampoline* thunk;
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
	dbg("Looking for thunk for %s (found in obj %s)", strtab_value(obj, symbol->st_name), obj->path);
	if (!obj->cheri_exports) {
		// Use placement-new here to use rtld xmalloc() instead of malloc
		// FIXME: const_cast should not be needed
		const_cast<Obj_Entry*>(obj)->cheri_exports =
			new (NEW(struct CheriExports)) CheriExports;
	}
	ThunkHash* s = obj->cheri_exports->getOrAddThunk(obj, symbol);

	void* target_cap = cheri_csetbounds(s->thunk, sizeof(SimpleExternalCallTrampoline));
	target_cap = cheri_incoffset(target_cap, offsetof(SimpleExternalCallTrampoline, code));
	target_cap = cheri_clearperm(target_cap, FUNC_PTR_REMOVE_PERMS);
	dbg("External call thunk resolved to %-#p", target_cap);
	assert(cheri_getperm(target_cap) & CHERI_PERM_EXECUTE);
	assert(cheri_getlen(target_cap) == sizeof(SimpleExternalCallTrampoline) &&
	    "stub should have tight bounds");
	return (dlfunc_t)target_cap;
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
	s->thunk = globalRwxAllocator.allocate<SimpleExternalCallTrampoline>();
	s->thunk->init(obj->target_cgp, make_function_pointer(sym, obj));
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
