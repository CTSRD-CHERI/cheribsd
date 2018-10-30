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
#include <uthash.h>
#include <dlfcn.h>
#include <new>

#include "rtld.h"

/* Simple external call thunk with data + code embedded */
struct ExternalCallThunk {
    const void* cgp;
    const void* target;
    uint32_t thunk_code[4]; // Three instructions + delay slot nop
};

struct ThunkHash {
	const Elf_Sym *id;		// key (TODO: use symbol table index)
#ifdef DEBUG
	const char* name;
#endif
	ExternalCallThunk* thunk;	// TODO: make this an index to save space
	UT_hash_handle hh;		// makes this structure hashable
};

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
