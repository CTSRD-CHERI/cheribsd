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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <ucontext.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_printf.h"
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
#include <stdatomic.h>
#include "rtld_libc.h"
#endif

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
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
void _rtld_get_rstk(void);
#endif

void
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
init_pltgot(Obj_Entry *obj, uintptr_t sealer)
#else
init_pltgot(Obj_Entry *obj)
#endif
{

	if (obj->pltgot != NULL) {
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
		obj->pltgot[1] = (uintptr_t) cheri_seal(obj, sealer);
#else
		obj->pltgot[1] = (uintptr_t) obj;
#endif
		obj->pltgot[2] = (uintptr_t) &_rtld_bind_start;
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

#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)

typedef void **tramp_stk_table_t;

void _rtld_thread_start(struct pthread *);
void _rtld_sighandler(int, siginfo_t *, void *);
void *get_rstk(const void *, uint32_t, tramp_stk_table_t);

#define DEFAULT_STACK_TABLE_SIZE 2
/* Default stack size in libthr */
#define DEFAULT_SANDBOX_STACK_SIZE	(sizeof(void *) / 4 * 1024 * 1024)

static void (*thr_thread_start)(struct pthread *);

void
_rtld_thread_start_init(void (*p)(struct pthread *))
{
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	assert(thr_thread_start == NULL);
	thr_thread_start = _rtld_sandbox_code(p, (struct tramp_sig) {
		.valid = true,
		.reg_args = 1, .mem_args = false, .ret_args = NONE
	});
}

void
_rtld_thread_start(struct pthread *curthread)
{
	tramp_stk_table_t tls;
	asm ("mrs	%0, ctpidr_el0" : "=C" (tls));
	asm ("msr	rctpidr_el0, %0" :: "C" (tls));

	tls = xcalloc(DEFAULT_STACK_TABLE_SIZE, sizeof(*tls));
	tls[0] = _rtld_get_rstk;
	asm ("msr	ctpidr_el0, %0" :: "C" (tls));

	thr_thread_start(curthread);
}

void
_rtld_thr_exit(long *state)
{
	tramp_stk_table_t tls;
	asm ("mrs	%0, ctpidr_el0" : "=C" (tls));

	vaddr_t top = cheri_gettop(tls);
	for (tramp_stk_table_t cur = &tls[1]; (vaddr_t)cur < top; ++cur) {
		void *stk = cheri_setaddress(*cur, cheri_getbase(*cur));
		if (stk != NULL && munmap(stk, DEFAULT_SANDBOX_STACK_SIZE) != 0)
			rtld_fatal("munmap failed");
	}
	free(tls);

	thr_exit(state);
}

static void (*thr_sighandler)(int, siginfo_t *, void *);

void
_rtld_sighandler(int sig, siginfo_t *info, void *_ucp)
{
	uintptr_t csp, rcsp;
	ucontext_t *ucp = _ucp;

	csp = ucp->uc_mcontext.mc_capregs.cap_sp;
	asm ("mrs	%0, rcsp_el0" : "=C" (rcsp));
	ucp->uc_mcontext.mc_capregs.cap_sp = rcsp;

	thr_sighandler(sig, info, ucp);

	rcsp = ucp->uc_mcontext.mc_capregs.cap_sp;
	asm ("msr	rcsp_el0, %0" :: "C" (rcsp));
	ucp->uc_mcontext.mc_capregs.cap_sp = csp;
}

void
_rtld_sighandler_init(void (*p)(int, siginfo_t *, void *))
{
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	assert(thr_sighandler == NULL);
	thr_sighandler = _rtld_sandbox_code(p, (struct tramp_sig) {
		.valid = true,
		.reg_args = 3, .mem_args = false, .ret_args = NONE
	});
}

void *
get_rstk(const void *target, uint32_t index, tramp_stk_table_t table)
{
	size_t len = cheri_getlen(table) / sizeof(*table);
	assert(len <= index || table[index] == NULL);
	if (len <= index) {
		size_t new_len = index * 2;
		table = realloc(table, new_len * sizeof(*table));
		if (table == NULL)
			rtld_fatal("realloc failed");
		memset(&table[len], 0, (new_len - len) * sizeof(*table));

		asm ("msr	ctpidr_el0, %0" :: "C" (table));
	}
	assert(table[index] == NULL);

	void **stk;
	struct Struct_Stack_Entry *_Atomic *head, *entry;

	len = DEFAULT_SANDBOX_STACK_SIZE;
	stk = (void **)((char *)mmap(NULL,
	    len,
	    PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE | MAP_STACK,
	    -1, 0) + len);
	if (stk == MAP_FAILED)
		rtld_fatal("mmap failed");
	stk = cheri_clearperm(stk, CHERI_PERM_EXECUTIVE | CHERI_PERM_SW_VMEM);
	stk[-1] = &stk[-1];

	table[index] = stk;

	head = &obj_from_addr(target)->stacks;
	entry = xmalloc(sizeof(*entry));
	entry->stack = stk;
	SLIST_NEXT(entry, link) = atomic_load_explicit(head,
	    memory_order_relaxed);
	while(!atomic_compare_exchange_weak_explicit(
	    head, &SLIST_NEXT(entry, link), entry,
	    memory_order_release, memory_order_relaxed));

	return (stk);
}

static int
exclude_symbol_in_lib(const char *name, const char *sym, const Obj_Entry *obj, const Elf_Sym *def)
{
	Name_Entry *entry;

	if (def == NULL ||
	    strcmp(sym, strtab_value(obj, def->st_name)) != 0)
		return (0);

	STAILQ_FOREACH(entry, &obj->names, link) {
		if (strcmp(name, entry->name) == 0)
			return (1);
	}
	return (0);
}

struct tramp_pg {
	void *_Atomic cursor;		/* Start of unused space */
	SLIST_ENTRY(tramp_pg) link;	/* Link to next page */
	void *trampolines[];		/* Start of trampolines */
};

static struct tramp_pg *
tramp_pg_new(struct tramp_pg *next)
{
	struct tramp_pg *pg = mmap(NULL,
	    /*
	     * 64K is the largest size such that any capability-aligned proper
	     * sub-range can be exactly bounded by a Morello capability.
	     */
	    64 * 1024,
	    PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_ANON | MAP_PRIVATE,
	    -1, 0);
	if (pg == MAP_FAILED)
		rtld_fatal("mmap failed");
	atomic_store_explicit(&pg->cursor, pg->trampolines,
	    memory_order_relaxed);
	SLIST_NEXT(pg, link) = next;
	return (pg);
}

static void *
tramp_pg_push(struct tramp_pg *pg, size_t len)
{
	void *cur = atomic_load_explicit(&pg->cursor, memory_order_relaxed);
	void *n_cur, *tramp;
	do {
		tramp = cheri_setbounds(cur, len);
		ptraddr_t n_cur_addr = roundup2(
		    cheri_gettop(tramp), _Alignof(void *));
		ptrdiff_t n_cur_len = cheri_gettop(cur) - n_cur_addr;

		n_cur = cheri_setaddress(cur, n_cur_addr);
		n_cur = cheri_setboundsexact(n_cur, n_cur_len);

	} while (!atomic_compare_exchange_weak_explicit(
	    &pg->cursor, &cur, n_cur,
	    /*
	     * Relaxed ordering is sufficient because there are no side-effects.
	     */
	    memory_order_relaxed, memory_order_relaxed));

	assert(!cheri_gettag(tramp) || cheri_gettag(n_cur));
	return (tramp);
}

typedef int64_t slot_index;

static struct {
	struct tramp_data *data;
	struct tramp_map_kv {
		_Atomic vaddr_t key;
		_Atomic slot_index index;
	} *map;
	_Atomic slot_index size, writers;
	int exp;
} tramp_table;

static struct {
	struct tramp_pg *_Atomic head;
	atomic_flag lock;
} tramp_pgs = {
	.lock = ATOMIC_FLAG_INIT
};

static slot_index
tramp_table_load_factor(int exp)
{
	/* LOAD_FACTOR is 37.5% of capacity. */
	return (3 << (exp - 3));
}

static struct tramp_map_kv *
tramp_map_new(int exp)
{
	struct tramp_map_kv *map = xmalloc(sizeof(*map) << exp);
	for (size_t i = 0; i < (1 << exp); ++i)
		map[i] = (struct tramp_map_kv) {
			.key = 0,
			.index = -1
		};
	return (map);
}

static struct tramp_data *
tramp_data_expand(int exp)
{
	/*
	 * The table only needs to be as large as the LOAD_FACTOR.
	 */
	struct tramp_data *data = realloc(tramp_table.data,
	    sizeof(*data) * tramp_table_load_factor(exp));
	if (data == NULL)
		rtld_fatal("realloc failed");
	return (data);
}

void
tramp_init()
{
	int exp = 9;
	tramp_table.data = tramp_data_expand(exp);
	tramp_table.map = tramp_map_new(exp);
	tramp_table.exp = exp;

	atomic_store_explicit(&tramp_pgs.head, tramp_pg_new(NULL),
	    memory_order_relaxed);
}

static uint32_t
pointerHash(uint64_t key) {
	uint32_t x = key ^ (key >> 32);
	x ^= x >> 16;
	x *= 0x21f0aaadU;
	x ^= x >> 15;
	x *= 0xd35a2d97U;
	x ^= x >> 15;
	return (x);
}

static slot_index
nextSlot(slot_index slot, uint32_t hash, int exp)
{
	uint32_t mask = (1 << exp) - 1;
	uint32_t step = (hash >> (32 - exp)) | 1;
	return ((slot + step) & mask);
}

static void
resizeTable(int exp)
{
	struct tramp_map_kv *map;
	struct tramp_data *data;
	vaddr_t key;
	uint32_t hash;
	slot_index size, slot;

	assert(0 < exp && exp < 32);

	free(tramp_table.map);
	data = tramp_data_expand(exp);
	map = tramp_map_new(exp);
	size = atomic_load_explicit(&tramp_table.size, memory_order_relaxed);

	for (slot_index idx = 0; idx < size; ++idx) {
		key = (vaddr_t)data[idx].target;
		hash = pointerHash(key);
		slot = hash;
		do
			slot = nextSlot(slot, hash, exp);
		while (atomic_load_explicit(
		    &map[slot].key, memory_order_relaxed) != 0);
		atomic_store_explicit(&map[slot].key, key,
		    memory_order_relaxed);
		atomic_store_explicit(&map[slot].index, idx,
		    memory_order_relaxed);
	}

	tramp_table.data = data;
	tramp_table.map = map;
	tramp_table.exp = exp;
}

static size_t
tramp_compile(tramp **entry, const struct tramp_data *data)
{
#define IMPORT(template) \
	extern const uint32_t tramp_##template[]; \
	extern const size_t size_tramp_##template

#define TRANSITION(template, ...) \
	if (code == tramp_##template) { \
		buf = mempcpy(buf, tramp_##template, size_tramp_##template); \
		size += size_tramp_##template; \
		__VA_ARGS__ \
		continue; \
	}

#define TO(template) \
	code = tramp_##template

	IMPORT(header);
	IMPORT(header_utrace);
	IMPORT(header_res);
	IMPORT(save_caller);
	IMPORT(switch_stack);
	IMPORT(clear_regs);
	IMPORT(invoke_res);
	IMPORT(invoke_exe);
	IMPORT(utrace_return);
	IMPORT(return);

	uint32_t *buf = (void *)*entry;
	const void *code;
	size_t size = 0;
	bool executive = cheri_getperm(data->target) & CHERI_PERM_EXECUTIVE;
	bool utrace = ld_utrace_compartment != NULL;

	if (utrace)
		code = tramp_header_utrace;
	else
		code = tramp_header;

	for (; code != NULL; ) {
		TRANSITION(header, {
			if (executive)
				TO(save_caller);
			else
				TO(header_res);
		})
		TRANSITION(header_utrace, {
			if (executive)
				TO(save_caller);
			else
				TO(header_res);
			*(*entry)++ = STAILQ_EMPTY(&data->obj->names) ?
			    data->obj->path :
			    STAILQ_FIRST(&data->obj->names)->name;
			*(*entry)++ = data->def == NULL ? "<unknown>" :
			    strtab_value(data->obj, data->def->st_name);
			*(*entry)++ = ld_utrace_log;
		})
		TRANSITION(header_res, {
			buf[-2] |= (uint32_t)data->obj->compart_id << 5;
			TO(save_caller);
		})
		TRANSITION(save_caller, {
			if (data->sig.valid)
				buf[-2] |= (uint32_t)data->sig.ret_args << 5;
			if (executive)
				TO(invoke_exe);
			else
				TO(switch_stack);
		})
		TRANSITION(switch_stack, {
			TO(clear_regs);
		})
		if (code == tramp_clear_regs) {
			if (data->sig.valid) {
				if (!data->sig.mem_args) {
					buf = mempcpy(buf, tramp_clear_regs,
					    sizeof(*tramp_clear_regs));
					size += sizeof(*tramp_clear_regs);
				}
				if (data->sig.ret_args != INDIRECT) {
					buf = mempcpy(buf, tramp_clear_regs + 1,
					    sizeof(*tramp_clear_regs));
					size += sizeof(*tramp_clear_regs);
				}
				int to_clear = 8 - data->sig.reg_args;
				buf = mempcpy(buf, tramp_clear_regs + 2,
				    sizeof(*tramp_clear_regs) * to_clear);
				size += sizeof(*tramp_clear_regs) * to_clear;
			}
			TO(invoke_res);
			continue;
		}
		TRANSITION(invoke_res, {
			if (utrace)
				TO(utrace_return);
			else
				TO(return);
		})
		TRANSITION(invoke_exe, {
			if (utrace)
				TO(utrace_return);
			else
				TO(return);
		})
		TRANSITION(utrace_return, {
			TO(return);
		})
		TRANSITION(return, {
			code = NULL;
		})
	}

	*(*entry)++ = data->target;

	return (size);

#undef IMPORT
#undef TRANSITION
#undef TO
}

static void *
tramp_pgs_append(const struct tramp_data *data)
{
	size_t len;
	/* A capability-aligned buffer large enough to hold a trampoline */
	tramp tmp[40];
	tramp *tramp, *entry = tmp;
	struct tramp_pg *pg;

	if (exclude_symbol_in_lib("libc.so.7", "rfork", data->obj, data->def) ||
	    exclude_symbol_in_lib("libc.so.7", "vfork", data->obj, data->def)) {
		return (data->target);
	}

	/* Fill a temporary buffer with the trampoline and obtain its length */
	len = tramp_compile(&entry, data);

	pg = atomic_load_explicit(&tramp_pgs.head, memory_order_acquire);
	tramp = tramp_pg_push(pg, len);
	if (!cheri_gettag(tramp)) {
		while (atomic_flag_test_and_set_explicit(&tramp_pgs.lock,
		    memory_order_acquire));
		pg = atomic_load_explicit(&tramp_pgs.head,
		    memory_order_relaxed);
		tramp = tramp_pg_push(pg, len);
		if (!cheri_gettag(tramp)) {
			pg = tramp_pg_new(pg);
			tramp = tramp_pg_push(pg, len);
			atomic_store_explicit(&tramp_pgs.head, pg,
			    memory_order_release);
		}
		atomic_flag_clear_explicit(&tramp_pgs.lock,
		    memory_order_release);
	}
	assert(cheri_gettag(tramp));

	entry = tramp + (entry - tmp);
	tramp = mempcpy(tramp, tmp, len);

	/*
	 * Ensure i- and d-cache coherency after writing executable code. The
	 * __clear_cache procedure rounds the addresses to cache-line-aligned
	 * addresses. Derive the start/end addresses from pg so that they have
	 * sufficiently large bounds to contain these rounded addresses.
	 */
	__clear_cache(cheri_copyaddress(pg, entry),
	    cheri_copyaddress(pg, tramp));

	entry = cheri_clearperm(entry, FUNC_PTR_REMOVE_PERMS);
	return (cheri_sealentry(cheri_capmode(entry)));
}

void *
tramp_intern(const struct tramp_data *data)
{
	void *entry;
	RtldLockState lockstate;
	const void *target = data->target;
	const uint32_t hash = pointerHash((uint64_t)target);
	slot_index slot, idx;
	vaddr_t key;
	int exp;

	assert(data->entry == NULL);

	if (((cheri_getperm(target) & CHERI_PERM_EXECUTE) == 0) ||
	    (cheri_getsealed(target) == 0) || (cheri_gettype(target) != 1))
		return (NULL);
#ifndef TRAMP_LINEAR_INSERTION
start:
#endif
	slot = hash;
#ifdef TRAMP_LINEAR_INSERTION
	wlock_acquire(rtld_tramp_lock, &lockstate);
#else
	rlock_acquire(rtld_tramp_lock, &lockstate);
#endif
	exp = tramp_table.exp;
	do {
		slot = nextSlot(slot, hash, exp);
		key = atomic_load_explicit(&tramp_table.map[slot].key,
		    memory_order_relaxed);
		if (key != 0)
			continue;
#ifndef TRAMP_LINEAR_INSERTION
		/*
		 * Invariant: tramp_table.size <= tramp_table.writers
		 *
		 * This can be shown by observing that every increment in
		 * tramp_table.size corresponds to an increment in
		 * tramp_table.writers.
		 */
		slot_index writers = atomic_fetch_add_explicit(
		    &tramp_table.writers, 1, memory_order_relaxed);
		/*
		 * Invariant: tramp_table.size <= writers < tramp_table.writers
		 */
		if (writers >= tramp_table_load_factor(exp)) {
			atomic_fetch_sub_explicit(&tramp_table.writers, 1,
			    memory_order_relaxed);
			lock_release(rtld_tramp_lock, &lockstate);
			goto start;
		}
#endif
		/*
		 * Invariant: writers < LOAD_FACTOR
		 *
		 * Hence tramp_table.size < LOAD_FACTOR.
		 *
		 * Race to acquire the current slot.
		 */
		if (atomic_compare_exchange_strong_explicit(
		    &tramp_table.map[slot].key, &key, (vaddr_t)target,
		    memory_order_relaxed, memory_order_relaxed))
			goto insert;
		else
#ifdef TRAMP_LINEAR_INSERTION
			rtld_fatal("tramp_intern failed to insert key");
#else
			atomic_fetch_sub_explicit(&tramp_table.writers, 1,
			    memory_order_relaxed);
#endif
	} while (key != (vaddr_t)target);
	/*
	 * Load-acquire the index until it becomes available.
	 */
	do
	        idx = atomic_load_explicit(&tramp_table.map[slot].index,
	            memory_order_acquire);
	while (idx == -1);
	entry = tramp_table.data[idx].entry;
	goto end;
insert:
	idx = atomic_fetch_add_explicit(&tramp_table.size, 1,
	    memory_order_relaxed);
	/*
	 * Invariant: tramp_table.size <= LOAD_FACTOR
	 *
	 * Construct the data array entry.
	 */
	entry = tramp_pgs_append(data);
	tramp_table.data[idx] = *data;
	tramp_table.data[idx].entry = entry;
	/*
	 * Store-release the index.
	 */
	atomic_store_explicit(&tramp_table.map[slot].index, idx,
	    memory_order_release);
	/*
	 * If tramp_table.size == LOAD_FACTOR, resize the table.
	 */
	if (idx + 1 == tramp_table_load_factor(exp)) {
#ifndef TRAMP_LINEAR_INSERTION
		/*
		 * Wait for other readers to complete.
		 */
		lock_upgrade(rtld_tramp_lock, &lockstate);
#endif
		/*
		 * There can be no other writer racing with us for the resize.
		 */
		resizeTable(exp + 1);
	}
end:
	lock_release(rtld_tramp_lock, &lockstate);
	return (entry);
}

void *
_rtld_sandbox_code(void *target, struct tramp_sig sig)
{
	const Obj_Entry *obj;

	if (sig.reg_args > 8)
		rtld_fatal(
		    "_rtld_sandbox_code: invalid tramp_sig.reg_args = %u",
		    sig.reg_args);

	if (cheri_gettag(target) &&
	    (cheri_getperm(target) & CHERI_PERM_EXECUTIVE) == 0) {

		obj = obj_from_addr(target);
		if (obj == NULL)
			rtld_fatal("%#p does not belong to any object", target);

		target =  tramp_intern(&(struct tramp_data) {
			.target = target,
			.obj = obj,
			.sig = sig
		});
	}

	return (target);
}

#endif

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

#ifdef __CHERI_PURE_CAPABILITY__
struct tls_data {
	uintcap_t	dtv_gen;
	int		tls_index;
	Elf_Addr	tls_offs;
	Elf_Addr	tls_size;
};

static void *
reloc_tlsdesc_alloc(int tlsindex, Elf_Addr tlsoffs, Elf_Addr tlssize)
{
	struct tls_data *tlsdesc;

	tlsdesc = xmalloc(sizeof(struct tls_data));
	tlsdesc->dtv_gen = tls_dtv_generation;
	tlsdesc->tls_index = tlsindex;
	tlsdesc->tls_offs = tlsoffs;
	tlsdesc->tls_size = tlssize;

	return (tlsdesc);
}
#else
struct tls_data {
	Elf_Addr	dtv_gen;
	int		tls_index;
	Elf_Addr	tls_offs;
};

static Elf_Addr
reloc_tlsdesc_alloc(int tlsindex, Elf_Addr tlsoffs)
{
	struct tls_data *tlsdesc;

	tlsdesc = xmalloc(sizeof(struct tls_data));
	tlsdesc->dtv_gen = tls_dtv_generation;
	tlsdesc->tls_index = tlsindex;
	tlsdesc->tls_offs = tlsoffs;

	return ((Elf_Addr)tlsdesc);
}
#endif

static void
reloc_tlsdesc(const Obj_Entry *obj, const Elf_Rela *rela, Elf_Addr *where,
    int flags, RtldLockState *lockstate)
{
	const Elf_Sym *def;
	const Obj_Entry *defobj;
	Elf_Addr offs;
#ifdef __CHERI_PURE_CAPABILITY__
	Elf_Addr size = where[3];
	void **wherec = (void **)where;
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
#ifdef __CHERI_PURE_CAPABILITY__
			wherec[0] = _rtld_tlsdesc_undef;
			where[2] = rela->r_addend;
#else
			where[0] = (Elf_Addr)_rtld_tlsdesc_undef;
			where[1] = rela->r_addend;
#endif
			return;
		}
	}
	offs += rela->r_addend;

	if (obj->tlsoffset != 0) {
		/* Variable is in initially allocated TLS segment */
#ifdef __CHERI_PURE_CAPABILITY__
		wherec[0] = _rtld_tlsdesc_static;
		where[2] = obj->tlsoffset + offs;
		where[3] = size;
#else
		where[0] = (Elf_Addr)_rtld_tlsdesc_static;
		where[1] = obj->tlsoffset + offs;
#endif
	} else {
		/* TLS offset is unknown at load time, use dynamic resolving */
#ifdef __CHERI_PURE_CAPABILITY__
		wherec[0] = _rtld_tlsdesc_dynamic;
		wherec[1] = reloc_tlsdesc_alloc(obj->tlsindex, offs, size);
#else
		where[0] = (Elf_Addr)_rtld_tlsdesc_dynamic;
		where[1] = reloc_tlsdesc_alloc(obj->tlsindex, offs);
#endif
	}
}

/*
 * Process the PLT relocations.
 */
int
reloc_plt(Obj_Entry *obj, int flags, RtldLockState *lockstate)
{
	const Elf_Rela *relalim;
	const Elf_Rela *rela;
#ifdef __CHERI_PURE_CAPABILITY__
	uintptr_t jump_slot_base;
#endif

	relalim = (const Elf_Rela *)((const char *)obj->pltrela +
	    obj->pltrelasize);
#ifdef __CHERI_PURE_CAPABILITY__
	jump_slot_base = (uintptr_t)cheri_clearperm(obj->text_rodata_cap,
	    FUNC_PTR_REMOVE_PERMS);
#endif
	for (rela = obj->pltrela; rela < relalim; rela++) {
		Elf_Addr *where;

		where = (Elf_Addr *)(obj->relocbase + rela->r_offset);

		switch(ELF_R_TYPE(rela->r_info)) {
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_JUMP_SLOT:
			/*
			 * XXX: This would be far more natural if the linker
			 * made it an R_MORELLO_RELATIVE-like fragment instead.
			 * https://git.morello-project.org/morello/llvm-project/-/issues/19
			 */
			*(uintptr_t *)where = cheri_sealentry(jump_slot_base +
			    *where);
			break;
#else
		case R_AARCH64_JUMP_SLOT:
			*where += (Elf_Addr)obj->relocbase;
			break;
#endif
#ifdef __CHERI_PURE_CAPABILITY__
		case R_MORELLO_TLSDESC:
#else
		case R_AARCH64_TLSDESC:
#endif
			reloc_tlsdesc(obj, rela, where, SYMLOOK_IN_PLT | flags,
			    lockstate);
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
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
			target = (uintptr_t)tramp_intern(&(struct tramp_data) {
				.target = (void *)target,
				.obj = defobj
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
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	ptr = (uintptr_t)tramp_intern(&(struct tramp_data) {
		.target = (void *)ptr,
		.obj = obj
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
			reloc_tlsdesc(obj, rela, where, flags, lockstate);
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

#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
	tramp_stk_table_t tls = xcalloc(DEFAULT_STACK_TABLE_SIZE, sizeof(*tls));
	tls[0] = _rtld_get_rstk;
	asm ("msr	ctpidr_el0, %0\n" :: "C" (tls));
#endif

	/*
	* Fix the size of the static TLS block by using the maximum
	* offset allocated so far and adding a bit for dynamic modules to
	* use.
	*/
	tls_static_space = tls_last_offset + tls_last_size +
	    RTLD_STATIC_TLS_EXTRA;

	_tcb_set(allocate_tls(objs, NULL, TLS_TCB_SIZE, TLS_TCB_ALIGN));
}

void *
__tls_get_addr(tls_index* ti)
{
	uintptr_t **dtvp;

	dtvp = &_tcb_get()->tcb_dtv;
	return (tls_get_addr_common(dtvp, ti->ti_module, ti->ti_offset));
}
