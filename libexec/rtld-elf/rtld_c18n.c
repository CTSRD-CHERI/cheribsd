/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021-2023 Dapeng Gao
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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <stdatomic.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_c18n.h"
#include "rtld_libc.h"
#include "rtld_utrace.h"

/*
 * Sealers for RTLD privileged information
 */
uintptr_t sealer_pltgot, sealer_jmpbuf, sealer_tramp;

const char *ld_utrace_compartment;	/* Use utrace() to log compartmentalisation-related events. */
const char *ld_compartment_overhead;	/* Simulate overhead during compartment transitions. */

uint16_t allocate_compart_id(void)
{
	static uint16_t max_compart_id;
	if (++max_compart_id == 0)
		rtld_fatal("max_compart_id overflowed");
	return (max_compart_id);
}


void _rtld_thread_start(struct pthread *);
void _rtld_sighandler(int, siginfo_t *, void *);
void *get_rstk(const void *, uint32_t, tramp_stk_table_t);

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

	ptraddr_t top = cheri_gettop(tls);
	for (tramp_stk_table_t cur = &tls[1]; (ptraddr_t)cur < top; ++cur) {
		void *stk = cheri_setaddress(*cur, cheri_getbase(*cur));
		if (stk != NULL && munmap(stk, DEFAULT_SANDBOX_STACK_SIZE) != 0)
			rtld_fatal("munmap failed");
	}
	free(tls);

	thr_exit(state);
}

static void (*thr_sighandler)(int, siginfo_t *, void *);

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

static bool
exclude_symbol_in_lib(const char *name, const char *sym, const struct tramp_data *data)
{
	Name_Entry *entry;

	if (data->def == NULL ||
	    strcmp(sym, strtab_value(data->obj, data->def->st_name)) != 0)
		return (false);

	STAILQ_FOREACH(entry, &data->obj->names, link) {
		if (strcmp(name, entry->name) == 0)
			return (true);
	}
	return (false);
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
		_Atomic ptraddr_t key;
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

/* Taken from https://github.com/skeeto/hash-prospector/issues/19 */
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
	ptraddr_t key;
	uint32_t hash;
	slot_index size, slot;

	assert(0 < exp && exp < 32);

	free(tramp_table.map);
	data = tramp_data_expand(exp);
	map = tramp_map_new(exp);
	size = atomic_load_explicit(&tramp_table.size, memory_order_relaxed);

	for (slot_index idx = 0; idx < size; ++idx) {
		key = (ptraddr_t)data[idx].target;
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

static void
tramp_hook(int event, void *target, const Obj_Entry *obj, const Elf_Sym *def)
{
	Elf64_Word sym_num = def == NULL ? 0 : def->st_name;
	const char *name = STAILQ_EMPTY(&obj->names) ? obj->path :
	    STAILQ_FIRST(&obj->names)->name;
	const char *sym = def == NULL ? "<unknown>" :
	    strtab_value(obj, def->st_name);
	void *tls;

	if (ld_utrace_compartment != NULL) {
		asm ("mrs	%0, rctpidr_el0" : "=C" (tls));
		if (event == 0)
			ld_utrace_log(UTRACE_COMPARTMENT_ENTER,
			    target, tls, sym_num, 0, name, sym);
		else
			ld_utrace_log(UTRACE_COMPARTMENT_LEAVE,
			    target, tls, sym_num, 0, name, sym);
	}
	if (ld_compartment_overhead != NULL) {
		getpid();
	}
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
	IMPORT(header_hook);
	IMPORT(header_res);
	IMPORT(save_caller);
	IMPORT(switch_stack);
	IMPORT(clear_regs);
	IMPORT(invoke_res);
	IMPORT(invoke_exe);
	IMPORT(return_hook);
	IMPORT(return);

	uint32_t *buf = (void *)*entry;
	size_t size = 0;
	bool executive = cheri_getperm(data->target) & CHERI_PERM_EXECUTIVE;
	bool hook = ld_utrace_compartment != NULL ||
	    ld_compartment_overhead != NULL;

	for (const void *code = hook ? tramp_header_hook : tramp_header;
	    code != NULL; ) {
		TRANSITION(header, {
			if (executive)
				TO(save_caller);
			else
				TO(header_res);
		})
		TRANSITION(header_hook, {
			if (executive)
				TO(save_caller);
			else
				TO(header_res);
			*(*entry)++ = data->obj;
			*(*entry)++ = data->def;
			*(*entry)++ = tramp_hook;
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
			if (hook)
				TO(return_hook);
			else
				TO(return);
		})
		TRANSITION(invoke_exe, {
			if (hook)
				TO(return_hook);
			else
				TO(return);
		})
		TRANSITION(return_hook, {
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
	tramp tmp[48];
	tramp *tramp, *entry = tmp;
	struct tramp_pg *pg;

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

static bool
tramp_sig_equal(struct tramp_sig lhs, struct tramp_sig rhs)
{
	return (lhs.reg_args == rhs.reg_args &&
		lhs.mem_args == rhs.mem_args &&
		lhs.ret_args == rhs.ret_args);
}

static bool
tramp_sig_compatible(struct tramp_sig lhs, struct tramp_sig rhs)
{
	return (!(lhs.valid && rhs.valid) || tramp_sig_equal(lhs, rhs));
}

static bool
tramp_sig_resolve(struct tramp_sig *lhs, struct tramp_sig rhs)
{
	if (!lhs->valid) {
		*lhs = rhs;
		return (true);
	}
	return (!rhs.valid || tramp_sig_equal(*lhs, rhs));
}

static tramp_sig_int
tramp_sig_to_int(struct tramp_sig sig)
{
	tramp_sig_int ret;
	memcpy(&ret, &sig, sizeof(tramp_sig_int));
	return ret;
}

static void *
tramp_get_entry(const struct tramp_data *found, const struct tramp_data *data)
{
	if (tramp_sig_compatible(found->sig, data->sig))
		return (found->entry);
	else
		rtld_fatal(
		    "Incompatible signatures for function %s: "
		    "%s requests %02hhX and %s provides %02hhX",
		    strtab_value(data->obj, data->def->st_name),
		    data->obj->path, tramp_sig_to_int(data->sig),
		    found->obj->path, tramp_sig_to_int(found->sig));
}

static void *
tramp_create_entry(struct tramp_data *data)
{
	struct tramp_sig sig;

	if (exclude_symbol_in_lib("libc.so.7", "rfork", data) ||
	    exclude_symbol_in_lib("libc.so.7", "vfork", data)) {
		return (data->target);
	}

	if (data->def != NULL) {
		sig = fetch_tramp_sig(data->obj, data->def - data->obj->symtab);
		if (!tramp_sig_resolve(&data->sig, sig))
			rtld_fatal(
			    "Incompatible signatures for function %s: "
			    "requests %02hhX and %s provides %02hhX",
			    strtab_value(data->obj, data->def->st_name),
			    tramp_sig_to_int(data->sig), data->obj->path,
			    tramp_sig_to_int(sig));
	}

	return (data->entry = tramp_pgs_append(data));
}

void *
tramp_intern(const struct tramp_data *data)
{
	void *entry;
	RtldLockState lockstate;
	ptraddr_t target = (ptraddr_t)data->target;
	const uint32_t hash = pointerHash(target);
	slot_index slot, idx;
	ptraddr_t key;
	int exp;

	assert(data->entry == NULL);

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
		    &tramp_table.map[slot].key, &key, target,
		    memory_order_relaxed, memory_order_relaxed))
			goto insert;
		else
#ifdef TRAMP_LINEAR_INSERTION
			rtld_fatal("tramp_intern failed to insert key");
#else
			atomic_fetch_sub_explicit(&tramp_table.writers, 1,
			    memory_order_relaxed);
#endif
	} while (key != target);
	/*
	 * Load-acquire the index until it becomes available.
	 */
	do
	        idx = atomic_load_explicit(&tramp_table.map[slot].index,
	            memory_order_acquire);
	while (idx == -1);
	entry = tramp_get_entry(&tramp_table.data[idx], data);
	goto end;
insert:
	idx = atomic_fetch_add_explicit(&tramp_table.size, 1,
	    memory_order_relaxed);
	/*
	 * Invariant: tramp_table.size <= LOAD_FACTOR
	 *
	 * Create the data array entry.
	 */
	tramp_table.data[idx] = *data;
	entry = tramp_create_entry(&tramp_table.data[idx]);
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

static void
tramp_sig_validate(struct tramp_sig sig)
{
	if (sig.valid && sig.reg_args > 8)
		rtld_fatal("Invalid tramp_sig.reg_args = %u", sig.reg_args);
}

static long
tramp_sig_to_otype(struct tramp_sig sig)
{
	return (sig.ret_args | (sig.mem_args << 2) | (sig.reg_args << 3));
}

void *
_rtld_sandbox_code(void *target, struct tramp_sig sig)
{
	const Obj_Entry *obj;
	void *target_unsealed;

	tramp_sig_validate(sig);

	if ((cheri_getperm(target) & CHERI_PERM_EXECUTIVE) != 0)
		return (target);

	obj = obj_from_addr(target);
	if (obj == NULL)
		rtld_fatal("%#p does not belong to any object", target);

	target_unsealed = cheri_unseal(target, sealer_tramp);
	if (cheri_gettag(target_unsealed)) {
		if (sig.valid &&
		    cheri_gettype(target) !=
		    (long)cheri_getbase(sealer_tramp) + tramp_sig_to_otype(sig))
			rtld_fatal("Signature mismatch");
		target = cheri_sealentry(target_unsealed);
	}

	target = tramp_intern(&(struct tramp_data) {
		.target = target,
		.obj = obj,
		.sig = sig
	});

	return (target);
}

void *
_rtld_safebox_code(void *target, struct tramp_sig sig)
{
	const Obj_Entry *obj;

	tramp_sig_validate(sig);

	if ((cheri_getperm(target) & CHERI_PERM_EXECUTIVE) != 0)
		return (target);

	obj = obj_from_addr(target);
	if (obj == NULL)
		rtld_fatal("%#p does not belong to any object", target);

	if (sig.valid) {
		asm ("chkssu	%0, %0, %1\n"
		    : "=C" (target)
		    : "C" (obj->text_rodata_cap));
		target = cheri_seal(target,
		    sealer_tramp + tramp_sig_to_otype(sig));
	}

	return target;
}

struct tramp_sig
fetch_tramp_sig(const Obj_Entry *obj, unsigned long symnum)
{
	if (obj->sigtab == NULL)
		return ((struct tramp_sig) {});
	else if (symnum < obj->dynsymcount)
		return (obj->sigtab[symnum]);
	else
		rtld_fatal("Invalid symbol number %lu for object %s.",
		    symnum, obj->path);
}
