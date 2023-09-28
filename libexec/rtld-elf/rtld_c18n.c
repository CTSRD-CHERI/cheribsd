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

const char *ld_compartment_utrace;	/* Use utrace() to log compartmentalisation-related events */
const char *ld_compartment_enable;	/* Enable compartmentalisation */
const char *ld_compartment_overhead;	/* Simulate overhead during compartment transitions */

/*
 * libthr support
 */
void (*thr_thread_start)(struct pthread *);

void
_rtld_thread_start_init(void (*p)(struct pthread *))
{
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	assert(thr_thread_start == NULL);
	thr_thread_start = tramp_intern(NULL, &(struct tramp_data) {
		.target = p,
		.defobj = obj_from_addr(p),
		.sig = (struct tramp_sig) {
			.valid = true,
			.reg_args = 1, .mem_args = false, .ret_args = NONE
		}
	});
}

void (*thr_sighandler)(int, siginfo_t *, void *);

void
_rtld_sighandler_init(void (*p)(int, siginfo_t *, void *))
{
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	assert(thr_sighandler == NULL);
	thr_sighandler = tramp_intern(NULL, &(struct tramp_data) {
		.target = p,
		.defobj = obj_from_addr(p),
		.sig = (struct tramp_sig) {
			.valid = true,
			.reg_args = 3, .mem_args = false, .ret_args = NONE
		}
	});
}

/*
 * Policies
 */
typedef ssize_t string_handle;

struct string_base {
	char *buf;
	string_handle size;
	string_handle capacity;
};

__unused static struct string_base *
string_base_create(string_handle capacity)
{
	struct string_base *sb = xmalloc(sizeof(*sb));
	sb->buf = xmalloc(sizeof(*sb->buf) * capacity);
	sb->size = 0;
	sb->capacity = capacity;
	return (sb);
}

__unused static string_handle
string_base_push(struct string_base *sb, const char *str)
{
	string_handle handle = sb->size;
	do {
		sb->buf[sb->size++] = *str;
		if (sb->size == sb->capacity) {
			sb->capacity *= 2;
			sb->buf = realloc(sb->buf,
			    sizeof(*sb->buf) * sb->capacity);
			if (sb->buf == NULL)
				rtld_fatal("realloc failed");
		}
	} while (*str++ != '\0');
	return (handle);
}

static string_handle
string_base_search(const struct string_base *sb, const char *str)
{
	string_handle i = 0;
	do {
		const char *cur = str;
		while (sb->buf[i] == *cur++)
			if (sb->buf[i++] == '\0')
				return (i);
		while (sb->buf[i] != '\0') ++i;
	} while (++i < sb->size);
	return (-1);
}

static char trusted_globals_names[] =
	"memset\0"
	"memcpy\0"
	"mempcpy\0"
	"memccpy\0"
	"memchr\0"
	"memrchr\0"
	"memmove\0"
	"strcpy\0"
	"strncpy\0"
	"stpcpy\0"
	"stpncpy\0"
	"strcat\0"
	"strncat\0"
	"strlcpy\0"
	"strlcat\0"
	"strlen\0"
	"strnlen\0"
	"strcmp\0"
	"strncmp\0"

	"__libc_start1\0"
	"setjmp\0"
	"longjmp\0"
	"_setjmp\0"
	"_longjmp\0"
	"sigsetjmp\0"
	"siglongjmp\0"

	"vfork\0"
	"rfork\0"

	/* See comment in function definition */
	"_rtld_thread_start";

static const struct string_base trusted_globals = {
	.buf = trusted_globals_names,
	.size = sizeof(trusted_globals_names),
	.capacity = sizeof(trusted_globals_names)
};

static struct compart rtld_compart = {
	.name = _BASENAME_RTLD
};

static struct {
	const struct compart **data;
	compart_id_t size;
	compart_id_t capacity;
} comparts;

static void
comparts_data_expand(compart_id_t capacity)
{
	const struct compart **data;

	data = realloc(comparts.data, sizeof(*data) * capacity);
	if (data == NULL)
		rtld_fatal("realloc failed");
	comparts.data = data;
	comparts.capacity = capacity;
}

static bool
string_search(const char *const strs[], const char *sym)
{
	if (strs != NULL)
		for (; *strs != NULL; ++strs)
			if (strcmp(sym, *strs) == 0)
				return (true);
	return (false);
}

static const struct compart *const *
compart_get_or_create(const char *lib)
{
	struct {
		const char *libraries[2];
		struct compart com;
	} *buf;
	for (compart_id_t i = 1; i < comparts.size; ++i)
		if (string_search(comparts.data[i]->libraries, lib))
			return (&comparts.data[i]);
	if (comparts.size == comparts.capacity)
		comparts_data_expand(comparts.capacity * 2);
	buf = xmalloc(sizeof(*buf));
	buf->libraries[0] = lib;
	buf->libraries[1] = NULL;
	buf->com = (struct compart) {
		.name = lib,
		.libraries = buf->libraries
	};
	comparts.data[comparts.size] = &buf->com;
	return (&comparts.data[comparts.size++]);
}

compart_id_t
compart_id_allocate(const char *name)
{
	const struct compart *const *com = compart_get_or_create(name);
	return (com - comparts.data);
}

static bool
tramp_should_include(const Obj_Entry *reqobj, const struct tramp_data *data)
{
	const char *sym;

	if (data->target == NULL)
		return (false);

	if (reqobj == NULL)
		return (true);

	if (reqobj->compart_id == data->defobj->compart_id)
		return (false);

	sym = strtab_value(data->defobj, data->def->st_name);

	if (string_base_search(&trusted_globals, sym) != -1)
		return (false);

	return (true);
}

/*
 * Trampolines
 */
struct tramp_pg {
	_Atomic(void *) cursor;		/* Start of unused space */
	SLIST_ENTRY(tramp_pg) link;	/* Link to next page */
	void *trampolines[];		/* Start of trampolines */
};

/*
* 64K is the largest size such that any capability-aligned proper
* sub-range can be exactly bounded by a Morello capability.
*/
#define	C18N_TRAMPOLINE_PAGE_SIZE	64 * 1024

static struct tramp_pg *
tramp_pg_new(struct tramp_pg *next)
{
	struct tramp_pg *pg = mmap(NULL,
	    C18N_TRAMPOLINE_PAGE_SIZE,
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
		ptraddr_t n_cur_addr;
		ptrdiff_t n_cur_len;

		tramp = cheri_setbounds(cur, len);
		n_cur_addr = roundup2(cheri_gettop(tramp), _Alignof(void *));
		n_cur_len = cheri_gettop(cur) - n_cur_addr;

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

typedef ssize_t slot_idx_t;

static struct {
	struct tramp_data *data;
	struct tramp_map_kv {
		_Atomic(ptraddr_t) key;
		_Atomic(slot_idx_t) index;
	} *map;
	_Atomic(slot_idx_t) size;
	_Atomic(slot_idx_t) writers;
	int exp;
} tramp_table;

static struct {
	_Atomic(struct tramp_pg *) head;
	atomic_flag lock;
} tramp_pgs = {
	.lock = ATOMIC_FLAG_INIT
};

static slot_idx_t
tramp_table_max_load(int exp)
{
	/* MAX_LOAD is 37.5% of capacity. */
	return (3 << (exp - 3));
}

static struct tramp_map_kv *
tramp_map_new(int exp)
{
	struct tramp_map_kv *map;

	map = xmalloc(sizeof(*map) << exp);
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
	struct tramp_data *data;
	/*
	 * The table only needs to be as large as the MAX_LOAD.
	 */
	data = realloc(tramp_table.data, sizeof(*data) * tramp_table_max_load(exp));
	if (data == NULL)
		rtld_fatal("realloc failed");
	return (data);
}

/* Public domain. Taken from https://github.com/skeeto/hash-prospector */
static uint32_t
pointer_hash(uint64_t key)
{
	uint32_t x = key ^ (key >> 32);
	x ^= x >> 16;
	x *= 0x21f0aaadU;
	x ^= x >> 15;
	x *= 0xd35a2d97U;
	x ^= x >> 15;
	return (x);
}

static slot_idx_t
nextSlot(slot_idx_t slot, uint32_t hash, int exp)
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
	slot_idx_t size, slot;

	assert(0 < exp && exp < 32);

	free(tramp_table.map);
	data = tramp_data_expand(exp);
	map = tramp_map_new(exp);
	size = atomic_load_explicit(&tramp_table.size, memory_order_relaxed);

	for (slot_idx_t idx = 0; idx < size; ++idx) {
		key = (ptraddr_t)data[idx].target;
		hash = pointer_hash(key);
		slot = hash;
		do
			slot = nextSlot(slot, hash, exp);
		while (atomic_load_explicit(&map[slot].key,
		    memory_order_relaxed) != 0);
		atomic_store_explicit(&map[slot].key, key,
		    memory_order_relaxed);
		atomic_store_explicit(&map[slot].index, idx,
		    memory_order_relaxed);
	}

	tramp_table.data = data;
	tramp_table.map = map;
	tramp_table.exp = exp;
}

void
tramp_hook(int event, void *target, const Obj_Entry *obj, const Elf_Sym *def,
    void *link, void *rcsp)
{
	Elf64_Word sym_num;
	const char *sym;
	const char *callee;

	compart_id_t caller_id;
	const char *caller;

	sym_num = def == NULL ? 0 : def->st_name;
	sym = def == NULL ? "<unknown>" : strtab_value(obj, def->st_name);
	callee = comparts.data[obj->compart_id]->name;

	if ((cheri_getperm(link) & CHERI_PERM_EXECUTIVE) == 0)
		caller_id = ((uintptr_t *)
		    cheri_setaddress(rcsp, cheri_gettop(rcsp)))[-2];
	else
		caller_id = 0;
	caller = comparts.data[caller_id]->name;

	if (ld_compartment_utrace != NULL)
		ld_utrace_log(event,
			target, NULL, sym_num, 0, callee, sym, caller);
	if (ld_compartment_overhead != NULL)
		getpid();
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
	memcpy(tramp, tmp, len);

	/*
	 * Ensure i- and d-cache coherency after writing executable code. The
	 * __clear_cache procedure rounds the addresses to cache-line-aligned
	 * addresses. Derive the start/end addresses from pg so that they have
	 * sufficiently large bounds to contain these rounded addresses.
	 */
	__clear_cache(cheri_copyaddress(pg, entry),
	    cheri_copyaddress(pg, (char *)tramp + len));

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
	return (!lhs.valid || !rhs.valid || tramp_sig_equal(lhs, rhs));
}

static void *
tramp_get_entry(const struct tramp_data *found, const struct tramp_data *data)
{
	if (!tramp_sig_compatible(found->sig, data->sig))
		rtld_fatal(
		    "Incompatible signatures for function %s: "
		    "%s requests %02hhX but %s provides %02hhX",
		    strtab_value(data->defobj, data->def->st_name),
		    data->defobj->path, tramp_sig_to_int(data->sig),
		    found->defobj->path, tramp_sig_to_int(found->sig));

	return (found->entry);
}

static void *
tramp_create_entry(struct tramp_data *found, const struct tramp_data *data)
{
	struct tramp_sig sig;

	*found = *data;
	if (found->def != NULL) {
		sig = tramp_fetch_sig(found->defobj,
		    found->def - found->defobj->symtab);
		if (!found->sig.valid)
			found->sig = sig;
		else if (!tramp_sig_compatible(found->sig, sig))
			rtld_fatal(
			    "Incompatible signatures for function %s: "
			    "requests %02hhX but %s provides %02hhX",
			    strtab_value(found->defobj, found->def->st_name),
			    tramp_sig_to_int(found->sig), found->defobj->path,
			    tramp_sig_to_int(sig));
	}

	return (found->entry = tramp_pgs_append(found));
}

void *
tramp_intern(const Obj_Entry *reqobj, const struct tramp_data *data)
{
	void *entry;
	RtldLockState lockstate;
	ptraddr_t target = (ptraddr_t)data->target;
	const uint32_t hash = pointer_hash(target);
	slot_idx_t slot, idx;
	ptraddr_t key;
	int exp;

	/* reqobj == NULL iff the request is by RTLD */
	assert(
	    (reqobj == NULL || data->def != NULL) &&
	    data->defobj != NULL &&
	    data->entry == NULL &&
	    tramp_sig_legal(data->sig));

	if (!tramp_should_include(reqobj, data))
		return (data->target);

start:
	slot = hash;
	rlock_acquire(rtld_tramp_lock, &lockstate);
	exp = tramp_table.exp;
	do {
		slot = nextSlot(slot, hash, exp);
		key = atomic_load_explicit(&tramp_table.map[slot].key,
		    memory_order_relaxed);
		if (key != 0)
			continue;
		/*
		 * Invariant: tramp_table.size <= tramp_table.writers
		 *
		 * This can be shown by observing that every increment in
		 * tramp_table.size corresponds to an increment in
		 * tramp_table.writers.
		 */
		slot_idx_t writers = atomic_fetch_add_explicit(
		    &tramp_table.writers, 1, memory_order_relaxed);
		/*
		 * Invariant: tramp_table.size <= writers < tramp_table.writers
		 */
		if (writers >= tramp_table_max_load(exp)) {
			atomic_fetch_sub_explicit(&tramp_table.writers, 1,
			    memory_order_relaxed);
			lock_release(rtld_tramp_lock, &lockstate);
			goto start;
		}
		/*
		 * Invariant: writers < MAX_LOAD
		 *
		 * Hence tramp_table.size < MAX_LOAD.
		 *
		 * Race to acquire the current slot.
		 */
		if (atomic_compare_exchange_strong_explicit(
		    &tramp_table.map[slot].key, &key, target,
		    memory_order_relaxed, memory_order_relaxed))
			goto insert;
		else
			atomic_fetch_sub_explicit(&tramp_table.writers, 1,
			    memory_order_relaxed);
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
	 * Invariant: tramp_table.size <= MAX_LOAD
	 *
	 * Create the data array entry.
	 */
	entry = tramp_create_entry(&tramp_table.data[idx], data);
	/*
	 * Store-release the index.
	 */
	atomic_store_explicit(&tramp_table.map[slot].index, idx,
	    memory_order_release);
	/*
	 * If tramp_table.size == MAX_LOAD, resize the table.
	 */
	if (idx + 1 == tramp_table_max_load(exp)) {
		/*
		 * Wait for other readers to complete.
		 */
		lock_upgrade(rtld_tramp_lock, &lockstate);
		/*
		 * There can be no other writer racing with us for the resize.
		 */
		resizeTable(exp + 1);
	}
end:
	lock_release(rtld_tramp_lock, &lockstate);
	return (entry);
}

/*
 * APIs
 */
struct tramp_sig
tramp_fetch_sig(const Obj_Entry *obj, unsigned long symnum)
{
	if (symnum >= obj->dynsymcount)
		rtld_fatal("Invalid symbol number %lu for object %s.",
		    symnum, obj->path);
	else if (obj->sigtab == NULL)
		return ((struct tramp_sig) {});
	else
		return (obj->sigtab[symnum]);
}

void
tramp_init(void)
{
	comparts_data_expand(1);
	comparts.data[comparts.size++] = &rtld_compart;

	int exp = 9;
	tramp_table.data = tramp_data_expand(exp);
	tramp_table.map = tramp_map_new(exp);
	tramp_table.exp = exp;

	atomic_store_explicit(&tramp_pgs.head, tramp_pg_new(NULL),
	    memory_order_relaxed);
}

void
tramp_add_comparts(struct policy *pol)
{
	if (pol == NULL)
		return;
	comparts_data_expand(comparts.size + pol->count);
	for (size_t i = 0; i < pol->count; ++i)
		comparts.data[comparts.size++] = &pol->coms[i];
}
