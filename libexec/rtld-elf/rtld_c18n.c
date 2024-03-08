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

#include <sys/param.h>
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_c18n.h"
#include "rtld_libc.h"
#include "rtld_utrace.h"

/*
 * Sealers for RTLD privileged information
 */
static uintptr_t sealer_jmpbuf;

uintptr_t sealer_pltgot, sealer_tramp;

/* Use utrace() to log compartmentalisation-related events */
const char *ld_compartment_utrace;

/* Enable compartmentalisation */
const char *ld_compartment_enable;

/* Simulate overhead during compartment transitions */
const char *ld_compartment_overhead;

/* Read the .c18n.signature ELF section */
const char *ld_compartment_sig;

/*
 * Policies
 */
typedef ssize_t string_handle;

struct string_base {
	char *buf;
	string_handle size;
	string_handle capacity;
};

static string_handle
string_base_search(const struct string_base *sb, const char *str)
{
	const char *cur;
	string_handle i = 0, s;

	do {
		s = i;
		cur = str;
		while (sb->buf[i] == *cur++)
			if (sb->buf[i++] == '\0')
				return (s);
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
	"memmem\0"
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
	"strchr\0"
	"strrchr\0"
	"strchrnul\0"
	"strspn\0"
	"strcspn\0"
	"strpbrk\0"
	"strsep\0"
	"strstr\0"
	"strnstr\0"

	"__libc_start1\0"
	"setjmp\0"
	"longjmp\0"
	"_setjmp\0"
	"_longjmp\0"
	"sigsetjmp\0"
	"siglongjmp\0"

	"vfork\0"
	"rfork\0"

	"_rtld_thread_start";

static const struct string_base trusted_globals = {
	.buf = trusted_globals_names,
	.size = sizeof(trusted_globals_names),
	.capacity = sizeof(trusted_globals_names)
};

static struct compart rtld_compart = {
	.name = _BASENAME_RTLD
};

static struct compart tcb_compart = {
	.name = "[TCB]",
	.libraries = (const char *[]) {
		"libc.so.7",
		"libthr.so.3",
		NULL
	}
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
string_search(const char * const strs[], const char *sym)
{
	if (strs != NULL)
		for (; *strs != NULL; ++strs)
			if (strcmp(sym, *strs) == 0)
				return (true);
	return (false);
}

static const struct compart * const *
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
	size_t index;

	index = compart_get_or_create(name) - comparts.data;
	if (index > C18N_COMPARTMENT_ID_MAX)
		rtld_fatal("Cannot allocate compartment ID");

	return (index);
}

static bool
tramp_should_include(const Obj_Entry *reqobj, const struct tramp_data *data)
{
	const char *sym;

	if (!cheri_gettag(data->target))
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
 * Stack switching
 */
void *allocate_rstk(unsigned);

static compart_id_t
stack_index_to_compart_id(unsigned index)
{
	struct stk_table dummy;

	return (sizeof(dummy.stacks->bottom) * index / sizeof(*dummy.stacks));
}

static size_t
compart_id_to_stack_index(compart_id_t cid)
{
	struct stk_table dummy;

	return (cid - offsetof(typeof(dummy), stacks) / sizeof(*dummy.stacks));
}

static void init_compart_stack(void **, compart_id_t);

static void
init_compart_stack(void **stk, compart_id_t cid)
{
	/*
	 * INVARIANT: The bottom of a compartment's stack contains a capability
	 * to the top of the stack either when the compartment was last entered
	 * or when it was last exited from, which ever occured later.
	 */
	stk[-1] = cheri_clearperm(stk - 1, CHERI_PERM_SW_VMEM);
	if (
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	    /*
	     * Do not check whether tracing is enabled if initialising the RTLD
	     * stack because the global variable might not have been relocated
	     * yet. This is only needed under the benchmark ABI, which has the
	     * concept of an RTLD stack.
	     */
	    cid == C18N_RTLD_COMPART_ID ||
#endif
	    ld_compartment_utrace != NULL)
		*--((uintptr_t **)stk)[-1] = cid;
}

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
uintptr_t c18n_init_rtld_stack(uintptr_t, void **);

uintptr_t
c18n_init_rtld_stack(uintptr_t ret, void **csp)
{
	init_compart_stack(csp, C18N_RTLD_COMPART_ID);

	return (ret);
}

/*
 * Save the initial stack (either at program launch or at thread start) in the
 * stack table.
 */
static void
init_stk_table(struct stk_table *table)
{
	void *sp = cheri_getstack();
	table->stacks[compart_id_to_stack_index(C18N_RTLD_COMPART_ID)].bottom =
	    cheri_setoffset(sp, cheri_getlen(sp));
}
#else
/*
 * Set a dummy Restricted stack so that trampolines do not need to test if the
 * Restricted stack is valid.
 */
static void *dummy_stack[1] = { &dummy_stack[0] };
#endif

static _Atomic(struct stk_table *) free_stk_tables;

static _Atomic(size_t) free_stk_table_cnt;

static void
push_stk_table(_Atomic(struct stk_table *) *head, struct stk_table *table)
{
	struct stk_table **link = &SLIST_NEXT(table, next);

	*link = atomic_load_explicit(head, memory_order_relaxed);

	while (!atomic_compare_exchange_weak_explicit(head, link, table,
	    /*
	     * Use release ordering to ensure that table construction happens
	     * before the push.
	     */
	    memory_order_release, memory_order_release));
}

static struct stk_table *
pop_stk_table(_Atomic(struct stk_table *) *head)
{
	struct stk_table *table, *next;

	table = atomic_load_explicit(head, memory_order_relaxed);

	/* No ABA problem because a stack table is never deallocated */
	do {
		next = SLIST_NEXT(table, next);
	} while (!atomic_compare_exchange_weak_explicit(head, &table, next,
	    /*
	     * Use acquire ordering to ensure that the pop happens after table
	     * construction.
	     */
	    memory_order_acquire, memory_order_acquire));

	table->resolver = allocate_rstk;

	return (table);
}

static struct stk_table *
stk_table_expand(struct stk_table *table, size_t n_capacity, bool lock)
{
	size_t o_capacity;
	RtldLockState lockstate;
	bool create = table == NULL;

	if (lock)
		wlock_acquire(rtld_bind_lock, &lockstate);
	table = realloc(table, sizeof(*table) +
	    sizeof(*table->stacks) * n_capacity);
	if (lock)
		lock_release(rtld_bind_lock, &lockstate);
	if (table == NULL)
		rtld_fatal("realloc failed");

	if (create) {
		table->resolver = allocate_rstk;
		o_capacity = 0;
	} else
		o_capacity = table->capacity;

	table->capacity =
	    (cheri_getlen(table) - offsetof(typeof(*table), stacks)) /
	    sizeof(*table->stacks);

	memset(&table->stacks[o_capacity], 0,
	    sizeof(*table->stacks) * (table->capacity - o_capacity));

	return (table);
}

void
allocate_stk_table(void)
{
	size_t cnt;

	/*
	 * Every call to this function is paired with a call to pop_stk_table
	 * later. If there are free stacks available, we do not actually
	 * allocate a new stack but rather decrement the counter to reserve one
	 * for the later pop.
	 */
	cnt = atomic_load_explicit(&free_stk_table_cnt, memory_order_relaxed);

	do {
		if (cnt == 0) {
			/*
			 * Allocate new stack tables to have the same capacity
			 * as the compartment array.
			 */
			push_stk_table(&free_stk_tables,
			    stk_table_expand(NULL, comparts.capacity, false));
			break;
		}
	} while (!atomic_compare_exchange_weak_explicit(
	    &free_stk_table_cnt, &cnt, cnt - 1,
	    /*
	     * Use acquire ordering to ensure that the pop happens after the
	     * earlier push.
	     */
	    memory_order_acquire, memory_order_acquire));
}

static void
free_stk_table(struct stk_table *table)
{
	push_stk_table(&free_stk_tables, table);
	/*
	 * Use release ordering to ensure that the push happens before the later
	 * pop.
	 */
	atomic_fetch_add_explicit(&free_stk_table_cnt, 1, memory_order_release);
}

static void *
stk_create(size_t size)
{
	char *stk;

	stk = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_STACK, -1, 0);
	if (stk == MAP_FAILED)
		rtld_fatal("mmap failed");

	stk = cheri_clearperm(stk + size, CHERI_PERM_EXECUTIVE);

	return (stk);
}

/* Default stack size in libthr */
#define	C18N_STACK_SIZE	(sizeof(void *) / 4 * 1024 * 1024)

void *allocate_rstk_impl(unsigned);

void *
allocate_rstk_impl(unsigned index)
{
	void *stk;
	size_t capacity, size;
	compart_id_t cid, cid_off;
	struct stk_table *table;

	table = stk_table_get();

	cid = stack_index_to_compart_id(index);
	cid_off = compart_id_to_stack_index(cid);

	capacity = table->capacity;
	if (capacity <= cid_off) {
		capacity = MAX(capacity * 2, cid_off + 1);
		table = stk_table_expand(table, capacity, true);
		stk_table_set(table);
	}
	assert(table->stacks[cid_off].bottom == NULL);

	size = C18N_STACK_SIZE;
	stk = stk_create(size);
	init_compart_stack(stk, cid);

	table->stacks[cid_off].bottom = stk;
	table->stacks[cid_off].size = size;

	return (stk);
}

struct trusted_frame {
	ptraddr_t next;
	uint8_t ret_args : 2;
	ptraddr_t cookie : 62;
	/*
	 * INVARIANT: This field contains the top of the caller's stack when the
	 * caller was last entered.
	 */
	void **o_stack;
	void *ret_addr;
};

/*
 * Returning this struct allows us to control the content of unused return value
 * registers.
 */
struct jmp_args { uintptr_t ret; uintptr_t dummy; };

struct jmp_args _rtld_setjmp_impl(uintptr_t, void **, struct trusted_frame *);

struct jmp_args
_rtld_setjmp_impl(uintptr_t ret, void **buf, struct trusted_frame *csp)
{
	/*
	 * Before setjmp is called, the top of the Executive stack contains:
	 * 	0.	Link to previous frame
	 * setjmp does not push to the Executive stack. When _rtld_setjmp is
	 * called, the following are pushed to the Executive stack:
	 * 	1.	Caller's data
	 * 	2.	Link to 0
	 * We store a sealed capability to the caller's frame in the jump
	 * buffer.
	 */

	*buf = cheri_seal(cheri_setaddress(csp, csp->next), sealer_jmpbuf);

	return ((struct jmp_args) { .ret = ret });
}

struct jmp_args _rtld_longjmp_impl(uintptr_t, void **, struct trusted_frame *,
    void **);

struct jmp_args
_rtld_longjmp_impl(uintptr_t ret, void **buf, struct trusted_frame *csp,
    void **rcsp)
{
	/*
	 * Before longjmp is called, the top of the Executive stack contains:
	 * 	0.	Link to previous frame
	 * longjmp does not push to the Executive stack. When _rtld_longjmp is
	 * called, the following are pushed to the Executive stack:
	 * 	1.	Caller's data
	 * 	2.	Link to 0
	 * _rtld_longjmp traverses down the Executive stack from 0 and unwinds
	 * the Restricted stack of each intermediate compartment until reaching
	 * the target frame.
	 */

	struct trusted_frame *target, *cur = csp;
	void **stack;

	target = cheri_unseal(*buf, sealer_jmpbuf);

	if (!cheri_is_subset(cur, target) || cur->next > (ptraddr_t)target)
		rtld_fatal("longjmp: Bad target");

	/*
	 * Unwind each frame before the target frame.
	 */
	while (cur < target) {
		stack = cur->o_stack;
		stack = cheri_setoffset(stack, cheri_getlen(stack));
		stack[-1] = cur->o_stack;
		cur = cheri_setaddress(cur, cur->next);
	}

	if (cur != target)
		rtld_fatal("longjmp: Bad target");

	/*
	 * Set the next frame to the target frame.
	 */
	csp->next = (ptraddr_t)cur;

	/*
	 * Maintain the invariant of the trusted frame and the invariant of the
	 * bottom of the target compartment's stack.
	 */
	stack = cheri_setoffset(rcsp, cheri_getlen(rcsp));
	csp->o_stack = stack[-1];
	stack[-1] = rcsp;

	return ((struct jmp_args) { .ret = ret });
}

/*
 * Trampolines
 */
struct tramp_pg {
	SLIST_ENTRY(tramp_pg) link;
	_Atomic(size_t) size;
	size_t capacity;
	_Alignas(_Alignof(void *)) char trampolines[];
};

/*
 * 64K is the largest size such that any capability-aligned proper
 * sub-range can be exactly bounded by a Morello capability.
 */
#define	C18N_TRAMPOLINE_PAGE_SIZE	64 * 1024

static struct tramp_pg *
tramp_pg_new(struct tramp_pg *next)
{
	size_t capacity = C18N_TRAMPOLINE_PAGE_SIZE;
	struct tramp_pg *pg;

	pg = mmap(NULL, capacity, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON,
	    -1, 0);
	if (pg == MAP_FAILED)
		rtld_fatal("mmap failed");
	SLIST_NEXT(pg, link) = next;
	atomic_store_explicit(&pg->size, 0, memory_order_relaxed);
	pg->capacity = capacity - offsetof(typeof(*pg), trampolines);
	return (pg);
}

static void *
tramp_pg_push(struct tramp_pg *pg, size_t len)
{
	char *tramp;
	size_t n_size;
	size_t size = atomic_load_explicit(&pg->size, memory_order_relaxed);

	do {
		tramp = roundup2(pg->trampolines + size,
		    _Alignof(struct tramp_header));
		n_size = tramp + len - pg->trampolines;
		if (n_size > pg->capacity)
			return (NULL);
	} while (!atomic_compare_exchange_weak_explicit(&pg->size,
	    /*
	     * Relaxed ordering is sufficient because there are no side-effects.
	     */
	    &size, n_size, memory_order_relaxed, memory_order_relaxed));

	tramp = cheri_setbounds(tramp, len);
	assert(cheri_gettag(tramp));

	return (tramp);
}

typedef ssize_t slot_idx_t;

static struct {
	_Alignas(CACHE_LINE_SIZE) _Atomic(slot_idx_t) size;
	size_t back;
	int exp;
	struct tramp_header **data;
	struct tramp_map_kv {
		_Atomic(ptraddr_t) key;
		_Atomic(slot_idx_t) index;
	} *map;
	_Alignas(CACHE_LINE_SIZE) _Atomic(slot_idx_t) writers;
} tramp_table;

static struct {
	_Alignas(CACHE_LINE_SIZE) _Atomic(struct tramp_pg *) head;
	_Alignas(CACHE_LINE_SIZE) atomic_flag lock;
} tramp_pgs = {
	.lock = ATOMIC_FLAG_INIT
};

static slot_idx_t
tramp_table_max_load(int exp)
{
	/* MAX_LOAD is 37.5% of capacity. */
	return (3 << (exp - 3));
}

static void
tramp_table_expand(int exp)
{
	char *buffer;
	size_t back, map_offset;

	/* The data array only needs to be as large as the MAX_LOAD. */
	back = sizeof(*tramp_table.data) * tramp_table_max_load(exp);
	back = map_offset = roundup2(back, _Alignof(typeof(*tramp_table.map)));
	back += sizeof(*tramp_table.map) << exp;

	buffer = mmap(NULL, back, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (buffer == MAP_FAILED)
		rtld_fatal("mmap failed");

	if (tramp_table.data != NULL) {
		memcpy(buffer, tramp_table.data,
		    sizeof(*tramp_table.data) *
		    atomic_load_explicit(&tramp_table.size,
		        memory_order_relaxed));
		if (munmap(tramp_table.data, tramp_table.back) != 0)
			rtld_fatal("munmap failed");
	}

	tramp_table.back = back;
	tramp_table.exp = exp;
	tramp_table.data = (void *)buffer;
	tramp_table.map = (void *)(buffer + map_offset);

	for (size_t i = 0; i < (1 << exp); ++i)
		tramp_table.map[i] = (struct tramp_map_kv) {
			.key = 0,
			.index = -1
		};
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
next_slot(slot_idx_t slot, uint32_t hash, int exp)
{
	uint32_t step, mask;

	step = (hash >> (32 - exp)) | 1;
	mask = (1 << exp) - 1;
	return ((slot + step) & mask);
}

/* Must be called with exclusive access to the table */
static void
resize_table(int exp)
{
	ptraddr_t key;
	uint32_t hash;
	slot_idx_t size, slot;

	assert(0 < exp && exp < 32);

	tramp_table_expand(exp);

	size = atomic_load_explicit(&tramp_table.size, memory_order_relaxed);

	for (slot_idx_t idx = 0; idx < size; ++idx) {
		key = (ptraddr_t)tramp_table.data[idx]->target;
		hash = pointer_hash(key);
		slot = hash;

		do {
			slot = next_slot(slot, hash, exp);
		} while (atomic_load_explicit(&tramp_table.map[slot].key,
		    memory_order_relaxed) != 0);

		atomic_store_explicit(&tramp_table.map[slot].key, key,
		    memory_order_relaxed);
		atomic_store_explicit(&tramp_table.map[slot].index, idx,
		    memory_order_relaxed);
	}
}

void
tramp_hook_impl(void *, int, void *, const Obj_Entry *, const Elf_Sym *,
    void *);

void
tramp_hook_impl(void *rcsp, int event, void *target, const Obj_Entry *obj,
    const Elf_Sym *def, void *link)
{
	Elf_Word sym_num;
	const char *sym;
	const char *callee;

	compart_id_t caller_id;
	const char *caller;

	struct utrace_rtld ut;
	static const char rtld_utrace_sig[RTLD_UTRACE_SIG_SZ] = RTLD_UTRACE_SIG;

	sym_num = def == NULL ? 0 : def->st_name;
	sym = def == NULL ? "<unknown>" : strtab_value(obj, def->st_name);
	callee = comparts.data[obj->compart_id]->name;

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	caller_id =
	    ((uintptr_t *)cheri_setoffset(rcsp, cheri_getlen(rcsp)))[-2];
	(void)link;
#else
	if (cheri_gettag(link) &&
	    (cheri_getperm(link) & CHERI_PERM_EXECUTIVE) == 0)
		caller_id = ((uintptr_t *)
		    cheri_setoffset(rcsp, cheri_getlen(rcsp)))[-2];
	else
		caller_id = C18N_RTLD_COMPART_ID;
#endif
	if (caller_id < C18N_RTLD_COMPART_ID)
		caller = "<unknown>";
	else
		caller = comparts.data[caller_id]->name;

	if (ld_compartment_utrace != NULL) {
		memcpy(ut.sig, rtld_utrace_sig, sizeof(ut.sig));
		ut.event = event;
		ut.handle = target;
		ut.mapsize = sym_num;
		strlcpy(ut.symbol, sym, sizeof(ut.symbol));
		strlcpy(ut.callee, callee, sizeof(ut.callee));
		strlcpy(ut.caller, caller, sizeof(ut.caller));
		utrace(&ut, sizeof(ut));
	}
	if (ld_compartment_overhead != NULL)
		getpid();
}

#define	C18N_MAX_TRAMP_SIZE	768

static struct tramp_header *
tramp_pgs_append(const struct tramp_data *data)
{
	size_t len;
	/* A capability-aligned buffer large enough to hold a trampoline */
	_Alignas(_Alignof(struct tramp_header)) char buf[C18N_MAX_TRAMP_SIZE];
	char *bufp = buf;
	struct tramp_header **headerp = (struct tramp_header **)&bufp;

	char *tramp;
	struct tramp_pg *pg;

	/* Fill a temporary buffer with the trampoline and obtain its length */
	len = tramp_compile(headerp, data);

	pg = atomic_load_explicit(&tramp_pgs.head, memory_order_acquire);
	tramp = tramp_pg_push(pg, len);
	if (tramp == NULL) {
		while (atomic_flag_test_and_set_explicit(&tramp_pgs.lock,
		    memory_order_acquire));
		pg = atomic_load_explicit(&tramp_pgs.head,
		    memory_order_relaxed);
		tramp = tramp_pg_push(pg, len);
		if (tramp == NULL) {
			pg = tramp_pg_new(pg);
			tramp = tramp_pg_push(pg, len);
			atomic_store_explicit(&tramp_pgs.head, pg,
			    memory_order_release);
		}
		atomic_flag_clear_explicit(&tramp_pgs.lock,
		    memory_order_release);
	}
	assert(cheri_gettag(tramp));

	bufp = tramp + (bufp - buf);
	memcpy(tramp, buf, len);

	/*
	 * Ensure i- and d-cache coherency after writing executable code. The
	 * __clear_cache procedure rounds the addresses to cache-line-aligned
	 * addresses. Derive the start address from pg so that it has
	 * sufficiently large bounds to contain these rounded addresses.
	 */
	__clear_cache(cheri_copyaddress(pg, (*headerp)->entry), tramp + len);

	return (*headerp);
}

static bool
func_sig_equal(struct func_sig lhs, struct func_sig rhs)
{
	return (lhs.reg_args == rhs.reg_args &&
		lhs.mem_args == rhs.mem_args &&
		lhs.ret_args == rhs.ret_args);
}

static void
tramp_check_sig(struct tramp_header *found, const Obj_Entry *reqobj,
    const struct tramp_data *data)
{
	struct func_sig sig;

	if (data->sig.valid && found->def != NULL) {
		sig = sigtab_get(found->defobj,
		    found->def - found->defobj->symtab);

		rtld_require(!sig.valid || func_sig_equal(data->sig, sig),
		    "Incompatible signatures for function %s: "
		    "%s requests " C18N_SIG_FORMAT_STRING " but "
		    "%s provides " C18N_SIG_FORMAT_STRING,
		    strtab_value(found->defobj, found->def->st_name),
		    reqobj->path, C18N_SIG_FORMAT(data->sig),
		    found->defobj->path, C18N_SIG_FORMAT(sig));
	}
}

static struct tramp_header *
tramp_create(const struct tramp_data *data)
{
	struct tramp_data newdata = *data;

	if (!newdata.sig.valid && newdata.def != NULL)
		newdata.sig = sigtab_get(newdata.defobj,
		    newdata.def - newdata.defobj->symtab);

	return (tramp_pgs_append(&newdata));
}

static void *
tramp_make_entry(struct tramp_header *header)
{
	void *entry = header->entry;

	entry = cheri_clearperm(entry, FUNC_PTR_REMOVE_PERMS);
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	entry = cheri_capmode(entry);
#endif

	return (cheri_sealentry(entry));
}

void *
tramp_intern(const Obj_Entry *reqobj, const struct tramp_data *data)
{
	struct tramp_header *header;
	RtldLockState lockstate;
	ptraddr_t target = (ptraddr_t)data->target;
	const uint32_t hash = pointer_hash(target);
	slot_idx_t slot, idx, writers;
	ptraddr_t key;
	int exp;

	/* reqobj == NULL iff the request is by RTLD */
	assert((reqobj == NULL || data->def != NULL) && data->defobj != NULL
	    && func_sig_legal(data->sig));

	if (!tramp_should_include(reqobj, data))
		return (data->target);

start:
	slot = hash;
	rlock_acquire(rtld_tramp_lock, &lockstate);
	exp = tramp_table.exp;
	do {
		slot = next_slot(slot, hash, exp);
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
		writers = atomic_fetch_add_explicit(&tramp_table.writers, 1,
		    memory_order_relaxed);

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

	/*
	 * Load the data array entry and exit the critical region.
	 */
	header = tramp_table.data[idx];
	goto end;

insert:
	idx = atomic_fetch_add_explicit(&tramp_table.size, 1,
	    memory_order_relaxed);

	/*
	 * Invariant: tramp_table.size <= MAX_LOAD
	 *
	 * Create the data array entry.
	 */
	header = tramp_table.data[idx] = tramp_create(data);

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
		resize_table(exp + 1);
	}
end:
	lock_release(rtld_tramp_lock, &lockstate);

	tramp_check_sig(header, reqobj, data);

	return (tramp_make_entry(header));
}

struct func_sig
sigtab_get(const Obj_Entry *obj, unsigned long symnum)
{
	if (symnum >= obj->dynsymcount)
		rtld_fatal("Invalid symbol number %lu for object %s.",
		    symnum, obj->path);

	if (obj->sigtab == NULL)
		return ((struct func_sig) { .valid = false });

	return (obj->sigtab[symnum]);
}

static struct tramp_header *
tramp_reflect(void *entry)
{
	struct tramp_pg *page = atomic_load_explicit(&tramp_pgs.head,
	    memory_order_acquire);
	uintptr_t data = (uintptr_t)entry;
	struct tramp_header *ret;

	if (!cheri_gettag(data))
		return (NULL);

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	data -= 1;
#endif
	data = (uintptr_t)__containerof((void *)data, struct tramp_header,
	    entry);

	while (page != NULL) {
		ret = cheri_buildcap(page, data);
		if (cheri_gettag(ret)) {
			if (cheri_gettag(ret->target))
				/*
				 * At this point, the provided data must have
				 * been (a) tagged and (b) pointing to the entry
				 * point of a trampoline.
				 */
				return (ret);
			else
				rtld_fatal("c18n: A return capability to a "
				    "trampoline is passed to tramp_reflect");
		}
		page = SLIST_NEXT(page, link);
	}

	return (NULL);
}

/*
 * APIs
 */
#define	C18N_FUNC_SIG_COUNT	72
#define	C18N_INIT_COMPART_COUNT	8

void
c18n_init(void)
{
	int exp = 9;
	uintptr_t sealer;
	struct stk_table *table;

	/*
	 * Allocate otypes for RTLD use
	 */
	if (sysctlbyname("security.cheri.sealcap", &sealer,
	    &(size_t) { sizeof(sealer) }, NULL, 0) < 0)
		rtld_fatal("sysctlbyname failed");

	sealer_pltgot = cheri_setboundsexact(sealer, 1);
	sealer += 1;

	sealer_jmpbuf = cheri_setboundsexact(sealer, 1);
	sealer += 1;

	sealer_tramp = cheri_setboundsexact(sealer, C18N_FUNC_SIG_COUNT);
	sealer += C18N_FUNC_SIG_COUNT;

	/*
	 * Initialise compartment database
	 */
	comparts_data_expand(C18N_INIT_COMPART_COUNT);
	while (comparts.size < C18N_RTLD_COMPART_ID)
		comparts.data[comparts.size++] = NULL;
	comparts.data[comparts.size++] = &rtld_compart;
	comparts.data[comparts.size++] = &tcb_compart;

	/*
	 * Initialise stack table
	 */
	table = stk_table_expand(NULL, C18N_INIT_COMPART_COUNT, false);

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * Under the benchmark ABI, the trusted stack is a pure data structure
	 * that does not simultaneously serve as RTLD's execution stack. Create
	 * a trusted stack while RTLD is bootstrapping.
	 */
	trusted_stk_set(stk_create(C18N_STACK_SIZE));
	init_stk_table(table);
#else
	untrusted_stk_set(&dummy_stack);
#endif

	stk_table_set(table);

	/*
	 * Initialise trampoline table
	 */
	tramp_table_expand(exp);

	atomic_store_explicit(&tramp_pgs.head, tramp_pg_new(NULL),
	    memory_order_relaxed);
}

void
c18n_add_comparts(struct policy *pol)
{
	if (pol == NULL)
		return;
	comparts_data_expand(comparts.size + pol->count);
	for (size_t i = 0; i < pol->count; ++i)
		comparts.data[comparts.size++] = &pol->coms[i];
}

void *
c18n_return_address(void)
{
	struct trusted_frame *tframe;

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	tframe = trusted_stk_get();
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wframe-address"
	tframe = __builtin_frame_address(2);
#pragma clang diagnostic pop
#endif

	return (tframe->ret_addr);
}

/*
 * libthr support
 */
static void (*thr_thread_start)(struct pthread *);

void _rtld_thread_start_init(void (*)(struct pthread *));

void
_rtld_thread_start_init(void (*p)(struct pthread *))
{
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	assert(thr_thread_start == NULL);
	thr_thread_start = tramp_intern(NULL, &(struct tramp_data) {
		.target = p,
		.defobj = obj_from_addr(p),
		.sig = (struct func_sig) {
			.valid = true,
			.reg_args = 1, .mem_args = false, .ret_args = NONE
		}
	});
}

void _rtld_thread_start_impl(struct pthread *);

void
_rtld_thread_start_impl(struct pthread *curthread)
{
	struct stk_table *table = pop_stk_table(&free_stk_tables);

	/* See c18n_init */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	trusted_stk_set(stk_create(C18N_STACK_SIZE));
	init_stk_table(table);
#else
	untrusted_stk_set(&dummy_stack);
#endif

	stk_table_set(table);

	thr_thread_start(curthread);
}

void _rtld_thr_exit(long *);

void
_rtld_thr_exit(long *state)
{
	char *stk;
	size_t size;
	struct stk_table *table = stk_table_get();

	for (size_t i = C18N_RTLD_COMPART_ID; i < table->capacity; ++i) {
		size = table->stacks[i].size;
		if (size != 0) {
			stk = table->stacks[i].bottom;
			if (munmap(stk - size, size) != 0)
				_exit(2);
			table->stacks[i] = (struct stk_table_stack) {
				.bottom = allocate_rstk,
				.size = 0
			};
		}
	}

	free_stk_table(table);

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * A trusted stack is created upon program start and thread creation.
	 * Unmap the stack here.
	 */
	void *trusted_stk = trusted_stk_get();
	trusted_stk = cheri_setoffset(trusted_stk, 0);
	if (munmap(trusted_stk, cheri_getlen(trusted_stk)) != 0)
		_exit(2);
#endif

	__sys_thr_exit(state);
}

/*
 * Signal support
 */
void _rtld_dispatch_signal(int, siginfo_t *, void *);

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
ptraddr_t sighandler_fix_link(struct trusted_frame *, ucontext_t *);

ptraddr_t
sighandler_fix_link(struct trusted_frame *csp, ucontext_t *ucp)
{
	ptraddr_t ret = csp->next;

	csp->next = ucp->uc_mcontext.mc_capregs.cap_sp;

	return (ret);
}

void sighandler_unfix_link(struct trusted_frame *, ptraddr_t);

void sighandler_unfix_link(struct trusted_frame *csp, ptraddr_t link)
{
	csp->next = link;
}
#endif

static struct sigaction_map {
	void *o_handler;
	__siginfohandler_t *n_handler;
} sigaction_map[_SIG_MAXSIG];

struct dispatch_signal_ret {
	siginfo_t *info;
	ucontext_t *ucp;
};

__siginfohandler_t *dispatch_signal_get(int);

__siginfohandler_t *
dispatch_signal_get(int sig)
{
	return (sigaction_map[sig - 1].n_handler);
}

struct dispatch_signal_ret dispatch_signal_begin(__siginfohandler_t,
    siginfo_t *, void *);

struct dispatch_signal_ret
dispatch_signal_begin(__siginfohandler_t sigfunc, siginfo_t *info,
    void *_ucp)
{
	compart_id_t cid = tramp_reflect(sigfunc)->defobj->compart_id;
	struct stk_table *table = stk_table_get();
	struct stk_table_stack stack;
	ucontext_t *ucp = _ucp;
	char **stk_bot;
	void *stk_top;

	stack = table->stacks[compart_id_to_stack_index(cid)];

	if (stack.size == 0)
		stk_bot = allocate_rstk_impl(compart_id_to_index(cid));
	else
		stk_bot = stack.bottom;

	stk_top = stk_bot[-1];

	stk_bot[-1] -= sizeof(*ucp);
	ucp = memcpy(stk_bot[-1], ucp, sizeof(*ucp));

	stk_bot[-1] -= sizeof(*info);
	info = memcpy(stk_bot[-1], info, sizeof(*info));

	ucp->uc_mcontext.mc_capregs.cap_sp = (uintptr_t)stk_top;

	return (struct dispatch_signal_ret) {
		.info = info,
		.ucp = ucp
	};
}

void dispatch_signal_end(ucontext_t *, ucontext_t *);

void
dispatch_signal_end(ucontext_t *new, ucontext_t *old __unused)
{
	void *top = (void **)new->uc_mcontext.mc_capregs.cap_sp;
	void **bot = cheri_setoffset(top, cheri_getlen(top));

	memset(new, 0, sizeof(*new));

	bot[-1] = top;
}

extern __siginfohandler_t *signal_dispatcher;

__siginfohandler_t *signal_dispatcher = _rtld_dispatch_signal;

void _rtld_sighandler_init(__siginfohandler_t *);

void
_rtld_sighandler_init(__siginfohandler_t *p)
{
	assert(signal_dispatcher == _rtld_dispatch_signal &&
	    (cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	signal_dispatcher = tramp_intern(NULL, &(struct tramp_data) {
		.target = p,
		.defobj = obj_from_addr(p),
		.sig = (struct func_sig) {
			.valid = true,
			.reg_args = 3, .mem_args = false, .ret_args = NONE
		}
	});
}

void *_rtld_sigaction_begin(int, struct sigaction *);

void *
_rtld_sigaction_begin(int sig, struct sigaction *act)
{
	struct func_sig fsig;
	void *context = act->sa_sigaction;
	struct tramp_header *header = tramp_reflect(context);
	const Obj_Entry *defobj;

	/*
	 * If the signal handler is not already wrapped by a trampoline, wrap it
	 * in one.
	 */
	if (header == NULL) {
		defobj = obj_from_addr(context);

		/*
		 * If SA_SIGINFO is not set, the signal handler can have one of
		 * two possible signatures.
		 */
		if ((act->sa_flags & SA_SIGINFO) == 0)
			fsig = (struct func_sig) { .valid = false };
		else
			fsig = (struct func_sig) {
				.valid = true,
				.reg_args = 3, .mem_args = false,
				.ret_args = NONE
			};

		context = tramp_intern(NULL, &(struct tramp_data) {
		    .target = context,
		    .defobj = defobj,
		    .sig = fsig
		});
	} else
		defobj = header->defobj;

	/*
	 * XXX: Enforce signal handling policy. We need to determine who is
	 * registering the signal, who is handling the signal, and ensure both
	 * are allowed.
	 */
	(void)sig;
	if (defobj->compart_id == C18N_RTLD_COMPART_ID)
		rtld_fatal("c18n: Attempting to register an RTLD function as "
		    "a signal handler");

	act->sa_flags |= SA_SIGINFO;

	return (context);
}

void _rtld_sigaction_end(int, void *, const struct sigaction *,
    struct sigaction *);

void _rtld_sigaction_end(int sig, void *context, const struct sigaction *act,
    struct sigaction *oact)
{
	struct sigaction_map *slot = &sigaction_map[sig - 1];

	/*
	 * If o_handler == NULL, then we must have oact->sa_sigaction == NULL
	 */
	if (oact != NULL && slot->o_handler != NULL)
		oact->sa_sigaction = slot->o_handler;

	if (act != NULL) {
		slot->o_handler = act->sa_sigaction;
		if (context != NULL)
			slot->n_handler = context;
	}
}
