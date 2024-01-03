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
static uintptr_t sealer_jmpbuf;

uintptr_t sealer_pltgot, sealer_tramp;

/* Use utrace() to log compartmentalisation-related events */
const char *ld_compartment_utrace;

/* Enable compartmentalisation */
const char *ld_compartment_enable;

/* Path of the compartmentalisation policy */
const char *ld_compartment_policy;

/* Simulate overhead during compartment transitions */
const char *ld_compartment_overhead;

/* Read the .c18n.signature ELF section */
const char *ld_compartment_sig;

/*
 * Policies
 */
#define	C18N_STRING_BASE_INIT	32

typedef ssize_t string_handle;

struct string_base {
	char *buf;
	string_handle size;
	string_handle capacity;
};

static void
string_base_expand(struct string_base *sb, size_t capacity)
{
	sb->buf = realloc(sb->buf, capacity);
	if (sb->buf == NULL)
		rtld_fatal("realloc failed");
	sb->capacity = capacity;
}

static string_handle
string_base_push(struct string_base *sb, const char *str)
{
	string_handle i = sb->size;

	do {
		if (sb->size == sb->capacity)
			string_base_expand(sb,
			    MAX(C18N_STRING_BASE_INIT, sb->capacity * 2));
		sb->buf[sb->size++] = *str;
	} while (*str++ != '\0');

	return (i);
}

static string_handle
string_base_search(const struct string_base *sb, const char *str)
{
	const char *cur;
	string_handle i = 0, s;

	while (i < sb->size) {
		s = i;
		cur = str;
		while (sb->buf[i] == *cur++)
			if (sb->buf[i++] == '\0')
				return (s);
		while (sb->buf[i] != '\0') ++i;
		++i;
	}

	return (-1);
}

static char default_policy[] =
	"Version 1\n"
	"\n"

	/* RTLD must be the first compartment defined */
	"compartment " _BASENAME_RTLD "\n"
	"\n"

	/* TCB must be the second compartment defined */
	"compartment [TCB]\n"
		"\tlibc.so.7\n"
		"\tlibthr.so.3\n"
	"\n"

	"caller *\n"
	"trust\n"
		"\tmemset\n"
		"\tmemcpy\n"
		"\tmempcpy\n"
		"\tmemccpy\n"
		"\tmemchr\n"
		"\tmemrchr\n"
		"\tmemmem\n"
		"\tmemmove\n"
		"\tstrcpy\n"
		"\tstrncpy\n"
		"\tstpcpy\n"
		"\tstpncpy\n"
		"\tstrcat\n"
		"\tstrncat\n"
		"\tstrlcpy\n"
		"\tstrlcat\n"
		"\tstrlen\n"
		"\tstrnlen\n"
		"\tstrcmp\n"
		"\tstrncmp\n"
		"\tstrchr\n"
		"\tstrrchr\n"
		"\tstrchrnul\n"
		"\tstrspn\n"
		"\tstrcspn\n"
		"\tstrpbrk\n"
		"\tstrsep\n"
		"\tstrstr\n"
		"\tstrnstr\n"

		"\t__libc_start1\n"
		"\tsetjmp\n"
		"\tlongjmp\n"
		"\t_setjmp\n"
		"\t_longjmp\n"
		"\tsigsetjmp\n"
		"\tsiglongjmp\n"

		"\tvfork\n"
		"\trfork\n"

		"\t_rtld_thread_start\n"

	"callee " _BASENAME_RTLD "\n"
	"export to [TCB]\n"
		"\t_rtld_thread_start_init\n"
		"\t_rtld_thread_start\n"
		"\t_rtld_thr_exit\n"
		"\t_rtld_sighandler_init\n"
		"\t_rtld_sighandler\n"
		"\t_rtld_setjmp\n"
		"\t_rtld_longjmp\n";

struct compart {
	/*
	 * Name of the compartment
	 */
	const char *name;
	/*
	 * Names of libraries that belong to the compartment
	 */
	struct string_base libs;
	/*
	 * Symbols that the library is allowed to import, if restrict_imports is
	 * true.
	 */
	struct string_base imports;
	/*
	 * Symbols trusted by the library.
	 */
	struct string_base trusts;
	bool restrict_imports;
};

static struct compart compart_uni = {
	.name = "[Universal]"
};

static struct {
	struct compart *data;
	compart_id_t size;
	compart_id_t capacity;
} comparts;

static void
comparts_data_expand(compart_id_t capacity)
{
	struct compart *data;

	data = realloc(comparts.data, sizeof(*data) * capacity);
	if (data == NULL)
		rtld_fatal("realloc failed");
	comparts.data = data;
	comparts.capacity = capacity;
}

static compart_id_t
compart_name_to_id(const char *name)
{
	compart_id_t i;

	/* Start searching from RTLD's compartment */
	for (i = C18N_RTLD_COMPART_ID; i < comparts.size; ++i)
		if (strcmp(comparts.data[i].name, name) == 0)
			return (i);

	rtld_fatal("c18n: Cannot find compartment ID for name %s", name);
}

static struct compart *
compart_allocate(const char *name)
{
	struct compart *com;

	if (comparts.size > C18N_COMPARTMENT_ID_MAX)
		rtld_fatal("Cannot allocate compartment ID");

	if (comparts.size == comparts.capacity)
		comparts_data_expand(comparts.capacity * 2);

	com = &comparts.data[comparts.size++];
	*com = (struct compart) {
		.name = name
	};

	return (com);
}

compart_id_t
compart_id_allocate(const char *lib)
{
	compart_id_t i;
	struct compart *com;

	/* Start searching after RTLD's compartment */
	for (i = C18N_RTLD_COMPART_ID + 1; i < comparts.size; ++i)
		if (string_base_search(&comparts.data[i].libs, lib) != -1)
			return (i);

	com = compart_allocate(lib);

	string_base_push(&com->libs, lib);

	return (i);
}

struct rule_action {
	compart_id_t caller;
	SLIST_ENTRY(rule_action) link;
};

struct rule {
	compart_id_t callee;
	struct string_base symbols;
	SLIST_HEAD(, rule_action) action;
	SLIST_ENTRY(rule) link;
};

static SLIST_HEAD(, rule) rules = SLIST_HEAD_INITIALIZER(rules);

static bool
evaluate_rules(compart_id_t caller, compart_id_t callee, const char *sym)
{
	struct rule *cur;
	struct rule_action *act;

	if (comparts.data[caller].restrict_imports &&
	    string_base_search(&comparts.data[caller].imports, sym) == -1)
		return (false);

	SLIST_FOREACH(cur, &rules, link) {
		if ((cur->callee != callee) ||
		    (string_base_search(&cur->symbols, sym) == -1))
			continue;
		SLIST_FOREACH(act, &cur->action, link) {
			if (act->caller == caller)
				return (true);
		}
		return (false);
	}

	return (true);
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

	if (string_base_search(&compart_uni.trusts, sym) != -1)
		return (false);

	if (string_base_search(&comparts.data[reqobj->compart_id].trusts, sym)
	    != -1)
		return (false);

	if (evaluate_rules(reqobj->compart_id, data->defobj->compart_id, sym))
		return (true);

	rtld_fatal("c18n: Policy violation: %s is not allowed to access symbol "
	    "%s defined by %s",
	    comparts.data[reqobj->compart_id].name, sym,
	    comparts.data[data->defobj->compart_id].name);
}

static bool
consume_until(const char **input, char delim, char *buf, size_t size)
{
	const char *cur = *input;

	while (1) {
		if (size == 0)
			return (false);
		if (*cur == delim)
			break;
		if (*cur == '\0')
			return (false);
		*buf++ = *cur++;
		--size;
	}

	*buf = '\0';
	*input = cur + 1;

	return (true);
}

static bool
consume_token(const char **input, const char *token)
{
	const char *str = *input;

	while (*token != '\0')
		if (*str++ != *token++)
			return (false);

	*input = str;

	return (true);
}

static void
policy_error(const char *pol, const char *cur)
{
	size_t li = 1;
	size_t ch = 1;

	while (pol != cur)
		if (*pol++ == '\n') {
			++li;
			ch = 1;
		} else
			++ch;

	rtld_fatal("c18n: Bad policy file at line %lu, character %lu", li, ch);
}

#define	C18N_POLICY_IDENT_MAX	128

static void
parse_policy(const char *pol)
{
	compart_id_t id;
	const char *cur = pol;
	struct rule_action *act;
	struct rule *rule;
	struct compart *com;
	struct string_base *symbols;
	char buf[C18N_POLICY_IDENT_MAX];

	if (!consume_token(&cur, "Version 1\n"))
		policy_error(pol, cur);

	while (*cur != '\0') {
		while (consume_token(&cur, "\n"));

		if (consume_token(&cur, "compartment ")) {

			if (consume_until(&cur, '\n', buf, sizeof(buf)))
				com = compart_allocate(strdup(buf));
			else
				policy_error(pol, cur);

			while (consume_token(&cur, "\t"))
				if (consume_until(&cur, '\n', buf, sizeof(buf)))
					string_base_push(&com->libs, buf);
				else
					policy_error(pol, cur);

		} else if (consume_token(&cur, "caller ")) {

			if (consume_token(&cur, "*\n"))
				com = &compart_uni;
			else if (consume_until(&cur, '\n', buf, sizeof(buf))) {
				id = compart_name_to_id(buf);
				if (id < comparts.size)
					com = &comparts.data[id];
				else
					policy_error(pol, cur);
			} else
				policy_error(pol, cur);

			if (consume_token(&cur, "trust\n"))
				symbols = &com->trusts;
			else if (consume_token(&cur, "import\n"))
				symbols = &com->imports;
			else
				policy_error(pol, cur);

			while (consume_token(&cur, "\t"))
				if (consume_until(&cur, '\n', buf, sizeof(buf)))
					string_base_push(symbols, buf);
				else
					policy_error(pol, cur);

		} else if (consume_token(&cur, "callee ")) {

			if (consume_until(&cur, '\n', buf, sizeof(buf))) {
				rule = xmalloc(sizeof(*rule));
				*rule = (struct rule) {
					.callee = compart_name_to_id(buf),
					.action = SLIST_HEAD_INITIALIZER()
				};
			} else
				policy_error(pol, cur);

			while (consume_token(&cur, "export to "))
				if (consume_until(&cur, '\n', buf, sizeof(buf))) {
					act = xmalloc(sizeof(*act));
					*act = (struct rule_action) {
						.caller = compart_name_to_id(buf),
					};
					SLIST_INSERT_HEAD(&rule->action, act, link);
				} else
					policy_error(pol, cur);

			while (consume_token(&cur, "\t"))
				if (consume_until(&cur, '\n', buf, sizeof(buf)))
					string_base_push(&rule->symbols, buf);
				else
					policy_error(pol, cur);

			SLIST_INSERT_HEAD(&rules, rule, link);
		} else
			policy_error(pol, cur);
	}
}

#define	C18N_INIT_COMPART_COUNT	8

void
c18n_init_policy(void)
{
	int fd;
	char *file;

	/*
	 * Initialise compartment database
	 */
	comparts_data_expand(C18N_INIT_COMPART_COUNT);
	comparts.size = C18N_RTLD_COMPART_ID;

	/* Load the default policy */
	parse_policy(default_policy);

	if (ld_compartment_policy != NULL) {
		if ((fd = open(ld_compartment_policy, O_RDONLY)) == -1)
			rtld_fatal("c18n: Cannot open policy file");

		file = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (file == MAP_FAILED)
			rtld_fatal("c18n: Cannot mmap policy file");

		parse_policy(file);

		if (munmap(file, page_size) != 0)
			rtld_fatal("c18n: Cannot munmap policy file");

		if (close(fd) != 0)
			rtld_fatal("c18n: Cannot close policy file");
	}
}

/*
 * Stack switching
 */
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
void c18n_init_rtld_stack(void **);

void
c18n_init_rtld_stack(void **csp)
{
	init_compart_stack(csp, C18N_RTLD_COMPART_ID);
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

	table->resolver = _rtld_get_rstk;

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
		table->resolver = _rtld_get_rstk;
		o_capacity = 0;
	} else
		o_capacity = table->capacity;

	table->capacity =
	    (cheri_getlen(table) - offsetof(typeof(*table), stacks)) /
	    sizeof(*table->stacks);

	for (size_t i = o_capacity; i < table->capacity; ++i)
		table->stacks[i].bottom = _rtld_get_rstk;

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

/* Default stack size in libthr */
#define	C18N_STACK_SIZE	(sizeof(void *) / 4 * 1024 * 1024)

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

void *get_rstk(unsigned);

void *
get_rstk(unsigned index)
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
	assert(table->stacks[cid_off].size == 0);

	size = C18N_STACK_SIZE;
	stk = stk_create(size);
	init_compart_stack(stk, cid);

	table->stacks[cid_off].bottom = stk;
	table->stacks[cid_off].size = size;

	return (stk);
}

struct jmp_args { void **buf; void *val; };

struct jmp_args _rtld_setjmp_impl(void **, void *, struct trusted_frame *);

struct jmp_args
_rtld_setjmp_impl(void **buf, void *val, struct trusted_frame *csp)
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

	*buf++ = cheri_seal(cheri_setaddress(csp, csp->next), sealer_jmpbuf);

	return ((struct jmp_args) { .buf = buf, .val = val });
}

struct jmp_args _rtld_longjmp_impl(void **, void *, struct trusted_frame *);

struct jmp_args
_rtld_longjmp_impl(void **buf, void *val, struct trusted_frame *csp)
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

	target = cheri_unseal(*buf++, sealer_jmpbuf);

	if (!cheri_is_subset(cur, target) || cur->next > (ptraddr_t)target)
		rtld_fatal("longjmp: Bad target");

	/*
	 * Skip the first frame because it will be unwinded when this call
	 * returns.
	 */
	while (cur->next < (ptraddr_t)target) {
		cur = cheri_setaddress(cur, cur->next);
		stack = cur->o_stack;
		stack = cheri_setoffset(stack, cheri_getlen(stack));
		stack[-1] = cur->o_stack;
	}

	*cur = *csp;
	csp->next = (ptraddr_t)cur;

	return ((struct jmp_args) { .buf = buf, .val = val });
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
		/*
		 * Align the trampoline to two capabilities so that the first
		 * instruction and the capability preceding it reside on the
		 * same cache line.
		 */
		tramp = roundup2(pg->trampolines + size, 2 * _Alignof(void *));
		n_size = tramp + len - pg->trampolines;
		if (n_size > pg->capacity)
			return (NULL);
	} while (!atomic_compare_exchange_weak_explicit(&pg->size,
	    /*
	     * Relaxed ordering is sufficient because there are no
	     * side-effects.
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
	struct tramp_data *data;
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
		key = (ptraddr_t)tramp_table.data[idx].target;
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
tramp_hook(void *, int, void *, const Obj_Entry *, const Elf_Sym *, void *);

void
tramp_hook(void *rcsp, int event, void *target, const Obj_Entry *obj,
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
	callee = comparts.data[obj->compart_id].name;

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
		caller = comparts.data[caller_id].name;

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

#define	C18N_MAX_TRAMPOLINE_SIZE	512

static void *
tramp_pgs_append(const struct tramp_data *data)
{
	size_t len;
	/* A capability-aligned buffer large enough to hold a trampoline */
	_Alignas(_Alignof(void *)) char tmp[C18N_MAX_TRAMPOLINE_SIZE];
	char *tramp, *entry = tmp;
	struct tramp_pg *pg;

	/* Fill a temporary buffer with the trampoline and obtain its length */
	len = tramp_compile((void **)&entry, data);

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

	entry = tramp + (entry - tmp);
	memcpy(tramp, tmp, len);

	/*
	 * Ensure i- and d-cache coherency after writing executable code. The
	 * __clear_cache procedure rounds the addresses to cache-line-aligned
	 * addresses. Derive the start/end addresses from pg so that they have
	 * sufficiently large bounds to contain these rounded addresses.
	 */
	__clear_cache(cheri_copyaddress(pg, entry),
	    cheri_copyaddress(pg, tramp + len));

	entry = cheri_clearperm(entry, FUNC_PTR_REMOVE_PERMS);
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	entry = cheri_capmode(entry);
#endif
	return (cheri_sealentry(entry));
}

static bool
func_sig_equal(struct func_sig lhs, struct func_sig rhs)
{
	return (lhs.reg_args == rhs.reg_args &&
		lhs.mem_args == rhs.mem_args &&
		lhs.ret_args == rhs.ret_args);
}

static bool
func_sig_compatible(struct func_sig lhs, struct func_sig rhs)
{
	return (!lhs.valid || !rhs.valid || func_sig_equal(lhs, rhs));
}

static void *
tramp_get_entry(const struct tramp_data *found, const struct tramp_data *data)
{
	if (!func_sig_compatible(found->sig, data->sig))
		rtld_fatal(
		    "Incompatible signatures for function %s: "
		    "%s requests " C18N_SIG_FORMAT_STRING " but %s provides "
		    C18N_SIG_FORMAT_STRING,
		    strtab_value(data->defobj, data->def->st_name),
		    data->defobj->path, C18N_SIG_FORMAT(data->sig),
		    found->defobj->path, C18N_SIG_FORMAT(found->sig));

	return (found->entry);
}

static void *
tramp_create_entry(struct tramp_data *found, const struct tramp_data *data)
{
	struct func_sig sig;

	*found = *data;
	if (found->def != NULL) {
		sig = c18n_fetch_sig(found->defobj,
		    found->def - found->defobj->symtab);
		if (!found->sig.valid)
			found->sig = sig;
		else if (!func_sig_compatible(found->sig, sig))
			rtld_fatal(
			    "Incompatible signatures for function %s: "
			    "requests " C18N_SIG_FORMAT_STRING
			    " but %s provides " C18N_SIG_FORMAT_STRING,
			    strtab_value(found->defobj, found->def->st_name),
			    C18N_SIG_FORMAT(found->sig), found->defobj->path,
			    C18N_SIG_FORMAT(sig));
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
	slot_idx_t slot, idx, writers;
	ptraddr_t key;
	int exp;

	/* reqobj == NULL iff the request is by RTLD */
	assert((reqobj == NULL || data->def != NULL) &&
	    data->defobj != NULL && data->entry == NULL &&
	    func_sig_legal(data->sig));

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
		resize_table(exp + 1);
	}
end:
	lock_release(rtld_tramp_lock, &lockstate);
	return (entry);
}

/*
 * APIs
 */
struct func_sig
c18n_fetch_sig(const Obj_Entry *obj, unsigned long symnum)
{
	if (symnum >= obj->dynsymcount)
		rtld_fatal("Invalid symbol number %lu for object %s.",
		    symnum, obj->path);

	if (obj->sigtab == NULL)
		return ((struct func_sig) {});
	return (obj->sigtab[symnum]);
}

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

/*
 * libthr support
 */
static void (*thr_thread_start)(struct pthread *);

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
				.bottom = _rtld_get_rstk,
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

static void (*thr_sighandler)(int, siginfo_t *, void *);

void
_rtld_sighandler_init(void (*p)(int, siginfo_t *, void *))
{
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) == 0);
	assert(thr_sighandler == NULL);
	thr_sighandler = tramp_intern(NULL, &(struct tramp_data) {
		.target = p,
		.defobj = obj_from_addr(p),
		.sig = (struct func_sig) {
			.valid = true,
			.reg_args = 3, .mem_args = false, .ret_args = NONE
		}
	});
}

void _rtld_sighandler_impl(int, siginfo_t *, void *, ptraddr_t *);

void
_rtld_sighandler_impl(int sig, siginfo_t *info, void *_ucp, ptraddr_t *frame)
{
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	(void)frame;
#else
	ucontext_t *ucp = _ucp;

	*frame = (ptraddr_t)ucp->uc_mcontext.mc_capregs.cap_sp;
#endif

	thr_sighandler(sig, info, _ucp);
}
