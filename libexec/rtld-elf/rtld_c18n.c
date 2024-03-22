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
#include <sys/stat.h>
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
static uintptr_t sealer_unwbuf;

uintptr_t sealer_pltgot, sealer_tramp;

#ifndef RTLD_SANDBOX_ALWAYS
/* Enable compartmentalisation */
bool ld_compartment_enable;
#endif

/* Permission bit to be cleared for user code */
uint64_t c18n_code_perm_clear;

/* Use utrace() to log compartmentalisation-related events */
const char *ld_compartment_utrace;

/* Path of the compartmentalisation policy */
const char *ld_compartment_policy;

/* Simulate overhead during compartment transitions */
const char *ld_compartment_overhead;

/* Read the .c18n.signature ELF section */
const char *ld_compartment_sig;

/* Expose tagged frame pointers to trusted frames */
const char *ld_compartment_unwind;

/*
 * Policies
 */
/*
 * RTLD is the first compartment.
 */
#define	C18N_RTLD_COMPART_ID	0

typedef ssize_t string_handle;

struct string_base {
	char *buf;
	string_handle size;
	string_handle capacity;
};

#define	C18N_STRING_BASE_INIT	32

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
		while (sb->buf[i++] == *cur)
			if (*cur++ == '\0')
				return (s);
		while (sb->buf[i] != '\0') ++i;
		++i;
	}

	return (-1);
}

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

/*
 * A pseudo-compartment that encompasses all compartments.
 */
static struct compart uni_compart;

static struct compart comparts_data_init[] = {
	[C18N_RTLD_COMPART_ID] = {
		.name = "[RTLD]"
	}
};

#define	C18N_INIT_COMPART_COUNT	nitems(comparts_data_init)

static struct {
	struct compart *data;
	compart_id_t size;
	compart_id_t capacity;
} comparts = {
	.data = comparts_data_init,
	.size = C18N_INIT_COMPART_COUNT,
	.capacity = C18N_INIT_COMPART_COUNT
};

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

static struct compart *
comparts_data_add(const char *name)
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

	/*
	 * Start searching from the first compartment
	 */
	for (i = C18N_RTLD_COMPART_ID; i < comparts.size; ++i)
		if (string_base_search(&comparts.data[i].libs, lib) != -1)
			return (i);

	com = comparts_data_add(lib);
	string_base_push(&com->libs, lib);

	return (i);
}

static compart_id_t
compart_name_to_id(const char *name)
{
	compart_id_t i;

	/*
	 * Start searching from the first compartment
	 */
	for (i = C18N_RTLD_COMPART_ID; i < comparts.size; ++i)
		if (strcmp(comparts.data[i].name, name) == 0)
			return (i);

	rtld_fatal("c18n: Cannot find compartment ID for name %s", name);
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

struct cursor {
	const char *buf;
	const size_t size;
	size_t pos;
};

static bool
eat(struct cursor *cur, const char *token)
{
	size_t pos = cur->pos;

	while (*token != '\0')
		if (pos >= cur->size || cur->buf[pos++] != *token++)
			return (false);

	cur->pos = pos;

	return (true);
}

static bool
eat_token(struct cursor *cur, char delim, char *buf, size_t size)
{
	char c;
	size_t pos = cur->pos;

	while (size > 0 && pos < cur->size) {
		c = cur->buf[pos++];
		if (c == delim) {
			*buf = '\0';
			cur->pos = pos;
			return (true);
		}
		*buf++ = c;
		--size;
	}

	return (false);
}

static void
policy_error(const struct cursor *cur)
{
	size_t li = 1;
	size_t ch = 1;
	size_t pos = 0;

	while (pos < cur->pos) {
		if (cur->buf[pos++] == '\n') {
			++li;
			ch = 1;
		} else
			++ch;
	}

	rtld_fatal("c18n: Policy error at line %lu, character %lu", li, ch);
}

#define	C18N_POLICY_TOKEN_MAX	128

static void
parse_policy(const char *pol, size_t size)
{
	compart_id_t id;
	struct cursor cur = {
		.buf = pol,
		.size = size
	};
	struct rule_action *act;
	struct rule *rule;
	struct compart *com;
	struct string_base *symbols;
	char buf[C18N_POLICY_TOKEN_MAX];

	if (!eat(&cur, "Version 1\n"))
		policy_error(&cur);

	while (cur.pos < cur.size) {
		while (eat(&cur, "\n"))
			;

		if (eat(&cur, "compartment ")) {
			if (eat_token(&cur, '\n', buf, sizeof(buf)))
				com = comparts_data_add(strdup(buf));
			else
				policy_error(&cur);

			while (eat(&cur, "\t"))
				if (eat_token(&cur, '\n', buf, sizeof(buf)))
					string_base_push(&com->libs, buf);
				else
					policy_error(&cur);

		} else if (eat(&cur, "caller ")) {
			if (eat(&cur, "*\n"))
				com = &uni_compart;
			else if (eat_token(&cur, '\n', buf, sizeof(buf))) {
				id = compart_name_to_id(buf);
				com = &comparts.data[id];
			} else
				policy_error(&cur);

			if (eat(&cur, "trust\n"))
				symbols = &com->trusts;
			else if (eat(&cur, "import\n"))
				symbols = &com->imports;
			else
				policy_error(&cur);

			while (eat(&cur, "\t"))
				if (eat_token(&cur, '\n', buf, sizeof(buf)))
					string_base_push(symbols, buf);
				else
					policy_error(&cur);

		} else if (eat(&cur, "callee ")) {
			if (eat_token(&cur, '\n', buf, sizeof(buf))) {
				id = compart_name_to_id(buf);
				rule = xmalloc(sizeof(*rule));
				*rule = (struct rule) {
					.callee = id,
					.action = SLIST_HEAD_INITIALIZER()
				};
			} else
				policy_error(&cur);

			while (eat(&cur, "export to "))
				if (eat_token(&cur, '\n', buf, sizeof(buf))) {
					id = compart_name_to_id(buf);
					act = xmalloc(sizeof(*act));
					*act = (struct rule_action) {
						.caller = id,
					};
					SLIST_INSERT_HEAD(&rule->action, act,
					    link);
				} else
					policy_error(&cur);

			while (eat(&cur, "\t"))
				if (eat_token(&cur, '\n', buf, sizeof(buf)))
					string_base_push(&rule->symbols, buf);
				else
					policy_error(&cur);

			SLIST_INSERT_HEAD(&rules, rule, link);
		} else
			policy_error(&cur);
	}
}

static bool
evaluate_rules(compart_id_t caller, compart_id_t callee, const char *sym)
{
	struct rule *cur;
	struct rule_action *act;

	if (comparts.data[caller].restrict_imports &&
	    string_base_search(&comparts.data[caller].imports, sym) == -1)
		return (false);

	SLIST_FOREACH(cur, &rules, link) {
		if (cur->callee != callee ||
		    string_base_search(&cur->symbols, sym) == -1)
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

	if (data->def == NULL)
		return (true);

	if (data->def == &sym_zero)
		return (false);

	sym = strtab_value(data->defobj, data->def->st_name);

	if (string_base_search(&uni_compart.trusts, sym) != -1)
		return (false);

	if (reqobj == NULL)
		return (true);

	if (reqobj->compart_id == data->defobj->compart_id)
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

/*
 * Stack switching
 */
struct stk_bottom {
	compart_id_t compart_id;
	/*
	 * Store an integer address of the compartment's name for debuggers.
	 */
	ptraddr_t compart_name;
	/*
	 * INVARIANT: The bottom of a compartment's stack contains a capability
	 * to the top of the stack either when the compartment was last entered
	 * or when it was last exited from, which ever occured later.
	 */
	void *top;
};

void *allocate_rstk(unsigned);

static compart_id_t
index_to_cid(unsigned index)
{
	struct stk_table_stack dummy;

	index *= sizeof(dummy.bottom);
	index -= offsetof(struct stk_table, stacks);
	index -= offsetof(struct stk_table_stack, bottom);
	index /= sizeof(dummy);

	/*
	 * Reverse the transform done in cid_to_table_index.
	 */
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	++index;
#endif
	return (index);
}

static void init_compart_stack(void *, compart_id_t);

static void
init_compart_stack(void *base, compart_id_t cid)
{
	struct stk_bottom *stk = base;
	--stk;

	memset(stk, 0, sizeof(*stk));
	*stk = (struct stk_bottom) {
		.compart_id = cid,
		.compart_name = (ptraddr_t)comparts.data[cid].name,
		.top = cheri_clearperm(stk, CHERI_PERM_SW_VMEM)
	};
}

uintptr_t c18n_init_rtld_stack(uintptr_t, void *);

uintptr_t
c18n_init_rtld_stack(uintptr_t ret, void *base)
{
	/*
	 * This function does very different things under the two ABIs.
	 *
	 * Under the purecap ABI, it repurposes the bottom of the trusted stack
	 * into a dummy stack that is installed in the Restricted stack register
	 * when running Executive mode code so that trampolines do not need to
	 * test if the Restricted stack is valid. The reduction of bounds is
	 * merely defensive. It should in theory be unnecessary.
	 *
	 * Under the benchmark ABI, it initialises RTLD's stack as a regular
	 * compartment's stack.
	 */
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	struct stk_bottom *stk = base;
	--stk;

	stk = cheri_setboundsexact(stk, sizeof(*stk));
	base = stk + 1;
#endif

	init_compart_stack(base, C18N_RTLD_COMPART_ID);

	return (ret);
}

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
/*
 * Save the initial stack (either at program launch or at thread start) in the
 * stack table.
 */
static void
init_stk_table(struct stk_table *table)
{
	void *sp = cheri_getstack();
	table->stacks[cid_to_table_index(C18N_RTLD_COMPART_ID)].bottom =
	    cheri_setoffset(sp, cheri_getlen(sp));
}
#else
void install_dummy_stack(void);

void
install_dummy_stack(void)
{
	struct stk_bottom *stk = cheri_getstack();
	stk = cheri_setoffset(stk, cheri_getlen(stk));
	--stk;

	untrusted_stk_set(stk->top);
}
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

	for (size_t i = o_capacity; i < table->capacity; ++i)
		table->stacks[i] = (struct stk_table_stack) {
			.bottom = allocate_rstk,
			.size = 0
		};

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
	compart_id_t cid;
	unsigned cid_off;
	size_t capacity, size;
	struct stk_table *table;

	table = stk_table_get();

	cid = index_to_cid(index);
	cid_off = cid_to_table_index(cid);

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

/*
 * Stack unwinding
 */
static void *
unwind_cursor(struct trusted_frame *tf)
{
	/*
	 * This helper is used by functions like setjmp. Before setjmp is
	 * called, the top of the trusted stack contains:
	 * 	0.	Link to previous frame
	 * setjmp does not push to the trusted stack. When _rtld_setjmp is
	 * called, the following are pushed to the trusted stack:
	 * 	1.	Caller's data
	 * 	2.	Link to 0
	 * We store a sealed capability to the caller's frame in the jump
	 * buffer.
	 */

	return (cheri_setaddress(tf, tf->next));
}

uintptr_t _rtld_setjmp(uintptr_t, void **);
uintptr_t _rtld_unw_getcontext(uintptr_t, void **);
uintptr_t _rtld_unw_getcontext_unsealed(uintptr_t, void **);

uintptr_t
_rtld_setjmp(uintptr_t ret, void **buf)
{
	*buf = cheri_seal(unwind_cursor(get_trusted_frame()), sealer_jmpbuf);
	return (ret);
}

uintptr_t
_rtld_unw_getcontext(uintptr_t ret, void **buf)
{
	*buf = cheri_seal(unwind_cursor(get_trusted_frame()), sealer_unwbuf);
	return (ret);
}

uintptr_t
_rtld_unw_getcontext_unsealed(uintptr_t ret, void **buf)
{
	*buf = unwind_cursor(get_trusted_frame());
	return (ret);
}

/*
 * Returning this struct allows us to control the content of unused return value
 * registers.
 */
struct jmp_args { uintptr_t ret1; uintptr_t ret2; };

static struct jmp_args
unwind_stack(struct jmp_args ret, void *rcsp, struct trusted_frame *target,
    struct trusted_frame *tf)
{
	/*
	 * Thie helper is used by functions like longjmp. Before longjmp is
	 * called, the top of the trusted stack contains:
	 * 	0.	Link to previous frame
	 * longjmp does not push to the trusted stack. When _rtld_longjmp is
	 * called, the following are pushed to the trusted stack:
	 * 	1.	Caller's data
	 * 	2.	Link to 0
	 * _rtld_longjmp traverses down the trusted stack from 0 and unwinds
	 * the stack of each intermediate compartment until reaching the target
	 * frame.
	 */

	struct stk_bottom *stk;
	struct trusted_frame *cur = tf;

	rtld_require(cheri_is_subset(cur, target) && cur < target,
	    "c18n: Illegal unwind from %#p to %#p", cur, target);

	/*
	 * Unwind each frame before the target frame.
	 */
	do {
		stk = cheri_setoffset(cur->n_sp, cheri_getlen(cur->n_sp));
		--stk;

		rtld_require((ptraddr_t)stk->top <= cur->o_sp,
		    "c18n: Cannot unwind %s from %#p to %p\n"
		    "tf: %#p -> %#p", comparts.data[stk->compart_id].name,
		    stk->top, (void *)(uintptr_t)cur->o_sp, tf, target);

		stk->top = cheri_setaddress(cur->n_sp, cur->o_sp);
		cur = cheri_setaddress(cur, cur->next);
	} while (cur < target);

	rtld_require(cur == target,
	    "c18n: Illegal unwind from %#p to %#p", cur, target);

	/*
	 * Set the next frame to the target frame.
	 */
	tf->next = (ptraddr_t)cur;

	/*
	 * Maintain the invariant of the trusted frame and the invariant of the
	 * bottom of the target compartment's stack.
	 */
	stk = cheri_setoffset(rcsp, cheri_getlen(rcsp));
	--stk;

	rtld_require(rcsp <= stk->top,
	    "c18n: Cannot complete unwind %s from %#p to %#p\n"
	    "tf: %#p -> %#p", comparts.data[stk->compart_id].name,
	    rcsp, stk->top, tf, target);

	tf->n_sp = rcsp;
	tf->o_sp = (ptraddr_t)stk->top;

	return (ret);
}

struct jmp_args _rtld_longjmp(struct jmp_args, void *, void **);
struct jmp_args _rtld_unw_setcontext(struct jmp_args, void *, void *, void **);
struct jmp_args _rtld_unw_setcontext_unsealed(struct jmp_args, void *, void *,
    void **);

struct jmp_args
_rtld_longjmp(struct jmp_args ret, void *rcsp, void **buf)
{
	return (unwind_stack(ret, rcsp, cheri_unseal(*buf, sealer_jmpbuf),
	    get_trusted_frame()));
}

struct jmp_args _rtld_unw_setcontext_epilogue(struct jmp_args ret, void *p,
    void *rcsp, void **buf);

struct jmp_args
_rtld_unw_setcontext(struct jmp_args ret, void *p __unused, void *rcsp,
    void **buf)
{
	if (!C18N_ENABLED) {
		__attribute__((musttail)) return (
		    _rtld_unw_setcontext_epilogue(ret, p, rcsp, buf));
	}
	return (unwind_stack(ret, rcsp, cheri_unseal(*buf, sealer_unwbuf),
	    get_trusted_frame()));
}

struct jmp_args
_rtld_unw_setcontext_unsealed(struct jmp_args ret, void *p __unused, void *rcsp,
    void **buf)
{
	if (!C18N_ENABLED) {
		__attribute__((musttail)) return (
		    _rtld_unw_setcontext_epilogue(ret, p, rcsp, buf));
	}
	return (unwind_stack(ret, rcsp, *buf, get_trusted_frame()));
}

uintptr_t _rtld_unw_getsealer(void);
uintptr_t
_rtld_unw_getsealer(void)
{
	return (sealer_unwbuf);
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
	const struct tramp_header **data;
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
tramp_hook_impl(int, const struct tramp_header *, const struct trusted_frame *);

void
tramp_hook_impl(int event, const struct tramp_header *hdr,
    const struct trusted_frame *tf)
{
	const char *sym;
	const char *callee;

	struct stk_bottom *stk;
	compart_id_t caller_id;
	const char *caller;

	struct utrace_rtld ut;
	static const char rtld_utrace_sig[RTLD_UTRACE_SIG_SZ] = RTLD_UTRACE_SIG;

	if (ld_compartment_utrace != NULL) {
		if (hdr->symnum == 0)
			sym = "<unknown>";
		else
			sym = symname(hdr->defobj, hdr->symnum);

		callee = comparts.data[hdr->defobj->compart_id].name;

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
		if (cheri_gettag(tf->pc) &&
		    (cheri_getperm(tf->pc) & CHERI_PERM_EXECUTIVE) == 0)
#endif
		{
			stk = cheri_setoffset(tf->n_sp, cheri_getlen(tf->n_sp));
			--stk;
		        caller_id = stk->compart_id;
		}
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
		else
			caller_id = C18N_RTLD_COMPART_ID;
#endif
		caller = comparts.data[caller_id].name;

		memcpy(ut.sig, rtld_utrace_sig, sizeof(ut.sig));
		ut.event = event;
		ut.handle = hdr->target;
		ut.mapsize = hdr->symnum;
		strlcpy(ut.symbol, sym, sizeof(ut.symbol));
		strlcpy(ut.callee, callee, sizeof(ut.callee));
		strlcpy(ut.caller, caller, sizeof(ut.caller));
		utrace(&ut, sizeof(ut));
	}
	if (ld_compartment_overhead != NULL)
		getpid();
}

#define	C18N_MAX_TRAMP_SIZE	768

static const struct tramp_header *
tramp_pgs_append(const struct tramp_data *data)
{
	size_t len;
	/* A capability-aligned buffer large enough to hold a trampoline */
	_Alignas(_Alignof(struct tramp_header)) char buf[C18N_MAX_TRAMP_SIZE];
	struct tramp_header *header;
	char *bufp = buf;

	char *tramp;
	struct tramp_pg *pg;

	/* Fill a temporary buffer with the trampoline and obtain its length */
	len = tramp_compile(&bufp, data);

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

	memcpy(tramp, buf, len);
	header = (struct tramp_header *)(tramp + (bufp - buf));

	/*
	 * Ensure i- and d-cache coherency after writing executable code. The
	 * __clear_cache procedure rounds the addresses to cache-line-aligned
	 * addresses. Derive the start address from pg so that it has
	 * sufficiently large bounds to contain these rounded addresses.
	 */
	__clear_cache(cheri_copyaddress(pg, header->entry), tramp + len);

	return (header);
}

static bool
func_sig_equal(struct func_sig lhs, struct func_sig rhs)
{
	return (lhs.reg_args == rhs.reg_args &&
		lhs.mem_args == rhs.mem_args &&
		lhs.ret_args == rhs.ret_args);
}

static void
tramp_check_sig(const struct tramp_header *found, const Obj_Entry *reqobj,
    const struct tramp_data *data)
{
	struct func_sig sig;

	if (data->sig.valid && found->symnum != 0) {
		sig = sigtab_get(found->defobj, found->symnum);

		rtld_require(!sig.valid || func_sig_equal(data->sig, sig),
		    "Incompatible signatures for function %s: "
		    "%s requests " C18N_SIG_FORMAT_STRING " but "
		    "%s provides " C18N_SIG_FORMAT_STRING,
		    symname(found->defobj, found->symnum),
		    reqobj->path, C18N_SIG_FORMAT(data->sig),
		    found->defobj->path, C18N_SIG_FORMAT(sig));
	}
}

static const struct tramp_header *
tramp_create(const struct tramp_data *data)
{
	struct tramp_data newdata = *data;

	if (!newdata.sig.valid && newdata.def != NULL)
		newdata.sig = sigtab_get(newdata.defobj,
		    newdata.def - newdata.defobj->symtab);

	return (tramp_pgs_append(&newdata));
}

static const void *
tramp_make_entry(const struct tramp_header *header)
{
	const void *entry = header->entry;

	entry = cheri_clearperm(entry, FUNC_PTR_REMOVE_PERMS);
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	entry = cheri_capmode(entry);
#endif

	return (cheri_sealentry(entry));
}

void *
tramp_intern(const Obj_Entry *reqobj, const struct tramp_data *data)
{
	RtldLockState lockstate;
	const struct tramp_header *header;
	ptraddr_t target = (ptraddr_t)data->target;
	const uint32_t hash = pointer_hash(target);
	slot_idx_t slot, idx, writers;
	ptraddr_t key;
	int exp;

	if (!C18N_ENABLED)
		return (data->target);

	/*
	 * INVARIANT: The defobj of each trampoline is tagged.
	 */
	assert(cheri_gettag(data->defobj));
	if (data->def == NULL)
		/*
		 * XXX-DG: reqobj != NULL causes policies to be evaluated which
		 * might result in a trampoline being elided. This is only safe
		 * to do for jump slot relocations.
		 *
		 * Currently, the decision to elide the trampoline or not is
		 * coupled with the decision of whether the symbol should be
		 * made accesible to the requesting object. This is insecure.
		 */
		assert(reqobj == NULL);
	else if (data->def == &sym_zero)
		assert(data->target == NULL);
	else
		assert(data->defobj->symtab <= data->def &&
		    data->def < data->defobj->symtab +
		    data->defobj->dynsymcount);
	assert(func_sig_legal(data->sig));

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

	/*
	 * Most consumers use type (void *) for function pointers.
	 */
	return (__DECONST(void *, tramp_make_entry(header)));
}

struct func_sig
sigtab_get(const Obj_Entry *obj, unsigned long symnum)
{
	rtld_require(symnum < obj->dynsymcount,
	    "c18n: Invalid symbol number %lu for object %s", symnum, obj->path);

	if (obj->sigtab == NULL)
		return ((struct func_sig) { .valid = false });

	return (obj->sigtab[symnum]);
}

struct tramp_header *
tramp_reflect(void *entry)
{
	struct tramp_header *ret;
	struct tramp_pg *page;
	char *data = entry;

	if (!cheri_gettag(data) || !cheri_getsealed(data) ||
	    cheri_gettype(data) != CHERI_OTYPE_SENTRY ||
	    (cheri_getperm(data) & CHERI_PERM_LOAD) == 0 ||
	    (cheri_getperm(data) & CHERI_PERM_EXECUTE) == 0 ||
	    (cheri_getperm(data) & CHERI_PERM_EXECUTIVE) == 0)
		return (NULL);

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	data -= 1;
#endif
	data = (char *)__containerof((void *)data, struct tramp_header, entry);

	page = atomic_load_explicit(&tramp_pgs.head, memory_order_acquire);

	while (page != NULL) {
		ret = cheri_buildcap(page, (uintptr_t)data);
		if (cheri_gettag(ret)) {
			if (cheri_gettag(ret->defobj))
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

void
c18n_init(void)
{
	extern const char c18n_default_policy[];
	extern const size_t c18n_default_policy_size;

	int fd;
	int exp = 9;
	char *file;
	struct stat st;
	uintptr_t sealer;
	struct compart *data;
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

	sealer_unwbuf = cheri_setboundsexact(sealer, 1);
	sealer += 1;

	sealer_tramp = cheri_setboundsexact(sealer, C18N_FUNC_SIG_COUNT);
	sealer += C18N_FUNC_SIG_COUNT;

	/*
	 * Migrate the compartment database to the heap
	 */
	data = xmalloc(sizeof(*data) * comparts.capacity);
	memcpy(data, comparts.data, sizeof(*comparts.data) * comparts.capacity);
	comparts.data = data;

	/*
	 * Load the default policy
	 */
	parse_policy(c18n_default_policy, c18n_default_policy_size);

	if (ld_compartment_policy != NULL) {
		if ((fd = open(ld_compartment_policy, O_RDONLY)) == -1)
			rtld_fatal("c18n: Cannot open policy file");

		if (fstat(fd, &st) == -1)
			rtld_fatal("c18n: Cannot obtain policy file size");

		file = xmalloc(st.st_size);
		if (read(fd, file, st.st_size) != st.st_size)
			rtld_fatal("c18n: Cannot read policy file");

		parse_policy(file, st.st_size);

		free(file);
		if (close(fd) != 0)
			rtld_fatal("c18n: Cannot close policy file");
	}

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
	install_dummy_stack();
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
	install_dummy_stack();
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
	compart_id_t cid = C18N_RTLD_COMPART_ID + 1;

	for (size_t i = cid_to_table_index(cid); i < table->capacity; ++i) {
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
dispatch_signal_begin(__siginfohandler_t sigfunc, siginfo_t *info, void *_ucp)
{
	compart_id_t cid = tramp_reflect(sigfunc)->defobj->compart_id;
	struct stk_table_stack *entry;
	ucontext_t *ucp = _ucp;
	struct sigframe {
		siginfo_t info;
		ucontext_t context;
	} *ntop, *otop;
	struct stk_bottom *stack;

	entry = &stk_table_get()->stacks[cid_to_table_index(cid)];
	if (entry->size == 0)
		stack = allocate_rstk_impl(cid_to_index(cid));
	else
		stack = entry->bottom;
	--stack;

	otop = stack->top;
	ntop = stack->top = otop - 1;

	assert(__is_aligned(ntop, _Alignof(typeof(*ntop))));
	*ntop = (struct sigframe) {
		.info = *info,
		.context = *ucp
	};

	/*
	 * Provide the original top of the target compartment's stack in the
	 * copy of the context.
	 */
	ntop->context.uc_mcontext.mc_capregs.cap_sp = (uintptr_t)otop;

	return (struct dispatch_signal_ret) {
		.info = &ntop->info,
		.ucp = &ntop->context
	};
}

void dispatch_signal_end(ucontext_t *, ucontext_t *);

void
dispatch_signal_end(ucontext_t *new, ucontext_t *old __unused)
{
	void *top;
	struct stk_bottom *stack;

	top = (void *)new->uc_mcontext.mc_capregs.cap_sp;
	stack = cheri_setoffset(top, cheri_getlen(top));
	--stack;

	/*
	 * Restore the top of the target compartment's stack to the value in the
	 * context.
	 */
	stack->top = top;
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
	/*
	 * XXX: Ignore sigaltstack for now.
	 */
	act->sa_flags &= ~SA_ONSTACK;

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
