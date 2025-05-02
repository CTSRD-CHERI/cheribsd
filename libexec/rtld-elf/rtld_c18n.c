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

/*
 * Design overview of compartmentalisation (c18n)
 *
 * When RTLD is relocating function symbols (during startup for GOT entries and
 * during program execution for lazily-bound symbols), tramp_intern is called to
 * create a trampoline that wraps the resolved function.
 *
 * Exactly one trampoline is constructed for each resolved function, where
 * uniqueness is guaranteed by a hash-table. When a cross-compartment function
 * call takes place, the trampoline intercepts the control-flow and performs a
 * domain transition from the caller's compartment to the callee's. A domain
 * transition consists of switching the execution stack and clearing non-
 * argument registers so that no capability leaks to the callee that is not
 * passed as an argument.
 *
 * During a domain transition, the trampoline uses a stack lookup table of type
 * 'struct stk_table' to record and retrieve the current stack top of each
 * compartment. In addition, the trampoline pushes a trusted frame of type
 * 'struct trusted_frame' to a trusted stack that records the path of domain
 * transitions. When the callee returns, control-flow is passed again to the
 * trampoline, which reverses the domain transition and pops the topmost trusted
 * frame from the trusted stack.
 *
 * Stack unwinding due to either setjmp/longjmp or C++ exceptions is supported.
 * The relevant parts of libc and libunwind have been modified so that when
 * attempting to save/restore the program state, RTLD hooks are called to update
 * state related to compartmentalisation such as the contents of the trusted
 * stack and the stack lookup table.
 *
 * Compartmentalisation integrates well with the POSIX signal mechanism. When
 * the user registers a signal handler, RTLD (or libthr, if multi-threading is
 * enabled) instead registers _rtld_sighandler on their behalf. When a signal
 * arrives, _rtld_sighandler dispatches the signal to the registered handler to
 * be run in its own compartment.
 */

#include <sys/param.h>
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <machine/sigframe.h>
#ifdef CHERI_LIB_C18N
#include <machine/sysarch.h>
#endif

#include <cheri/c18n.h>

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_c18n.h"
#include "rtld_libc.h"
#include "rtld_utrace.h"

_Static_assert(
    TRUSTED_FRAME_SIZE * sizeof(uintptr_t) == sizeof(struct trusted_frame),
    "Unexpected struct trusted_frame size");
_Static_assert(
    TRUSTED_FRAME_SP_OSP == offsetof(struct trusted_frame, state.sp),
    "Unexpected struct trusted_frame member offset");
_Static_assert(
    TRUSTED_FRAME_PREV == offsetof(struct trusted_frame, previous),
    "Unexpected struct trusted_frame member offset");
_Static_assert(
    TRUSTED_FRAME_CALLER == offsetof(struct trusted_frame, caller),
    "Unexpected struct trusted_frame member offset");
_Static_assert(
    TRUSTED_FRAME_CALLEE == offsetof(struct trusted_frame, callee),
    "Unexpected struct trusted_frame member offset");
_Static_assert(
    TRUSTED_FRAME_LANDING == offsetof(struct trusted_frame, landing),
    "Unexpected struct trusted_frame member offset");

_Static_assert(
    STACK_TABLE_RTLD == cid_to_index_raw(RTLD_COMPART_ID),
    "Unexpected struct stk_table member offset");

_Static_assert(sizeof(struct func_sig) == sizeof(func_sig_int),
    "Unexpected func_sig size");

_Static_assert(
    SIG_FRAME_SIZE == sizeof(struct sigframe),
    "Unexpected struct sigframe size");

/*
 * Sealers for RTLD privileged information
 */
#ifndef CHERI_LIB_C18N_NO_OTYPE
static uintptr_t sealer_tcb;
static uintptr_t sealer_trusted_stk;

uintptr_t sealer_pltgot;
#endif

#ifndef HAS_RESTRICTED_MODE
uintptr_t sealer_tidc;
#endif

/* Enable compartmentalisation */
bool ld_compartment_enable;

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

/* Export compartmentalisation statistics to a file */
const char *ld_compartment_stats;

/* Export count of compartment switches to statistics */
const char *ld_compartment_switch_count;

/* Compartmentalisation information exported to the kernel */
static struct cheri_c18n_info *c18n_info;
struct rtld_c18n_stats *c18n_stats;

#define	INC_NUM_COMPART		(c18n_stats->rcs_compart++, comparts.size++)
#define	INC_NUM_BYTES(n)						\
	atomic_fetch_add_explicit(&c18n_stats->rcs_bytes_total, (n),	\
	    memory_order_relaxed)

static void *
c18n_malloc(size_t n)
{
	void *buf = xmalloc(n);

	INC_NUM_BYTES(cheri_getlen(buf));
	return (buf);
}

static void *
c18n_realloc(void *buf, size_t new)
{
	size_t old = buf == NULL ? 0 : cheri_getlen(buf);

	buf = realloc(buf, new);
	if (buf == NULL)
		rtld_fatal("realloc failed");
	new = cheri_getlen(buf);
	INC_NUM_BYTES(new - old);
	return (buf);
}

static void
c18n_free(void *buf)
{
	size_t old = buf == NULL ? 0 : cheri_getlen(buf);

	free(buf);
	INC_NUM_BYTES(-old);
}

static char *
c18n_strdup(const char *s)
{
	char *buf = strdup(s);

	INC_NUM_BYTES(cheri_getlen(buf));
	return (buf);
}

/*
 * Policies
 */
typedef size_t string_handle;

struct string_base {
	char *buf;
	string_handle size;
	string_handle capacity;
};

#define	C18N_STRING_BASE_INIT	32

static void
string_base_expand(struct string_base *sb, size_t capacity)
{
	sb->buf = c18n_realloc(sb->buf, capacity);
	sb->capacity = capacity;
}

static void
string_base_push(struct string_base *sb, const char *str)
{
	string_handle cap;
	size_t len;

	len = strlen(str) + 1;
	if (sb->size + len > sb->capacity) {
		cap = MAX(C18N_STRING_BASE_INIT, sb->capacity * 2);
		while (sb->size + len > cap)
			cap *= 2;

		string_base_expand(sb, cap);
	}
	memcpy(sb->buf + sb->size, str, len);
	sb->size += len;
}

static bool
string_base_search(const struct string_base *sb, const char *str)
{
	const char *cp, *end;

	cp = sb->buf;
	end = cp + sb->size;
	while (cp < end) {
		if (strcmp(cp, str) == 0)
			return (true);
		cp = strchr(cp, '\0') + 1;
	}

	return (false);
}

struct compart {
	/*
	 * Compartment information exposed to the kernel.
	 */
	struct rtld_c18n_compart info;
	/*
	 * Name of the compartment.
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

extern int _compart_size;
int _compart_size = sizeof(struct compart);

extern struct r_debug r_debug;

void
r_debug_comparts_state(struct r_debug *, struct compart *);
void
r_debug_comparts_state(struct r_debug *rd __unused, struct compart *m __unused)
{
	/*
	 * See r_debug_state().
	 */
	__compiler_membar();
}

#define GDB_COMPARTS_STATE(s,m)				\
	r_debug.r_comparts_state = s; r_debug_comparts_state(&r_debug, m);

/*
 * A pseudo-compartment that encompasses all compartments.
 */
static struct compart uni_compart;

static struct {
	struct compart *data;
	compart_id_t size;
	compart_id_t capacity;
} comparts;

static void
expand_comparts_data(compart_id_t capacity)
{
	struct compart *data;

	atomic_fetch_add_explicit(&c18n_info->comparts_gen, 1,
	    memory_order_acq_rel);

	data = c18n_realloc(comparts.data, sizeof(*data) * capacity);
	comparts.data = c18n_info->comparts = r_debug.r_comparts = data;
	comparts.capacity = capacity;

	atomic_fetch_add_explicit(&c18n_info->comparts_gen, 1,
	    memory_order_acq_rel);
}

static struct compart *
add_comparts_data(const char *name)
{
	compart_id_t i;
	struct compart *com;
	char *c_name;

	rtld_require(comparts.size <= COMPART_ID_MAX,
	    "c18n: Compartment ID overflow for %s", name);

	c_name = c18n_strdup(name);

	if (comparts.size == comparts.capacity)
		expand_comparts_data(comparts.capacity * 2);

	atomic_fetch_add_explicit(&c18n_info->comparts_gen, 1,
	    memory_order_acq_rel);
	GDB_COMPARTS_STATE(RCT_ADD, NULL);

	i = INC_NUM_COMPART;
	com = &comparts.data[i];
	*com = (struct compart) {
		.info = (struct rtld_c18n_compart) {
			.rcc_name = c_name,
			.rcc_id = i
		},
		.name = c_name
	};
	c18n_info->comparts_size = r_debug.r_comparts_size = comparts.size;

	atomic_fetch_add_explicit(&c18n_info->comparts_gen, 1,
	    memory_order_acq_rel);
	GDB_COMPARTS_STATE(RCT_CONSISTENT, com);

	return (com);
}

compart_id_t
compart_id_allocate(const char *lib, int flags)
{
	compart_id_t i;
	struct compart *com;

	/*
	 * Start searching from the first compartment
	 */
	for (i = RTLD_COMPART_ID; i < comparts.size; ++i) {
		com = &comparts.data[i];
		if (string_base_search(&com->libs, lib))
			goto out;
	}

	com = add_comparts_data(lib);
	string_base_push(&com->libs, lib);

out:
	com->info.rcc_dlopened_explicitly = (flags & RTLD_LO_DLOPEN_TOP) != 0;
	com->info.rcc_dlopened = (flags & RTLD_LO_DLOPEN) != 0;
	return (i);
}

static compart_id_t
compart_name_to_id(const char *name)
{
	compart_id_t i;

	/*
	 * Start searching from the first compartment
	 */
	for (i = RTLD_COMPART_ID; i < comparts.size; ++i)
		if (strcmp(comparts.data[i].name, name) == 0)
			return (i);

	rtld_fatal("c18n: Cannot find compartment ID for %s", name);
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
				com = add_comparts_data(buf);
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
				rule = c18n_malloc(sizeof(*rule));
				*rule = (struct rule) {
					.callee = id,
					.action = SLIST_HEAD_INITIALIZER()
				};
			} else
				policy_error(&cur);

			while (eat(&cur, "export to "))
				if (eat_token(&cur, '\n', buf, sizeof(buf))) {
					id = compart_name_to_id(buf);
					act = c18n_malloc(sizeof(*act));
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
	    !string_base_search(&comparts.data[caller].imports, sym))
		return (false);

	SLIST_FOREACH(cur, &rules, link) {
		if (cur->callee != callee ||
		    !string_base_search(&cur->symbols, sym))
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
tramp_should_include(const Plt_Entry *plt, compart_id_t caller,
    const struct tramp_data *data)
{
	compart_id_t callee;
	const char *sym;

	if (data->def == NULL)
		return (true);

	if (data->def == &sym_zero)
		return (false);

	sym = strtab_value(data->defobj, data->def->st_name);

	if (string_base_search(&uni_compart.trusts, sym))
		return (false);

	callee = compart_id_for_address(data->defobj, (ptraddr_t)data->target);

	/*
	 * Jump slots within the same compartment do not require a
	 * trampoline.
	 */
	if (plt != NULL && caller == callee)
		return (false);

	if (string_base_search(&comparts.data[caller].trusts, sym))
		return (false);

	if (evaluate_rules(caller, callee, sym))
		return (true);

	rtld_fatal("c18n: Policy violation: %s is not allowed to access symbol "
	    "%s defined by %s",
	    comparts.data[caller].name, sym,
	    comparts.data[callee].name);
}

/*
 * Stack switching
 */
/*
 * Assembly function with non-standard ABI.
 */
void create_untrusted_stk(void);

static _Atomic(struct stk_table *) dead_stk_tables;

/*
 * A fake tcb that is passed to libthr during thread creation and destruction.
 */
struct tcb_wrapper {
	struct tcb header __attribute__((cheri_no_subobject_bounds));
	struct tcb *tcb;
	struct stk_table *table;
#ifndef HAS_RESTRICTED_MODE
#ifdef CHERI_LIB_C18N_NO_OTYPE
	struct tidc *tidc;
#else
	struct tidc tidc;
#endif
#endif
};

#if !defined(HAS_RESTRICTED_MODE) && defined(CHERI_LIB_C18N_NO_OTYPE)
/* Maximum number of threads lifted from thr_list.c */
#define	MAX_THREADS	100000

static struct tidc *tidc_freelist;

static struct tidc *
allocate_tidc(void)
{
	struct tidc *tidc;

	tidc = tidc_freelist;
	if (tidc == NULL) {
		rtld_fdprintf(STDERR_FILENO, "c18n: Cannot allocate tidc\n");
		abort();
	}
	tidc_freelist = tidc->next;

	return (tidc);
}

static void
free_tidc(struct tidc *tidc)
{
	tidc->next = tidc_freelist;
	tidc_freelist = tidc;
}

static uintptr_t
init_tidc_table(size_t len)
{
	struct tidc *table, *tidc;

	table = c18n_malloc(sizeof(*table) * len);
	for (size_t i = 0; i < len; ++i) {
		tidc = cheri_setboundsexact(&table[i], sizeof(*tidc));
		free_tidc(tidc);
	}

	return ((uintptr_t)table);
}
#endif

static void
push_stk_table(_Atomic(struct stk_table *) *head, struct stk_table *table)
{
	struct stk_table **link = &SLIST_NEXT(table, next);

	*link = atomic_load_explicit(head, memory_order_relaxed);

	while (!atomic_compare_exchange_weak_explicit(head, link, table,
	    /*
	     * Use release ordering to ensure that table use happens before the
	     * push.
	     */
	    memory_order_release, memory_order_relaxed));
}

static struct stk_table *
pop_stk_table(_Atomic(struct stk_table *) *head)
{
	struct stk_table *table, *next;

	table = atomic_load_explicit(head, memory_order_relaxed);

	do {
		next = SLIST_NEXT(table, next);
	} while (!atomic_compare_exchange_weak_explicit(head, &table, next,
	    /*
	     * Use acquire ordering to ensure that the pop happens before table
	     * use.
	     */
	    memory_order_acquire, memory_order_relaxed));

	return (table);
}

static struct stk_table *
expand_stk_table(struct stk_table *table, size_t capacity)
{
	size_t o_capacity;
	bool create = table == NULL;

	table = c18n_realloc(table,
	    sizeof(*table) + sizeof(*table->entries) * capacity);

	if (create)
		table->meta = NULL;

	table->meta = c18n_realloc(table->meta,
	    sizeof(*table->meta) +
	    sizeof(*table->meta->compart_stk) * capacity);
	if (table->meta == NULL)
		rtld_fatal("realloc failed");

	if (create) {
		table->resolver = create_untrusted_stk;
		table->meta->wrap = NULL;
		table->meta->trusted_stk = (struct stk_table_stk_info) {};
		o_capacity = 0;
	} else
		o_capacity = table->meta->capacity;

	table->meta->capacity =
	    (cheri_getlen(table) - offsetof(typeof(*table), entries)) /
	    sizeof(*table->entries);

	for (size_t i = o_capacity; i < table->meta->capacity; ++i) {
		table->meta->compart_stk[i] = (struct stk_table_stk_info) {};
		table->entries[i] = (struct stk_table_entry) {
			.stack = create_untrusted_stk,
		};
	}

	return (table);
}

struct tcb *
c18n_allocate_tcb(struct tcb *tcb)
{
	struct stk_table *table;
	struct tcb_wrapper *wrap;

	table = expand_stk_table(NULL, comparts.size);

	wrap = c18n_malloc(sizeof(*wrap));
	*wrap = (struct tcb_wrapper) {
		.header = *tcb,
		.tcb = c18n_seal(tcb, sealer_tcb),
		.table = c18n_seal(table, sealer_tcb),
#if !defined(HAS_RESTRICTED_MODE) && defined(CHERI_LIB_C18N_NO_OTYPE)
		.tidc = allocate_tidc()
#endif
	};

	return (&wrap->header);
}

void
c18n_free_tcb(void)
{
	struct stk_table *table;

	table = pop_stk_table(&dead_stk_tables);

#if !defined(HAS_RESTRICTED_MODE) && defined(CHERI_LIB_C18N_NO_OTYPE)
	free_tidc(table->meta->wrap->tidc);
#endif
	c18n_free(table->meta->wrap);
	c18n_free(table->meta);
	c18n_free(table);
}

static void *
create_stk(size_t size)
{
	char *stk;

	stk = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_STACK, -1, 0);
	if (stk == MAP_FAILED)
		rtld_fatal("mmap failed");

	return (stk + size);
}

#define	C18N_TRUSTED_STACK_SIZE		(128 * 1024)
#define	C18N_SIG_STACK_SIZE		SIGSTKSZ

int     __sys_sigaltstack(const stack_t *, stack_t *);

static void
init_stk_table(struct stk_table *table, struct tcb_wrapper *wrap)
{
	char *sp;
	size_t size;
#ifndef USE_RESTRICTED_MODE
	stack_t osigstk;
#endif
	struct trusted_frame *tf;
#ifndef HAS_RESTRICTED_MODE
	struct tidc *tidc;
#endif

	/*
	 * Save the fake tcb in the stack lookup table.
	 */
	table->meta->wrap = wrap;

#ifndef USE_RESTRICTED_MODE
	/*
	 * Create a signal stack, record it in the stack lookup table, and
	 * register it.
	 */
	size = C18N_SIG_STACK_SIZE;
	sp = create_stk(size);
	table->meta->sig_stk = (struct stk_table_stk_info) {
		.size = size,
		.begin = sp - size
	};
	if (__sys_sigaltstack(
	    &(stack_t) { .ss_sp = sp - size, .ss_size = size },
	    &osigstk) != 0) {
		rtld_fdprintf(STDERR_FILENO, "c18n: sigaltstack failed\n");
		abort();
	}
	assert(osigstk.ss_flags == SS_DISABLE);
#endif

	/*
	 * Create a trusted stack and record it in the stack lookup table.
	 */
	size = C18N_TRUSTED_STACK_SIZE;
	tf = create_stk(size);
	table->meta->trusted_stk = (struct stk_table_stk_info) {
		.size = size,
		.begin = (char *)tf - size
	};

	/*
	 * Record RTLD's stack in the stack lookup table.
	 */
#ifndef USE_RESTRICTED_MODE
	sp = cheri_setoffset(cheri_getstack(), 0);
#else
	/*
	 * RTLD's actual stack is the Executive stack which does not need to be
	 * stored in the stack lookup table. Instead, fill the table entry with
	 * a one-byte dummy stack.
	 *
	 * Note that NULL cannot be used here because a compartment can then
	 * pretend to be RTLD when a signal is delivered. Nor can a zero-length
	 * stack be used because the signal handler uses the recorded size of
	 * the stack to determine whether it has been allocated.
	 */
	static char dummy_stk;
	sp = &dummy_stk;
	set_untrusted_stk(sp);
#endif
	size = cheri_getlen(sp);
	assert(size > 0);
	table->meta->compart_stk[RTLD_COMPART_ID] = (struct stk_table_stk_info)
	{
		.size = size,
		.begin = sp
	};
	table->entries[RTLD_COMPART_ID].stack = sp + size;

#ifndef HAS_RESTRICTED_MODE
	/*
	 * Install the tidc buffer.
	 */
#ifdef CHERI_LIB_C18N_NO_OTYPE
	tidc = wrap->tidc;
#else
	tidc = cheri_setboundsexact(&wrap->tidc, sizeof(*tidc));
#endif
	tidc = c18n_seal_subset(tidc, sealer_tidc);
	if (sysarch(RISCV_SET_UTIDC, &tidc) != 0) {
		rtld_fdprintf(STDERR_FILENO, "c18n: Cannot set tidc %#p\n",
		    tidc);
		abort();
	}
#endif

	/*
	 * Push a dummy trusted frame indicating that the 'root' compartment is
	 * RTLD.
	 */
	tf = push_dummy_rtld_trusted_frame(tf);

	/*
	 * Install the stack lookup table.
	 */
	set_stk_table(table);
}

#define	C18N_STACK_SIZE		(4 * 1024 * 1024)

/*
 * This function must be called under an rtld_tramp_lock to ensure that
 * compartments are not being added or removed concurrently.
 */
static void *
get_or_create_untrusted_stk(compart_id_t cid, struct stk_table **tablep)
{
	char *stk;
	size_t size;
	struct stk_table *table = *tablep;

	if (table->meta->capacity <= cid) {
		/*
		 * If the compartment ID exceeds the capacity of the stack
		 * lookup table, then new libraries must have been loaded.
		 */
		*tablep = table = expand_stk_table(table, comparts.size);
		set_stk_table(table);
	} else if (table->meta->compart_stk[cid].size > 0)
		return (table->entries[cid].stack);

	size = C18N_STACK_SIZE;
	stk = create_stk(size);

	table->meta->compart_stk[cid] = (struct stk_table_stk_info) {
		.size = size,
		.begin = stk - size
	};
	table->entries[cid].stack = cheri_clearperm(stk, CHERI_PERM_SW_VMEM);

	atomic_fetch_add_explicit(&c18n_stats->rcs_ustack, 1,
	    memory_order_relaxed);

	return (stk);
}

void *resolve_untrusted_stk_impl(stk_table_index);

void *
resolve_untrusted_stk_impl(stk_table_index index)
{
	void *stk;
	sigset_t nset, oset;
	struct stk_table *table;
	struct trusted_frame *tf;
	RtldLockState lockstate;

	/*
	 * Push a dummy trusted frame indicating that the current compartment is
	 * RTLD.
	 */
	tf = push_dummy_rtld_trusted_frame(get_trusted_stk());

	/*
	 * Make the function re-entrant by blocking all signals and re-check
	 * whether the stack needs to be allocated.
	 */
	SIGFILLSET(nset);
	sigprocmask(SIG_SETMASK, &nset, &oset);
	rlock_acquire(rtld_tramp_lock, &lockstate);

	table = get_stk_table();
	stk = get_or_create_untrusted_stk(index_to_cid(index), &table);

	lock_release(rtld_tramp_lock, &lockstate);
	sigprocmask(SIG_SETMASK, &oset, NULL);

	tf = pop_dummy_rtld_trusted_frame(tf);

	return (stk);
}

/*
 * Stack unwinding
 *
 * APIs exposed to stack unwinders (e.g., libc setjmp/longjmp and libunwind)
 */
int
c18n_is_tramp(uintptr_t pc, const struct trusted_frame *tf)
{
	if (!cheri_gettag(pc))
		return (0);
	return (pc == tf->landing);
}

void *
dl_c18n_get_trusted_stack(uintptr_t pc)
{
	/*
	 * Return a sealed capability to the caller's trusted frame. But if the
	 * caller is entered via a trampoline and a return capability to said
	 * trampoline is passed as the argument, return a sealed capability to
	 * the trusted frame of the caller's own caller.
	 */

	struct trusted_frame *tf;

	if (!C18N_ENABLED)
		return (NULL);

	tf = get_trusted_stk()->previous;
	if (c18n_is_tramp(pc, tf))
		tf = tf->previous;

	return (c18n_seal_subset(tf, sealer_trusted_stk));
}

void
dl_c18n_unwind_trusted_stack(void *rcsp, void *target)
{
	/*
	 * Traverse the trusted stack and unwind the untrusted stack of each
	 * compartment until reaching the target compartment. Then return to the
	 * target compartment while installing the untrusted stack passed by the
	 * argument.
	 */

	void **ospp;
	compart_id_t cid;
	stk_table_index index;
	struct stk_table *table;
	struct trusted_frame *cur, *tf;
	sigset_t nset, oset;

	if (!C18N_ENABLED)
		return;

	/*
	 * Make the function re-entrant by blocking all signals.
	 */
	SIGFILLSET(nset);
	sigprocmask(SIG_SETMASK, &nset, &oset);

	tf = get_trusted_stk();
	target = c18n_unseal_subset(target, sealer_trusted_stk, tf);

	if (!cheri_is_subset(tf, target) ||
	    (ptraddr_t)tf->previous >= (ptraddr_t)target) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: Illegal unwind from %#p to %#p\n", tf, target);
		abort();
	}

	/*
	 * Unwind each frame before the target frame.
	 */
	cur = tf;
	table = get_stk_table();
	do {
		index = cur->caller;
		cid = index_to_cid(index);
		ospp = &table->entries[cid].stack;

		if ((ptraddr_t)*ospp > (ptraddr_t)cur->osp) {
			rtld_fdprintf(STDERR_FILENO,
			    "c18n: Cannot unwind %s from %#p to %#p\n",
			    comparts.data[cid].name, *ospp, cur->osp);
			abort();
		}

		*ospp = cur->osp;
		cur = cur->previous;
	} while ((ptraddr_t)cur < (ptraddr_t)target);

	if ((ptraddr_t)cur != (ptraddr_t)target) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: Illegal unwind from %#p to %#p\n", cur, target);
		abort();
	}

	/*
	 * Link the topmost trusted frame to the target frame. Modify the
	 * topmost trusted frame to restore the untrusted stack when it is
	 * popped.
	 */
	if ((ptraddr_t)rcsp > (ptraddr_t)*ospp) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: Cannot complete unwind %s from %#p to %#p, ",
		    "tf: %#p -> %#p\n", comparts.data[cid].name, rcsp, *ospp,
		    tf, target);
		abort();
	}

	tf->state.sp = rcsp;
	tf->osp = *ospp;
	tf->previous = cur;
	tf->caller = index;

	sigprocmask(SIG_SETMASK, &oset, NULL);
}

int
dl_c18n_is_trampoline(uintptr_t pc, void *tfs)
{
	struct trusted_frame *tf;

	if (!C18N_ENABLED)
		return (0);

	tf = c18n_unseal_subset(tfs, sealer_trusted_stk, get_trusted_stk());
	if (!cheri_gettag(tf))
		return (0);

	return (c18n_is_tramp(pc, tf));
}

void *
dl_c18n_pop_trusted_stack(struct dl_c18n_compart_state *state, void *tfs)
{
	struct trusted_frame *tf;

	if (!C18N_ENABLED)
		return (NULL);

	tf = c18n_unseal_subset(tfs, sealer_trusted_stk, get_trusted_stk());
	*state = tf->state;
	return (c18n_seal_subset(tf->previous, sealer_trusted_stk));
}

/*
 * Trampolines
 */
static size_t tramp_pg_size;

static struct tramp_pg *
tramp_pg_new(struct tramp_pg *next)
{
	size_t capacity = tramp_pg_size;
	struct tramp_pg *pg;

	pg = mmap(NULL, capacity, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON,
	    -1, 0);
	if (pg == MAP_FAILED)
		rtld_fatal("mmap failed");
	SLIST_NEXT(pg, link) = next;
	atomic_store_explicit(&pg->size, 0, memory_order_relaxed);
	pg->capacity = capacity - offsetof(typeof(*pg), trampolines);

	atomic_fetch_add_explicit(&c18n_stats->rcs_tramp_page, 1,
	    memory_order_relaxed);

	return (pg);
}

static void *
tramp_pg_push(struct tramp_pg *pg, size_t len)
{
	char *tramp;
	size_t size, n_size;

	if (pg == NULL)
		return (NULL);

	size = atomic_load_explicit(&pg->size, memory_order_relaxed);
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

	tramp = cheri_setboundsexact(tramp, len);
	assert(cheri_gettag(tramp));

	return (tramp);
}

static struct {
	_Alignas(CACHE_LINE_SIZE) _Atomic(slot_idx_t) size;
	slot_idx_t dead;
	int exp;
	struct tramp_header **data;
	struct tramp_map_kv {
		_Atomic(ptraddr_t) key;
		_Atomic(slot_idx_t) index;
	} *map;
	_Alignas(CACHE_LINE_SIZE) _Atomic(slot_idx_t) writers;
} tramp_table;

static slot_idx_t
tramp_table_max_load(int exp)
{
	/* MAX_LOAD is 37.5% of capacity. */
	return (3 << (exp - 3));
}

static slot_idx_t
expand_tramp_table(int exp)
{
	slot_idx_t size, cur = 0;

	/*
	 * The lower bound ensures that the maximum load can be calculated
	 * without underflow. The upper bound ensures that the index does not
	 * overflow.
	 */
	assert(3 <= exp && exp <= 30);
	tramp_table.exp = exp;

	c18n_free(tramp_table.map);
	/*
	 * The data array only needs to be as large as the maximum load.
	 */
	tramp_table.data = c18n_realloc(tramp_table.data,
	    sizeof(*tramp_table.data) * tramp_table_max_load(exp));
	size = atomic_load_explicit(&tramp_table.size, memory_order_relaxed);
	for (slot_idx_t i = 0; i < size; ++i)
		if (tramp_table.data[i] == NULL)
			tramp_table.dead -= 1;
		else {
			tramp_table.data[i]->index = cur;
			tramp_table.data[cur++] = tramp_table.data[i];
		}
	assert(tramp_table.dead == 0);
	atomic_store_explicit(&tramp_table.size, cur, memory_order_relaxed);
	tramp_table.map = c18n_malloc(sizeof(*tramp_table.map) << exp);

	for (size_t i = 0; i < (1 << exp); ++i)
		tramp_table.map[i] = (struct tramp_map_kv) {
			.key = 0,
			.index = -1
		};

	return (cur);
}

/* Public domain. Taken from https://github.com/skeeto/hash-prospector */
static uint32_t
hash_pointer(ptraddr_t key)
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

	/*
	 * If there are no dead entries, then we have to increase the size of
	 * the table rather than just discard the dead entries.
	 */
	if (tramp_table.dead == 0)
		exp += 1;

	size = expand_tramp_table(exp);

	for (slot_idx_t idx = 0; idx < size; ++idx) {
		key = (ptraddr_t)atomic_load_explicit(
		    &tramp_table.data[idx]->target, memory_order_relaxed);
		hash = hash_pointer(key);
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
tramp_hook_impl(int, const struct tramp_header *);

void
tramp_hook_impl(int event, const struct tramp_header *hdr)
{
	const char *sym;
	const char *callee;
	const char *caller;
	struct utrace_c18n ut;
	const struct trusted_frame *tf = get_trusted_stk();

	if (ld_compartment_utrace != NULL) {
		if (hdr->symnum == 0)
			sym = "<unknown>";
		else
			sym = symname(hdr->defobj, hdr->symnum);
		callee = comparts.data[index_to_cid(tf->callee)].name;
		caller = comparts.data[index_to_cid(tf->caller)].name;

		memcpy(ut.sig, C18N_UTRACE_SIG, C18N_UTRACE_SIG_SZ);
		ut.event = event;
		ut.symnum = hdr->symnum;
		ut.fp = tf->state.fp;
		ut.pc = tf->state.pc;
		ut.sp = tf->state.sp;
		ut.osp = tf->osp;
		ut.previous = tf->previous;
		memcpy(&ut.fsig, &hdr->sig, sizeof(ut.fsig));
		strlcpy(ut.symbol, sym, sizeof(ut.symbol));
		strlcpy(ut.callee, callee, sizeof(ut.callee));
		strlcpy(ut.caller, caller, sizeof(ut.caller));
		utrace(&ut, sizeof(ut));
	}
	if (ld_compartment_overhead != NULL)
		getpid();
}

static struct tramp_header *
tramp_pgs_alloc(Obj_Entry *obj, const char buf[], const char *bufp, size_t len)
{
	char *tramp;
	struct tramp_pg *pg;
	struct tramp_header *header;

	pg = atomic_load_explicit(&obj->tramp_pgs, memory_order_acquire);
	tramp = tramp_pg_push(pg, len);
	if (tramp == NULL) {
		while (atomic_flag_test_and_set_explicit(&obj->tramp_pgs_lock,
		    memory_order_acquire));
		pg = atomic_load_explicit(&obj->tramp_pgs,
		    memory_order_relaxed);
		tramp = tramp_pg_push(pg, len);
		if (tramp == NULL) {
			pg = tramp_pg_new(pg);
			tramp = tramp_pg_push(pg, len);
			atomic_store_explicit(&obj->tramp_pgs, pg,
			    memory_order_release);
		}
		atomic_flag_clear_explicit(&obj->tramp_pgs_lock,
		    memory_order_release);
	}
	assert(cheri_gettag(tramp));

	memcpy(tramp, buf, len);
	header = (struct tramp_header *)(tramp + (bufp - buf));

#ifdef __aarch64__
	/*
	 * Ensure i- and d-cache coherency after writing executable code. The
	 * __clear_cache procedure rounds the addresses to cache-line-aligned
	 * addresses. Derive the start address from pg so that it has
	 * sufficiently large bounds to contain these rounded addresses.
	 */
	__clear_cache(cheri_copyaddress(pg, header->entry), tramp + len);
#elif __riscv
	/*
	 * XXX Dapeng: This is insufficient for multicore as fence.i only
	 * guarantees consistency on the current core.
	 */
	asm volatile ("fence.i");
#endif

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
tramp_check_found(struct tramp_header *found, const Obj_Entry *reqobj,
    const struct tramp_data *data)
{
	struct func_sig sig;
	void *found_target;

	if (data->sig.valid && found->symnum != 0) {
		sig = sigtab_get(found->defobj, found->symnum);

		rtld_require(!sig.valid || func_sig_equal(data->sig, sig),
		    "Incompatible signatures for function %s: "
		    "%s requests " C18N_SIG_FORMAT_STRING " but "
		    "%s provides " C18N_SIG_FORMAT_STRING,
		    symname(found->defobj, found->symnum),
		    reqobj != NULL ? reqobj->path : "",
		    C18N_SIG_FORMAT(data->sig),
		    found->defobj->path, C18N_SIG_FORMAT(sig));
	}

	if (!cheri_gettag(data->target))
		return;

	found_target = atomic_load_explicit(&found->target,
	    memory_order_relaxed);
	do {
		if (cheri_gettag(found_target)) {
			rtld_require(
			    cheri_equal_exact(found_target, data->target),
			    "c18n: Incompatible capability metadata for "
			    "function %s: found %#p, requested %#p\n",
			    symname(found->defobj, found->symnum),
			    found_target, data->target);
			break;
		} else if (atomic_compare_exchange_weak_explicit(&found->target,
		    &found_target, data->target,
		    memory_order_relaxed, memory_order_relaxed)) {
			/*
			 * Issue a release fence to prevent the storing of the
			 * updated target from being reordered with any
			 * subsequent store. This ensures that the updated
			 * target is visible to the trampoline when it is
			 * potentially run in another thread.
			 *
			 * Strictly speaking, C semantics requires a
			 * corresponding acquire operation for the ordering to
			 * be established. But in reality this fence alone is
			 * sufficient to prevent store-store reordering.
			 */
			atomic_thread_fence(memory_order_release);
			break;
		}
	} while (1);
}

#define	C18N_MAX_TRAMP_SIZE	768

static struct tramp_header *
tramp_create(const struct tramp_data *data)
{
	struct tramp_data newdata = *data;
	/* A capability-aligned buffer large enough to hold a trampoline */
	_Alignas(_Alignof(struct tramp_header)) char buf[C18N_MAX_TRAMP_SIZE];
	char *bufp = buf;
	size_t len;

	if (!newdata.sig.valid && newdata.def != NULL)
		newdata.sig = sigtab_get(newdata.defobj,
		    newdata.def - newdata.defobj->symtab);

	len = tramp_compile(&bufp, &newdata);
	return (tramp_pgs_alloc(data->defobj, buf, bufp, len));
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

#if defined(__aarch64__) && defined(CHERI_LIB_C18N_NO_OTYPE)
const void *
plt_tramp_make(Plt_Entry *plt)
{
	struct tramp_header *header;
	/* A capability-aligned buffer large enough to hold a trampoline */
	_Alignas(_Alignof(struct tramp_header)) char buf[72];
	char *bufp = buf;
	size_t len;

	len = plt_tramp_compile(&bufp, plt);
	header = tramp_pgs_alloc(buf, bufp, len);

	return (tramp_make_entry(header));
}
#endif

void *
tramp_intern(const Plt_Entry *plt, compart_id_t caller,
    const struct tramp_data *data)
{
	RtldLockState lockstate;
	void *tramp_entry;
	struct tramp_header *header;
	ptraddr_t target = (ptraddr_t)data->target;
	const uint32_t hash = hash_pointer(target);
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
		 * Currently, the decision to elide the trampoline or not is
		 * coupled with the decision of whether the symbol should be
		 * made accessible to the requesting object. This is insecure.
		 */
		assert(plt == NULL);
	else if (data->def == &sym_zero)
		assert(data->target == NULL);
	else
		assert(data->defobj->symtab <= data->def &&
		    data->def < data->defobj->symtab +
		    data->defobj->dynsymcount);
	assert(func_sig_legal(data->sig));

	if (!tramp_should_include(plt, caller, data))
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
	atomic_fetch_add_explicit(&c18n_stats->rcs_tramp, 1,
	    memory_order_relaxed);

	/*
	 * Invariant: tramp_table.size <= MAX_LOAD
	 *
	 * Create the data array entry.
	 */
	header = tramp_table.data[idx] = tramp_create(data);

	/*
	 * Complete initialisation of the trampoline.
	 */
	do
		header->next = atomic_load_explicit(&header->defobj->tramps,
		    memory_order_relaxed);
	while (!atomic_compare_exchange_weak_explicit(&header->defobj->tramps,
	    &header->next, header,
	    /*
	     * Relaxed ordering is sufficient because the linked-list is only
	     * otherwise accessed under a mutex, when all trampolines pointing
	     * to a shared object are deleted from the hash table.
	     */
	    memory_order_relaxed, memory_order_relaxed));
	header->index = idx;

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
		resize_table(exp);
	}
end:
	lock_release(rtld_tramp_lock, &lockstate);

	/*
	 * Check that the found trampoline matches the expected signature (if
	 * any) of the requester. Also fill out the trampoline target if the
	 * trampoline is partially constructed from a previous untagged target.
	 */
	tramp_check_found(header, plt != NULL ? plt->obj : NULL, data);

	/*
	 * Defensive programming: if the requester supplies an untagged target
	 * capability, return an untagged trampoline.
	 */
	tramp_entry = tramp_make_entry(header);
	if (!cheri_gettag(data->target))
		tramp_entry = cheri_cleartag(tramp_entry);

	return (tramp_entry);
}

struct func_sig
sigtab_get(const Obj_Entry *obj, unsigned long symnum)
{
	if (symnum >= obj->dynsymcount) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: Invalid symbol number %lu for %s\n",
		    symnum, obj->path);
		abort();
	}

	if (obj->sigtab == NULL)
		return ((struct func_sig) { .valid = false });

	return (obj->sigtab[symnum]);
}

struct tramp_header *
tramp_reflect(const void *data)
{
	Obj_Entry *obj;
	struct tramp_header *ret;
	struct tramp_pg *page;

	if (!cheri_gettag(data) || !cheri_getsealed(data) ||
	    cheri_gettype(data) != CHERI_OTYPE_SENTRY ||
	    (cheri_getperm(data) & CHERI_PERM_LOAD) == 0 ||
	    (cheri_getperm(data) & CHERI_PERM_EXECUTE) == 0
#ifdef HAS_RESTRICTED_MODE
	    || (cheri_getperm(data) & CHERI_PERM_EXECUTIVE) == 0
#endif
	    )
		return (NULL);

#ifdef USE_RESTRICTED_MODE
	data = (const char *)data - 1;
#elif !defined(HAS_RESTRICTED_MODE)
	data = cheri_unseal(data, 0);
#endif
	data = __containerof(data, struct tramp_header, entry);

	TAILQ_FOREACH(obj, &obj_list, next) {
		for (page = atomic_load_explicit(&obj->tramp_pgs,
		    memory_order_acquire);
		    page != NULL; page = SLIST_NEXT(page, link)) {
			ret = cheri_buildcap(page, (uintptr_t)data);
			if (!cheri_gettag(ret))
				continue;
			if (cheri_can_access(ret, CHERI_PERM_LOAD,
			    (ptraddr_t)&ret->defobj, sizeof(ret->defobj)) &&
			    cheri_gettag(ret->defobj))
				/*
				 * At this point, the provided data must have
				 * been (a) tagged and (b) pointing to the entry
				 * point of a trampoline.
				 */
				return (ret);
			else {
				rtld_fdprintf(STDERR_FILENO,
				    "c18n: Cannot reflect trampoline %#p\n",
				    ret);
				break;
			}
		}
	}

	return (NULL);
}

ptraddr_t _rtld_tramp_reflect(const void *);

ptraddr_t
_rtld_tramp_reflect(const void *addr)
{
	struct tramp_header *header;

	if (!C18N_ENABLED)
		return (0);

	header = tramp_reflect(addr);
	if (header == NULL)
		return (0);

	return ((ptraddr_t)header->target);
}

/*
 * APIs
 */
bool _rtld_c18n_is_enabled(void);

bool
_rtld_c18n_is_enabled(void)
{
	return (C18N_ENABLED);
}

void
c18n_init(Obj_Entry *obj_rtld, Elf_Auxinfo *aux_info[])
{
	extern const char c18n_default_policy[];
	extern const size_t c18n_default_policy_size;

	int fd;
	char *file;
	struct stat st;

	/*
	 * Create memory mapping for compartmentalisation statistics.
	 */
	if (ld_compartment_stats == NULL)
		fd = -1;
	else {
		fd = open(ld_compartment_stats, O_RDWR | O_TRUNC | O_CREAT,
		    0666);
		if (fd == -1)
			rtld_fatal("c18n: Cannot open file (%s)",
			    rtld_strerror(errno));
		if (ftruncate(fd, sizeof(*c18n_stats)) == -1)
			rtld_fatal("c18n: Cannot truncate file (%s)",
			    rtld_strerror(errno));
	}

	c18n_stats = mmap(NULL, sizeof(*c18n_stats), PROT_READ | PROT_WRITE,
	    fd == -1 ? MAP_ANON : MAP_SHARED, fd, 0);
	if (c18n_stats == MAP_FAILED)
		rtld_fatal("c18n: Cannot mmap file (%s)", rtld_strerror(errno));
	atomic_store_explicit(&c18n_stats->version, RTLD_C18N_STATS_VERSION,
	    memory_order_release);

	if (aux_info[AT_CHERI_C18N] != NULL) {
		c18n_info = aux_info[AT_CHERI_C18N]->a_un.a_ptr;
		*c18n_info = (struct cheri_c18n_info) {
			.stats_size = sizeof(*c18n_stats),
			.stats = c18n_stats,
			.comparts_entry_size = sizeof(*comparts.data)
		};
		atomic_store_explicit(&c18n_info->version,
		    CHERI_C18N_INFO_VERSION, memory_order_release);
	}

	/*
	 * Initialise compartment table, add the RTLD compartment, load the
	 * default policy, and load the user-supplied policy.
	 */
	expand_comparts_data(8);

	string_base_push(&add_comparts_data("[RTLD]")->libs, obj_rtld->path);

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
}

/*
 * Trampoline pages should be large to minimise pressure on the TLB, but not too
 * large. 4MB is a reasonable threshold.
 */
#define	MAX_TRAMP_PG_SIZE		(4 * 1024 * 1024)

void
c18n_init2(void)
{
	struct tcb_wrapper *wrap;
#ifndef CHERI_LIB_C18N_NO_OTYPE
	uintptr_t sealer;

	/*
	 * Allocate otypes for RTLD use
	 */
	if (sysctlbyname("security.cheri.sealcap", &sealer,
	    &(size_t) { sizeof(sealer) }, NULL, 0) < 0)
		rtld_fatal("sysctlbyname failed");

	sealer_pltgot = cheri_setboundsexact(sealer, 1);
	sealer += 1;

	sealer_tcb = cheri_setboundsexact(sealer, 1);
	sealer += 1;

	sealer_trusted_stk = cheri_setboundsexact(sealer, 1);
	sealer += 1;

#ifndef HAS_RESTRICTED_MODE
	sealer_tidc = cheri_setboundsexact(sealer, 1);
	sealer += 1;
#endif
#else
#ifndef HAS_RESTRICTED_MODE
	sealer_tidc = init_tidc_table(MAX_THREADS);
#endif
#endif

	/*
	 * All libraries have been loaded. Create and initialise a stack lookup
	 * table with the same size as the number of compartments.
	 */
	wrap = c18n_malloc(sizeof(*wrap));
	*wrap = (struct tcb_wrapper) {
#if !defined(HAS_RESTRICTED_MODE) && defined(CHERI_LIB_C18N_NO_OTYPE)
		.tidc = allocate_tidc()
#endif
	};
	init_stk_table(expand_stk_table(NULL, comparts.size), wrap);

	/*
	 * Create a trampoline table with 2^9 = 512 entries.
	 */
	expand_tramp_table(9);

	/*
	 * Find a suitable page size and create the first trampoline page.
	 */
	for (int n = npagesizes - 1; n >= 0; --n) {
		if (pagesizes[n] <= MAX_TRAMP_PG_SIZE) {
			tramp_pg_size = pagesizes[n];
			break;
		}
	}
	assert(tramp_pg_size > 0);
}

void
c18n_release_obj(Obj_Entry *obj)
{
	RtldLockState lockstate;
	size_t len;
	struct tramp_pg *pg, *next_pg;
	const struct tramp_header *header;

	wlock_acquire(rtld_tramp_lock, &lockstate);

	/*
	 * Remove trampolines pointing to the object from the hash-table.
	 */
	header = atomic_load_explicit(&obj->tramps, memory_order_relaxed);
	while (header != NULL) {
		tramp_table.data[header->index] = NULL;
		tramp_table.dead += 1;
		header = header->next;
	}

	/*
	 * Iterate through the linked-list of all trampoline pages and unmap
	 * them. This must be done under a mutex so that no trampoline page is
	 * being concurrently inserted.
	 */
	pg = atomic_load_explicit(&obj->tramp_pgs, memory_order_relaxed);
	while (pg != NULL) {
		next_pg = SLIST_NEXT(pg, link);
		len = offsetof(typeof(*pg), trampolines) + pg->capacity;
		if (munmap(pg, len) != 0) {
			rtld_fdprintf(STDERR_FILENO,
			    "c18n: munmap(%#p, %zu) = %s\n",
			    pg, len, rtld_strerror(errno));
			abort();
		}
		pg = next_pg;
	}

	lock_release(rtld_tramp_lock, &lockstate);

	/*
	 * Iterate through the stack lookup table of all threads and remove and
	 * unmap the untrusted stacks associated with the object.
	 */

	/*
	 * Remove compartments associated with the object from the compartment
	 * table and recycle their compartment IDs.
	 */
}

/*
 * libthr support
 */
static void (*thr_thread_start)(struct pthread *);

void _rtld_thread_start_init(void (*)(struct pthread *));
void _rtld_thread_start(struct pthread *);
void _rtld_thr_exit(long *);

void
_rtld_thread_start_init(void (*p)(struct pthread *))
{
	if (!C18N_ENABLED)
		return;

#ifdef USE_RESTRICTED_MODE
	assert((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) != 0);
#endif
	assert(thr_thread_start == NULL);
	thr_thread_start = p;
}

void
_rtld_thread_start(struct pthread *curthread)
{
	struct tcb *tcb;
	struct stk_table *table;
	struct tcb_wrapper *wrap;

	/*
	 * The thread pointer register contains the fake tcb upon entering the
	 * new thread. Extract and install the actual tcb and stack lookup
	 * table.
	 */
	tcb = get_trusted_tp();
#ifdef __riscv
	/*
	 * The TCB is shifted by the kernel on RISC-V. See `cpu_set_user_tls`.
	 */
	tcb -= 1;
#endif
	wrap = __containerof(tcb, struct tcb_wrapper, header);

	tcb = c18n_unseal(wrap->tcb, sealer_tcb);
	*tcb = wrap->header;
	_tcb_set(tcb);

	table = c18n_unseal(wrap->table, sealer_tcb);
	init_stk_table(table, wrap);

	thr_thread_start(curthread);
}

static bool
identify_untrusted_stk(void *canonical, void *untrusted)
{
	canonical = cheri_clearperm(canonical, CHERI_PERM_SW_VMEM);
	return (cheri_is_subset(untrusted, canonical));
}

void
_rtld_thr_exit(long *state)
{
	size_t i;
	sigset_t nset;
#ifndef USE_RESTRICTED_MODE
	stack_t osigstk;
#endif
	struct stk_table_stk_info *data;
	struct stk_table *table = get_stk_table();

	/*
	 * Block all signals before destroying thread-specific data structures.
	 */
	SIGFILLSET(nset);
	sigprocmask(SIG_SETMASK, &nset, NULL);

	/*
	 * Uninstall the trusted stack and the stack lookup table.
	 */
	set_stk_table(NULL);
	set_trusted_stk(NULL);

#ifndef HAS_RESTRICTED_MODE
	/*
	 * Uninstall the tidc buffer.
	 */
	if (sysarch(RISCV_SET_UTIDC, &(void *) { NULL }) != 0) {
		rtld_fdprintf(STDERR_FILENO, "c18n: Cannot clear tidc\n");
		abort();
	}
#endif

	/*
	 * Clear RTLD's stack lookup table entry.
	 */
	i = RTLD_COMPART_ID;
	table->meta->compart_stk[i] = (struct stk_table_stk_info) {};
	table->entries[i] = (struct stk_table_entry) {
		.stack = create_untrusted_stk,
	};

	/*
	 * Unmap each compartment's stack.
	 */
	for (i = i + 1; i < table->meta->capacity; ++i) {
		data = &table->meta->compart_stk[i];
		if (data->size == 0)
			continue;
		if (!identify_untrusted_stk(
		    data->begin, table->entries[i].stack)) {
			rtld_fdprintf(STDERR_FILENO,
			    "c18n: Untrusted stack %#p of %s is not derived "
			    "from %#p\n", table->entries[i].stack,
			    comparts.data[i].name, data->begin);
			abort();
		}
		if (munmap(data->begin, data->size) != 0) {
			rtld_fdprintf(STDERR_FILENO,
			    "c18n: munmap(%#p, %zu) failed\n",
			    data->begin, data->size);
			abort();
		}
		*data = (struct stk_table_stk_info) {};
		table->entries[i] = (struct stk_table_entry) {
			.stack = create_untrusted_stk,
		};
	}

	/*
	 * Unmap the trusted stack.
	 */
	data = &table->meta->trusted_stk;
	if (munmap(data->begin, data->size) != 0) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: munmap(%#p, %zu) failed\n",
		    data->begin, data->size);
		abort();
	}
	*data = (struct stk_table_stk_info) {};

#ifndef USE_RESTRICTED_MODE
	/*
	 * Deregister and unmap the signal stack.
	 */
	if (__sys_sigaltstack(
	    &(stack_t) { .ss_flags = SS_DISABLE }, &osigstk) != 0) {
		rtld_fdprintf(STDERR_FILENO, "c18n: sigaltstack failed\n");
		abort();
	}
	data = &table->meta->sig_stk;
	assert(osigstk.ss_sp == data->begin &&
	    osigstk.ss_size == data->size &&
	    osigstk.ss_flags == 0);
	if (munmap(data->begin, data->size) != 0) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: munmap(%#p, %zu) failed\n",
		    data->begin, data->size);
		abort();
	}
	*data = (struct stk_table_stk_info) {};
#endif

	/*
	 * Push the stack lookup table for garbage collection.
	 */
	push_stk_table(&dead_stk_tables, table);

	__sys_thr_exit(state);
}

/*
 * Signal support
 */
static struct sigaction sigactions[_SIG_MAXSIG];

void _rtld_sighandler_init(__siginfohandler_t *);
void _rtld_sighandler(int, siginfo_t *, void *);
void _rtld_siginvoke(int, siginfo_t *, ucontext_t *, const struct sigaction *);
int _rtld_sigaction(int, const struct sigaction *, struct sigaction *);

static void
sigdispatch(int sig, siginfo_t *info, void *_ucp)
{
	RtldLockState lockstate;
	ucontext_t *ucp = _ucp;
	struct sigaction act;

	rlock_acquire(rtld_sigaction_lock, &lockstate);
	act = sigactions[sig - 1];
	lock_release(rtld_sigaction_lock, &lockstate);

	/*
	 * Compute the signals to be blocked for the duration of the signal
	 * handler.
	 */
	SIGSETOR(act.sa_mask, ucp->uc_sigmask);
	if ((act.sa_flags & SA_NODEFER) == 0)
		SIGADDSET(act.sa_mask, sig);

	_rtld_siginvoke(sig, info, ucp, &act);
}

static __siginfohandler_t *signal_dispatcher = sigdispatch;

void
_rtld_sighandler_init(__siginfohandler_t *handler)
{
	if (!C18N_ENABLED)
		return;

#ifdef USE_RESTRICTED_MODE
	assert((cheri_getperm(handler) & CHERI_PERM_EXECUTIVE) != 0);
#endif
	assert(signal_dispatcher == sigdispatch);
	signal_dispatcher = handler;
}

#ifdef USE_RESTRICTED_MODE
void _rtld_sighandler_impl(int, siginfo_t *, ucontext_t *);

void
_rtld_sighandler_impl(int sig, siginfo_t *info, ucontext_t *ucp)
#else
void _rtld_sighandler_impl(int, siginfo_t *, ucontext_t *, struct sigframe *);

void
_rtld_sighandler_impl(int sig, siginfo_t *info, ucontext_t *ucp,
    struct sigframe *sf)
#endif
{
	struct stk_table *table;
	struct trusted_frame *tf;
	stk_table_index intr_idx;
	compart_id_t intr;

#ifdef USE_RESTRICTED_MODE
	uintptr_t csp;
#endif
	void *nsp;
	void *osp;
	struct trusted_frame *ntf;
	uintptr_t *table_reg;

#ifndef USE_RESTRICTED_MODE
	/*
	 * Move the sigframe to RTLD's stack.
	 */
	*sf = (struct sigframe) {
		.sf_si = *info,
		.sf_uc = *ucp
	};

	/*
	 * Zero the sigframe on the interrupted compartment's stack.
	 */
	memset(info, 0, sizeof(*info));
	memset(ucp, 0, sizeof(*ucp));

	info = &sf->sf_si;
	ucp = &sf->sf_uc;
#endif

	/*
	 * We cannot make compartment transitions yet because the interrupt may
	 * have happened during the middle of a compartment transition, when
	 * data structures are not consistent.
	 *
	 * First, get the untrusted stack when the interrupt happened and figure
	 * out which compartment it belongs to.
	 */
	table = get_stk_table();
#ifdef USE_RESTRICTED_MODE
	/*
	 * When using Restricted mode, the untrusted stack can only be obtained
	 * by directly reading the register, which must then be set to RTLD's
	 * untrusted stack to simulate a transition to RTLD's compartment.
	 */
	nsp = get_untrusted_stk();
	set_untrusted_stk(table->entries[RTLD_COMPART_ID].stack);
	csp = ucp->uc_mcontext.mc_capregs.cap_sp;
	ucp->uc_mcontext.mc_capregs.cap_sp = (uintptr_t)nsp;
#elif defined(__aarch64__)
	nsp = (void *)ucp->uc_mcontext.mc_capregs.cap_sp;
#elif defined(__riscv)
	nsp = (void *)ucp->uc_mcontext.mc_capregs.cp_csp;
#endif

	tf = get_trusted_stk();
	/*
	 * Usually, nsp is actually the interrupted compartment's stack top.
	 */
	intr_idx = tf->callee;
	intr = index_to_cid(intr_idx);
	if (intr < table->meta->capacity &&
	    table->meta->compart_stk[intr].size > 0 &&
	    identify_untrusted_stk(table->meta->compart_stk[intr].begin, nsp))
		goto found;
	/*
	 * If the interrupt occured at a point in the trampoline while a
	 * tail-call is taking place, where the callee has been updated but the
	 * callee's stack has not been installed yet, nsp would refer to the
	 * stack top of the compartment identified as the caller in a partially
	 * constructed frame above the topmost frame.
	 */
	intr_idx = tf[-1].caller;
	intr = index_to_cid(intr_idx);
	if (intr < table->meta->capacity &&
	    table->meta->compart_stk[intr].size > 0 &&
	    identify_untrusted_stk(table->meta->compart_stk[intr].begin, nsp))
		goto found_trusted;
	/*
	 * If the interrupt occurred at a point in the trampoline where a new
	 * frame has been pushed but the callee's stack has not been installed
	 * yet, nsp would refer to the stack top of the caller of the
	 * interrupted compartment.
	 *
	 * Or, if the interrupt occurred at a point in the return path of a
	 * trampoline where the caller's stack is installed but the topmost
	 * frame has not been popped yet, nsp would refer to the caller's stack.
	 *
	 * Or, if the interrupt occurred at a point in the trampoline where
	 * stack resolution is taking place, nsp would remain the caller's stack
	 * top.
	 */
	intr_idx = tf->caller;
	intr = index_to_cid(intr_idx);
	if (identify_untrusted_stk(table->meta->compart_stk[intr].begin, nsp))
		goto found_trusted;
	/*
	 * Lazy binding, thread-local storage, and stack resolution all involve
	 * switching to RTLD's stack. In this case, nsp would refer to RTLD's
	 * stack top.
	 */
	intr_idx = cid_to_index(RTLD_COMPART_ID);
	intr = RTLD_COMPART_ID;
	if (identify_untrusted_stk(table->meta->compart_stk[intr].begin, nsp))
		goto found_trusted;
	rtld_fdprintf(STDERR_FILENO,
	    "c18n: Cannot resolve inconsistent untrusted stack %#p. "
	    "Please file a bug report!\n", nsp);
	abort();
found_trusted:
#ifdef USE_RESTRICTED_MODE
	/*
	 * The untrusted stack can only become temporarily inconsistent when
	 * running code in Executive mode. This performs a quick sanity check.
	 */
	if ((cheri_getperm(ucp->uc_mcontext.mc_capregs.cap_elr) &
	    CHERI_PERM_EXECUTIVE) == 0) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: Cannot resolve inconsistent untrusted stack %#p in "
		    "Restricted Mode. Please file a bug report!\n", nsp);
		abort();
	}
#endif
found:

	/*
	 * Emulate a compartment transition from the interrupted compartment to
	 * RTLD.
	 *
	 * Update the stack lookup table with the interrupted compartment's
	 * current stack top and get its old stack top.
	 */
	osp = table->entries[intr].stack;
	table->entries[intr].stack = nsp;

	/*
	 * Push a dummy frame onto the trusted stack that would restore the
	 * interrupted compartment's stack top during an unwind.
	 *
	 * Skip over a frame because the interrupted code might be constructing
	 * a frame.
	 */
	ntf = tf - 2;
	*ntf = (struct trusted_frame) {
		.state = (struct dl_c18n_compart_state) {
			.sp = nsp
		},
		.osp = osp,
		.previous = tf,
		.caller = intr_idx,
		/*
		 * This field is used by the next trampoline to determine the
		 * current compartment.
		 */
		.callee = cid_to_index(RTLD_COMPART_ID)
	};
	set_trusted_stk(ntf);

	/*
	 * If the interrupted code has loaded the stack lookup table, it would
	 * be located in register STACK_TABLE_N. Check if this is the case.
	 */
#ifdef __aarch64__
	table_reg = &ucp->uc_mcontext.mc_capregs.cap_x[STACK_TABLE_N];
#elif defined(__riscv)
	table_reg = &ucp->uc_mcontext.mc_capregs.cp_ct[STACK_TABLE_N];
#endif
	if (!cheri_equal_exact(table, *table_reg))
		table_reg = NULL;

	signal_dispatcher(sig, info, ucp);

	/*
	 * Check whether the table is still there.
	 */
	if (table_reg != NULL && !cheri_equal_exact(table, *table_reg))
		table_reg = NULL;

	/*
	 * The stack lookup table may have been expanded after the signal
	 * dispatcher returns. This would happen if new libraries have been
	 * loaded previously and the signal handler calls into one of them.
	 */
	table = get_stk_table();

	/*
	 * Update the register containing the stack lookup table if needed.
	 */
	if (table_reg != NULL)
		*table_reg = (uintptr_t)table;

	/*
	 * Emulate a compartment return from RTLD to the interrupted
	 * compartment. Pop the dummy frame from the trusted stack.
	 */
	assert(get_trusted_stk() == ntf);
	table->entries[index_to_cid(ntf->caller)].stack = ntf->osp;
	set_trusted_stk(ntf->previous);
#ifdef USE_RESTRICTED_MODE
	/*
	 * When using Restricted mode, manually set the untrusted stack because
	 * the kernel does not do that.
	 */
	set_untrusted_stk((void *)ucp->uc_mcontext.mc_capregs.cap_sp);
	ucp->uc_mcontext.mc_capregs.cap_sp = csp;
#endif
}

void
_rtld_siginvoke(int sig, siginfo_t *info, ucontext_t *ucp,
    const struct sigaction *act)
{
	bool siginfo;
	void *sigfunc;
	RtldLockState lockstate;
	struct tramp_header *header;
	compart_id_t callee;
	stk_table_index callee_idx;
	struct stk_table *table;
	struct sigframe *osp, *nsp;
	struct trusted_frame *tf, *ntf;
	sigset_t oset;

	siginfo = (act->sa_flags & SA_SIGINFO) != 0;
	if (siginfo)
		sigfunc = act->sa_sigaction;
	else
		sigfunc = act->sa_handler;

	/*
	 * Acquire a lock between reflecting the trampoline and getting its
	 * compartment's stack to ensure that the compartment is not destroyed
	 * concurrently.
	 */
	rlock_acquire(rtld_tramp_lock, &lockstate);

	header = tramp_reflect(sigfunc);

	/*
	 * The signal handler must be wrapped by a trampoline if function
	 * pointer wrapping is enabled.
	 */
	if (header == NULL) {
		rtld_fdprintf(STDERR_FILENO,
		    "c18n: Invalid handler %#p for signal %d\n",
		    sigfunc, sig);
		abort();
	}

	/*
	 * If the signal handler is not already wrapped by a trampoline, wrap it
	 * in one.
	 */
	callee = compart_id_for_address(header->defobj,
	    (ptraddr_t)header->target);
	callee_idx = cid_to_index(callee);

	/*
	 * Get the stack of the signal handler's compartment.
	 */
	table = get_stk_table();
	osp = get_or_create_untrusted_stk(callee, &table);

	lock_release(rtld_tramp_lock, &lockstate);

	nsp = osp - 1;
	*nsp = (struct sigframe) {
		.sf_si = *info,
		.sf_uc = *ucp
	};
	table->entries[callee].stack = nsp;

	/*
	 * Push a dummy frame onto the trusted stack that would restore the
	 * stack top of the signal handler's compartment during an unwind.
	 */
	tf = get_trusted_stk();
	ntf = tf - 1;
	*ntf = (struct trusted_frame) {
		.osp = osp,
		.previous = tf,
		.caller = callee_idx,
		/*
		 * This field is used by the next trampoline to determine the
		 * current compartment.
		 */
		.callee = cid_to_index(RTLD_COMPART_ID)
	};
	set_trusted_stk(ntf);

	/*
	 * Restore the user-supplied signal mask before invoking the handler.
	 */
	sigprocmask(SIG_SETMASK, &act->sa_mask, &oset);

	if (siginfo)
		((__siginfohandler_t *)sigfunc)(sig, &nsp->sf_si, &nsp->sf_uc);
	else
		((__sighandler_t *)sigfunc)(sig);

	/*
	 * Restore the signal mask of RTLD's signal handler.
	 */
	sigprocmask(SIG_SETMASK, &oset, NULL);

	/*
	 * Copy the modified user context back to the original one.
	 * XXX DG: Need to sanitise the modified user context.
	 */
	*ucp = nsp->sf_uc;

	/*
	 * The stack lookup table may have been expanded after the signal
	 * dispatcher returns. This would happen if new libraries have been
	 * loaded previously and the signal handler calls into one of them.
	 */
	table = get_stk_table();

	/*
	 * Pop the dummy frame from the trusted stack.
	 */
	assert(get_trusted_stk() == ntf);
	table->entries[index_to_cid(ntf->caller)].stack = ntf->osp;
	set_trusted_stk(ntf->previous);
}

int
_rtld_sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
	RtldLockState lockstate;
	struct sigaction act2, oact2, nact, *slot;
	const struct sigaction *nactp = act;
	sigset_t nset, oset;
	int ret;

	if (act != NULL) {
		act2 = *act;
		if (act2.sa_handler != SIG_DFL && act2.sa_handler != SIG_IGN) {
			nact = act2;
			nactp = &nact;

			nact.sa_sigaction = _rtld_sighandler;
			/* Always use the sigaltstack. */
			nact.sa_flags |= SA_ONSTACK;
			nact.sa_flags &= ~SA_NODEFER;
			nact.sa_flags |= SA_SIGINFO;
			SIGFILLSET(nact.sa_mask);
		}
	}

	/*
	 * Make the function re-entrant by blocking all signals. Lock to protect
	 * the sigaction table.
	 */
	SIGFILLSET(nset);
	sigprocmask(SIG_SETMASK, &nset, &oset);
	wlock_acquire(rtld_sigaction_lock, &lockstate);

	ret = __sys_sigaction(sig, nactp, &oact2);

	if (ret == 0) {
		slot = &sigactions[sig - 1];
		if (oact != NULL) {
			if (oact2.sa_handler == SIG_DFL ||
			    oact2.sa_handler == SIG_IGN)
				*oact = oact2;
			else
				*oact = *slot;
		}
		if (act != NULL)
			*slot = act2;
	}

	lock_release(rtld_sigaction_lock, &lockstate);
	sigprocmask(SIG_SETMASK, &oset, NULL);

	return (ret);
}
