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

#ifndef RTLD_C18N_H
#define RTLD_C18N_H

#include <machine/c18n.h>

#include <stdint.h>

/*
 * Global symbols
 */
extern uintptr_t sealer_pltgot, sealer_tramp;
extern const char *ld_compartment_utrace;
extern const char *ld_compartment_policy;
extern const char *ld_compartment_overhead;
extern const char *ld_compartment_sig;
extern const char *ld_compartment_unwind;
extern const char *ld_compartment_stats;
extern const char *ld_compartment_switch_count;
extern struct rtld_c18n_stats *c18n_stats;

/*
 * Policies
 */
/*
 * RTLD is the first compartment.
 */
#define	RTLD_COMPART_ID		0

typedef uint16_t compart_id_t;
/*
 * Define another type for the stack table index to avoid confusion.
 */
typedef struct { uint16_t val; } stk_table_index;

compart_id_t compart_id_allocate(const char *, int);
compart_id_t compart_id_for_address(const Obj_Entry *, Elf_Addr);

/*
 * Stack switching
 */
struct stk_table_stk_info {
	size_t size;
	void *begin;
};

struct stk_table_metadata {
	size_t capacity;
	struct tcb_wrapper *wrap;
	/*
	 * This field and the next array record the base and length of the
	 * trusted stack and each compartment stack. This information is used to
	 * unmap the stacks when the thread exits.
	 */
	struct stk_table_stk_info trusted_stk;
	struct stk_table_stk_info compart_stk[];
};

struct stk_table {
	/*
	 * This field contains the stack resolver when the table is installed in
	 * a thread. When the thread exits and the table awaits to be garbage-
	 * collected, this field points to the next element of a linked list.
	 */
	union {
		void (*resolver)(void);
		SLIST_ENTRY(stk_table) next;
	};
	/*
	 * This field points to a structure containing metadata about the table.
	 * The metadata is not stored in-line so that the frequently-accessed
	 * items of the table are densely packed to reduce cache pressure.
	 */
	struct stk_table_metadata *meta;
	/*
	 * The i-th entry contains the current stack top of compartment i.
	 */
	struct stk_table_entry {
		void *stack;
		void *reserved;
	} entries[];
};

#define	cid_to_index_raw(cid)						\
	offsetof(struct stk_table, entries[cid].stack)

#define	cid_to_index(cid)	((stk_table_index) { cid_to_index_raw(cid) })

#define	index_to_cid(index)						\
	(((index).val -							\
	offsetof(struct stk_table, entries) -				\
	offsetof(struct stk_table_entry, stack)) /			\
	sizeof(struct stk_table_entry))

#define	COMPART_ID_MAX		index_to_cid((stk_table_index) { -1 })

#include "rtld_c18n_machdep.h"

struct trusted_frame {
	/*
	 * Architecture-specific callee-saved registers, including fp, sp, and
	 * the return address
	 */
	struct dl_c18n_compart_state state;
	/*
	 * INVARIANT: This field contains the top of the caller's stack when the
	 * caller was last entered.
	 */
	void *osp;
	/*
	 * Pointer to the previous trusted frame
	 */
	struct trusted_frame *previous;
	/*
	 * Stack table index of the caller, derived from its compartment ID
	 */
	stk_table_index caller;
	/*
	 * This padding space must be filled with zeros so that an optimised
	 * trampoline can use a wide load to load multiple fields of the trusted
	 * frame and then use a word-sized register to extract the caller field.
	 */
	uint16_t zeros;
	/*
	 * Stack table index of the callee, derived from its compartment ID
	 */
	stk_table_index callee;
	/*
	 * Number of return value registers with architecture-specific encoding
	 */
	uint16_t n_rets;
	/*
	 * This field contains the code address in the trampoline that the
	 * callee should return to. This is used by trampolines to detect cross-
	 * compartment tail-calls.
	 */
	ptraddr_t landing;
};

struct tcb *c18n_allocate_tcb(struct tcb *);
void c18n_free_tcb(void);

/*
 * Stack unwinding
 */
int c18n_is_tramp(uintptr_t, const struct trusted_frame *);

/*
 * Trampolines
 */
#define	DT_CHERI_C18N_SIG	0x60000100	/* function signature (c18n) */

#define	C18N_SIG_FORMAT_STRING	\
    "(valid = %d, reg_args = %d, mem_args = %d, ret_args = %d)"
#define	C18N_SIG_FORMAT(sig)	\
    (sig.valid), (sig.reg_args), (sig.mem_args), (sig.ret_args)

typedef uint8_t func_sig_int;

/* Must not be reordered */
enum tramp_ret_args {
	TWO,
	ONE,
	NONE,
	INDIRECT
};

struct func_sig {
	unsigned char ret_args : 2; /* enum tramp_ret_args */
	unsigned char mem_args : 1;
	unsigned char reg_args : 4;
	unsigned char valid : 1;
};

struct tramp_data {
	void *target;
	const Obj_Entry *defobj;
	const Elf_Sym *def;
	struct func_sig sig;
};

struct tramp_header {
	/*
	 * The target is atomic because it may be modified, after trampoline
	 * creation, from an untagged value to a tagged value. Atomicity ensures
	 * that the tagged value is visible to the trampoline when it is run.
	 */
	_Atomic(void *) target;
	const Obj_Entry *defobj;
	size_t symnum;
	struct func_sig sig;
	uint32_t entry[];
};

/*
 * Assembly function with non-standard ABI.
 */
void tramp_hook(void);

size_t tramp_compile(char **, const struct tramp_data *);

void *tramp_intern(const Plt_Entry *, compart_id_t, const struct tramp_data *);
struct tramp_header *tramp_reflect(const void *);
struct func_sig sigtab_get(const Obj_Entry *, unsigned long);

static inline long
func_sig_to_otype(struct func_sig sig)
{
	return (sig.ret_args | (sig.mem_args << 2) | (sig.reg_args << 3));
}

static inline bool
func_sig_legal(struct func_sig sig)
{
	return (!sig.valid || sig.reg_args <= 8);
}

/*
 * APIs
 */
void *_rtld_sandbox_code(void *, struct func_sig);
void *_rtld_safebox_code(void *, struct func_sig);

void c18n_init(Obj_Entry *, Elf_Auxinfo *[]);
void c18n_init2(Obj_Entry *);
#endif
