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

#include <stdint.h>
#include "rtld_c18n_machdep.h"

/*
 * Global symbols
 */
extern uintptr_t sealer_pltgot, sealer_tramp;
extern const char *ld_compartment_utrace;
extern const char *ld_compartment_enable;
extern const char *ld_compartment_overhead;
extern const char *ld_compartment_sig;
extern const char *ld_compartment_unwind;

/*
 * Policies
 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
#define	C18N_RTLD_COMPART_ID	1
#else
#define	C18N_RTLD_COMPART_ID	0
#endif
#define	C18N_COMPARTMENT_ID_MAX	(UINT16_MAX >> 1)

typedef uint16_t compart_id_t;

struct compart {
	/*
	 * Name of the compartment
	 */
	const char *name;
	/*
	 * NULL-terminated array of libraries that belong to the compartment
	 */
	const char **libraries;
};

struct policy {
	struct compart *coms;
	size_t count;
};

void c18n_add_comparts(struct policy *);
compart_id_t compart_id_allocate(const char *);

/*
 * Stack switching
 */
struct stk_table {
	union {
		void *(*resolver)(unsigned);
		SLIST_ENTRY(stk_table) next;
	};
	size_t capacity;
	struct stk_table_stack {
		void *bottom;
		size_t size;
	} stacks[];
};

struct Struct_Stack_Entry {
    SLIST_ENTRY(Struct_Stack_Entry) link;
    void *stack;
};

void allocate_stk_table(void);

static inline unsigned
compart_id_to_index(compart_id_t cid)
{
	struct stk_table dummy;

	return (sizeof(*dummy.stacks) * cid / sizeof(dummy.stacks->bottom));
}

static inline struct stk_table *
stk_table_get(void)
{
	struct stk_table *table;

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	asm ("mrs	%0, rctpidr_el0" : "=C" (table));
#else
	asm ("mrs	%0, ctpidr_el0" : "=C" (table));
#endif
	return (table);
}

static inline void
stk_table_set(struct stk_table *table)
{
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	asm ("msr	rctpidr_el0, %0" :: "C" (table));
#else
	asm ("msr	ctpidr_el0, %0" :: "C" (table));
#endif
}

static inline void *
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
trusted_stk_get(void)
#else
untrusted_stk_get(void)
#endif
{
	void *sp;

	asm ("mrs	%0, rcsp_el0" : "=C" (sp));
	return (sp);
}

static inline void
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
trusted_stk_set(void *sp)
#else
untrusted_stk_set(void *sp)
#endif
{
	asm ("msr	rcsp_el0, %0" :: "C" (sp));
}

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
_Static_assert(sizeof(struct func_sig) == sizeof(func_sig_int),
    "Unexpected func_sig size");

struct tramp_data {
	void *target;
	const Obj_Entry *defobj;
	const Elf_Sym *def;
	struct func_sig sig;
};

struct tramp_header {
	void *target;
	const Obj_Entry *defobj;
	const Elf_Sym *def;
	uint32_t entry[];
};

void *tramp_hook(void *, int, void *, const Obj_Entry *, const Elf_Sym *,
    void *);
size_t tramp_compile(char **, const struct tramp_data *);
void *tramp_intern(const Obj_Entry *reqobj, const struct tramp_data *);

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

void c18n_init(void);
void *c18n_return_address(void);

#endif
