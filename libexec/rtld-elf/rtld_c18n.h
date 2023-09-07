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

/*
 * Global symbols
 */
extern uintptr_t sealer_pltgot, sealer_jmpbuf, sealer_tramp;
extern const char *ld_utrace_compartment;
extern const char *ld_compartment_enable;
extern const char *ld_compartment_overhead;

void ld_utrace_log(int, void *, void *, size_t, int, const char *, const char *);

/*
 * Policies
 */
typedef uint16_t compart_id_t;

struct compart {
	/*
	 * Name of the compartment
	 */
	const char *name;
	/*
	 * List of compartment's per-thread stacks
	 */
	struct Struct_Stack_Entry *_Atomic stacks;
	/*
	 * NULL-terminated array of libraries that belong to the compartment
	 */
	const char **libraries;
	/*
	 * NULL-terminated array of symbols governed by the compartment's policy
	 */
	const char **symbols;
	bool trust : 1;
	bool negative : 1;
};

struct policy {
	struct compart *coms;
	size_t count;
};

compart_id_t compart_id_allocate(const char *);

/*
 * Stack switching
 */
#define DEFAULT_STACK_TABLE_SIZE 2

typedef void **tramp_stk_table_t;

struct Struct_Stack_Entry {
    SLIST_ENTRY(Struct_Stack_Entry) link;
    void *stack;
};

void _rtld_get_rstk(void);

/*
 * Trampolines
 */
typedef const void *tramp;
typedef uint8_t tramp_sig_int;

struct tramp_sig {
	enum tramp_ret_args: unsigned char {
		C0_AND_C1,
		C0,
		NONE,
		INDIRECT
	} ret_args : 2;
	bool mem_args : 1;
	unsigned char reg_args : 4;
	bool valid : 1;
};

struct tramp_data {
	void *target;
	const Obj_Entry *defobj;
	const Elf_Sym *def;
	tramp *entry;
	struct tramp_sig sig;
};
_Static_assert(sizeof(struct tramp_sig) == sizeof(tramp_sig_int),
    "Unexpected tramp_sig size");

void *tramp_intern(const Obj_Entry *reqobj, const struct tramp_data *);
struct tramp_sig tramp_fetch_sig(const Obj_Entry *, unsigned long);

/*
 * APIs
 */
/*
void *_rtld_sandbox_code(void *, struct tramp_sig);
void *_rtld_safebox_code(void *, struct tramp_sig);
*/

void tramp_init(void);
void tramp_add_comparts(struct policy *);

/*
 * libc support
 */
void *_rtld_setjmp_impl(void **restrict, void **restrict);
#endif
