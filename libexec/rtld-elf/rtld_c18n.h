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
extern const char *ld_compartment_overhead;

uint16_t allocate_compart_id(void);
void ld_utrace_log(int, void *, void *, size_t, int, const char *, const char *);

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

struct tramp_data {
	void *target;
	const Obj_Entry *obj;
	const Elf_Sym *def;
	tramp *entry;
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
	} sig;
};
_Static_assert(sizeof(struct tramp_sig) == sizeof(tramp_sig_int),
    "Unexpected tramp_sig size");

void tramp_init(void);
void *tramp_intern(const struct tramp_data *);
void *_rtld_sandbox_code(void *, struct tramp_sig);
void *_rtld_safebox_code(void *, struct tramp_sig);
struct tramp_sig fetch_tramp_sig(const Obj_Entry *, unsigned long);

#endif
