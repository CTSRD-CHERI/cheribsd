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

#include <sys/param.h>
#include <sys/mman.h>

#include <cheri/c18n.h>

#include <stdlib.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_c18n.h"
#include "rtld_libc.h"
#include "rtld_utrace.h"

/*
 * Trampolines
 */
size_t
tramp_compile(char **entry, const struct tramp_data *data)
{
#define IMPORT(template)				\
	extern const uint32_t tramp_##template[];	\
	extern const size_t size_tramp_##template

	IMPORT(push_frame);
	IMPORT(update_fp);
	IMPORT(update_fp_untagged);
	IMPORT(count_entry);
	IMPORT(call_hook);
	IMPORT(invoke_exe);
	IMPORT(clear_mem_args);
	IMPORT(clear_ret_args_indirect);
	IMPORT(clear_ret_args);
	IMPORT(invoke_res);
	IMPORT(count_return);
	IMPORT(pop_frame);

	size_t size = 0;
	char *buf = *entry;
	size_t hook_off, count_off;
	size_t header_off, target_off, landing_off, unused_regs;
	bool executive = cheri_getperm(data->target) & CHERI_PERM_EXECUTIVE;
	bool count = ld_compartment_switch_count != NULL;
	bool hook = ld_compartment_utrace != NULL ||
	    ld_compartment_overhead != NULL;

#define	COPY_VALUE(val)	({				\
	size_t _old_size = size;			\
	*(typeof(val) *)(buf + size) = val;		\
	size += sizeof(val);				\
	_old_size;					\
})

#define	COPY(template)					\
	do {						\
		memcpy(buf + size, tramp_##template,	\
		    size_tramp_##template);		\
		size += size_tramp_##template;		\
	} while(0)

#define	PATCH_INS(offset)	((uint32_t *)(buf + (offset)))		\

#define	PATCH_OFF(tramp, name)	({					\
		extern const int32_t patch_tramp_##tramp##_##name;	\
		size + patch_tramp_##tramp##_##name;			\
	})

#define PATCH_MOV(tramp, name, value)					\
	do {								\
		uint32_t _value = (value);				\
		_value = ((_value & 0xffff) << 5);			\
		*PATCH_INS(PATCH_OFF(tramp, name)) |= _value;		\
	} while (0)

#define	PATCH_UBFM(tramp, name, value)					\
	do {								\
		uint32_t _value = (value);				\
		_value = ((_value & 0x3f) << 10);			\
		*PATCH_INS(PATCH_OFF(tramp, name)) |= _value;		\
	} while (0)

#define	PATCH_LDR_IMM(tramp, name, target)				\
	do {								\
		int32_t _offset = PATCH_OFF(tramp, name);		\
		int32_t _value = (target) - _offset;			\
		_value =						\
		    (roundup2(_value, sizeof(void *)) & 0x1ffff0) << 1;	\
		*PATCH_INS(_offset) |= _value;				\
	} while(0)

#define	PATCH_ADR(offset, target)					\
	do {								\
		int32_t _offset = (offset);				\
		int32_t _value = (target) - _offset;			\
		_value =						\
		    ((_value & 0x3) << 29) |				\
		    ((_value & 0x1ffffc) << 3);				\
		*PATCH_INS(_offset) |= _value;				\
	} while (0)

	if (hook)
		hook_off = COPY_VALUE(&tramp_hook);

	if (count)
		count_off = COPY_VALUE(&c18n_stats->rcs_switch);

	*(struct tramp_header *)(buf + size) = (struct tramp_header) {
		.target = data->target,
		.defobj = data->defobj,
		.symnum = data->def == NULL ?
		    0 : data->def - data->defobj->symtab,
		.sig = data->sig
	};
	header_off = size;
	target_off = size + offsetof(struct tramp_header, target);
	*entry = buf + size;
	size += offsetof(struct tramp_header, entry);

	COPY(push_frame);
	PATCH_MOV(push_frame, cid, cid_to_index(data->defobj->compart_id).val);
	landing_off = PATCH_OFF(push_frame, landing);
	/*
	 * The number of return value registers is encoded as follows:
	 * - TWO:	0b1111
	 * - ONE:	0b0111
	 * - NONE:	0b0011
	 * - INDIRECT:	0b0001
	 */
	PATCH_UBFM(push_frame, n_rets,
	    51 - (data->sig.valid ? data->sig.ret_args : 0));
	PATCH_LDR_IMM(push_frame, target, target_off);

	if (executive || ld_compartment_unwind != NULL)
		COPY(update_fp);
	else
		COPY(update_fp_untagged);

	if (count) {
		COPY(count_entry);
		PATCH_LDR_IMM(count_entry, counter, count_off);
	}

	if (hook) {
		COPY(call_hook);
		PATCH_LDR_IMM(call_hook, function, hook_off);
		PATCH_MOV(call_hook, event, UTRACE_COMPARTMENT_ENTER);
		PATCH_ADR(PATCH_OFF(call_hook, header), header_off);
	}

	if (executive)
		COPY(invoke_exe);
	else {
		if (data->sig.valid) {
			if (!data->sig.mem_args)
				COPY(clear_mem_args);

			if (data->sig.ret_args != INDIRECT)
				COPY(clear_ret_args_indirect);

			unused_regs = sizeof(*tramp_clear_ret_args) *
			    (8 - data->sig.reg_args);

			memcpy(buf + size, tramp_clear_ret_args, unused_regs);
			size += unused_regs;
		}
		COPY(invoke_res);
	}
	/*
	 * Add 1 to set the LSB of the landing address so that it matches the
	 * address generated by a branch-and-link instruction in C64 mode.
	 */
	PATCH_ADR(landing_off, size + 1);

	if (count)
		COPY(count_return);

	if (hook) {
		COPY(call_hook);
		PATCH_LDR_IMM(call_hook, function, hook_off);
		PATCH_MOV(call_hook, event, UTRACE_COMPARTMENT_LEAVE);
		PATCH_ADR(PATCH_OFF(call_hook, header), header_off);
	}

	COPY(pop_frame);

	return (size);
}
