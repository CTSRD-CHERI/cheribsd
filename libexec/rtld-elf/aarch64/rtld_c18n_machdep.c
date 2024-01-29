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
tramp_compile(void **entry, const struct tramp_data *data)
{
#define IMPORT(template)				\
	extern const uint32_t tramp_##template[];	\
	extern const size_t size_tramp_##template

	struct {
		void *target;
	} header;

	struct {
		const Obj_Entry *defobj;
		const Elf_Sym *def;
		void *function;
	} header_hook;

	IMPORT(save_caller);
	IMPORT(call_hook);
	IMPORT(switch_stack);
	IMPORT(invoke_exe);
	IMPORT(clear_mem_args);
	IMPORT(clear_ret_args_indirect);
	IMPORT(clear_ret_args);
	IMPORT(invoke_res);
	IMPORT(pop_frame);
	IMPORT(return);
	IMPORT(return_hook);

#undef	IMPORT

	uint32_t *buf = *entry;
	size_t size = 0;
	int to_clear;
	bool executive = cheri_getperm(data->target) & CHERI_PERM_EXECUTIVE;
	bool hook = ld_compartment_utrace != NULL ||
	    ld_compartment_overhead != NULL;

#define	COPY_DATA(s)					\
	do {						\
		buf = mempcpy(buf, &(s), sizeof(s));	\
		size += sizeof(s);			\
	} while (0)

#define	COPY(template)					\
	do {						\
		buf = mempcpy(buf, tramp_##template,	\
		    size_tramp_##template);		\
		size += size_tramp_##template;		\
	} while(0)

#define	PATCH_POINT(tramp, name) ({					\
		extern const int32_t patch_tramp_##tramp##_##name;	\
		&buf[patch_tramp_##tramp##_##name / sizeof(*buf)];	\
	})

#define PATCH_MOV(tramp, name, value)					\
	do {								\
		*PATCH_POINT(tramp, name) |= ((uint16_t)value) << 5;	\
	} while (0)

#define	PATCH_LDR_IMM(tramp, name, offset)				\
	do {								\
		extern const int32_t patch_tramp_##tramp##_##name;	\
		*PATCH_POINT(tramp, name) |= (roundup2(			\
		    sizeof(void *) * (offset) -				\
		    patch_tramp_##tramp##_##name - size,		\
		    sizeof(void *)) & 0x1ffff0) << 1;			\
	} while(0)

	header.target = data->target;
	COPY_DATA(header);

	if (hook) {
		header_hook.defobj = data->defobj;
		header_hook.def = data->def;
		header_hook.function = _rtld_tramp_hook;
		COPY_DATA(header_hook);
	}

	*entry = buf;

	COPY(save_caller);
	PATCH_LDR_IMM(save_caller, target, 0);
	if (data->sig.valid)
		PATCH_MOV(save_caller, ret_args, data->sig.ret_args);

	if (hook) {
		COPY(call_hook);
		PATCH_MOV(call_hook, event, UTRACE_COMPARTMENT_ENTER);
		PATCH_LDR_IMM(call_hook, target, 0);
		PATCH_LDR_IMM(call_hook, obj, 1);
		PATCH_LDR_IMM(call_hook, def, 2);
		PATCH_LDR_IMM(call_hook, function, 3);
	}

	if (!executive) {
		COPY(switch_stack);
		PATCH_MOV(switch_stack, cid,
		    compart_id_to_index(data->defobj->compart_id));
	}

	if (executive)
		COPY(invoke_exe);
	else {
		if (data->sig.valid) {
			if (!data->sig.mem_args)
				COPY(clear_mem_args);
			if (data->sig.ret_args != INDIRECT)
				COPY(clear_ret_args_indirect);
			to_clear = 8 - data->sig.reg_args;
			buf = mempcpy(buf, tramp_clear_ret_args,
			    sizeof(*tramp_clear_ret_args) * to_clear);
			size += sizeof(*tramp_clear_ret_args) * to_clear;
		}
		COPY(invoke_res);
	}

	COPY(pop_frame);

	if (hook) {
		COPY(return_hook);
		PATCH_MOV(return_hook, event, UTRACE_COMPARTMENT_LEAVE);
		PATCH_LDR_IMM(return_hook, obj, 1);
		PATCH_LDR_IMM(return_hook, def, 2);
		PATCH_LDR_IMM(return_hook, function, 3);
	} else
		COPY(return);

#undef	COPY
#undef	PATCH_POINT
#undef	PATCH_MOV
#undef	PATCH_LDR_IMM

	return (size);
}

/*
 * APIs
 */
void *
_rtld_safebox_code(void *target, struct func_sig sig)
{
	const Obj_Entry *obj;

	if (!func_sig_legal(sig)) {
		_rtld_error(
		    "_rtld_sandbox_code: Invalid signature "
		    C18N_SIG_FORMAT_STRING,
		    C18N_SIG_FORMAT(sig));
		return (NULL);
	}

	if ((cheri_getperm(target) & CHERI_PERM_EXECUTIVE) != 0)
		return (target);

	obj = obj_from_addr(target);
	if (obj == NULL) {
		_rtld_error(
		    "_rtld_sandbox_code: "
		    "%#p does not belong to any object", target);
		return (NULL);
	}

	if (sig.valid) {
		asm ("chkssu	%0, %0, %1"
		    : "+C" (target)
		    : "C" (obj->text_rodata_cap)
		    : "cc");
		target = cheri_seal(target,
		    sealer_tramp + func_sig_to_otype(sig));
	}

	return (target);
}

void *
_rtld_sandbox_code(void *target, struct func_sig sig)
{
	const Obj_Entry *obj;
	void *target_unsealed;

	if (!func_sig_legal(sig)) {
		_rtld_error(
		    "_rtld_sandbox_code: Invalid signature "
		    C18N_SIG_FORMAT_STRING,
		    C18N_SIG_FORMAT(sig));
		return (NULL);
	}

	if ((cheri_getperm(target) & CHERI_PERM_EXECUTIVE) != 0)
		return (target);

	obj = obj_from_addr(target);
	if (obj == NULL) {
		_rtld_error(
		    "_rtld_sandbox_code: "
		    "%#p does not belong to any object", target);
		return (NULL);
	}

	target_unsealed = cheri_unseal(target, sealer_tramp);
	if (cheri_gettag(target_unsealed)) {
		if (sig.valid && cheri_gettype(target) !=
		    (long)cheri_getbase(sealer_tramp) + func_sig_to_otype(sig))
			rtld_fatal("Signature mismatch");
		target = cheri_sealentry(target_unsealed);
	}

	target = tramp_intern(NULL, &(struct tramp_data) {
		.target = target,
		.defobj = obj,
		.sig = sig
	});

	return (target);
}
