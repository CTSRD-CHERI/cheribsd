/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
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
	IMPORT(clear_args);
	IMPORT(invoke);
	IMPORT(pop_frame);

	size_t size = 0;
	char *buf = *entry;
	size_t sealer_off, target_off, pcc_off, landing_off, unused_regs;

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

#define	PATCH_I_TYPE(tramp, name, value)				\
	do {								\
		uint32_t _value = (value);				\
		_value = ((_value & 0xfff) << 20);			\
		*PATCH_INS(PATCH_OFF(tramp, name)) |= _value;		\
	} while (0)

#define	PATCH_LANDING(landing_off, value)				\
	do {								\
		uint32_t _value = (value);				\
		_value = ((_value & 0xfff) << 20);			\
		*PATCH_INS(landing_off) |= _value;			\
	} while (0)

#define	PATCH_CClear(tramp, name, value)				\
	do {								\
		uint32_t _value = (value);				\
		_value = ((_value & 0x1f) << 7) |			\
		    ((_value & 0xe0) << 10);				\
		*PATCH_INS(PATCH_OFF(tramp, name)) |= _value;		\
	} while (0)

	sealer_off = COPY_VALUE(sealer_tidc);

	*(struct tramp_header *)(buf + size) = (struct tramp_header) {
		.target = data->target,
		.defobj = data->defobj,
		.symnum = data->def == NULL ?
		    0 : data->def - data->defobj->symtab,
		.sig = data->sig
	};
	target_off = size + offsetof(struct tramp_header, target);
	*entry = buf + size;
	size += offsetof(struct tramp_header, entry);

	COPY(push_frame);
	pcc_off = PATCH_OFF(push_frame, pcc);
	PATCH_I_TYPE(push_frame, unsealer, sealer_off - pcc_off);
	PATCH_I_TYPE(push_frame, cid,
	    cid_to_index(data->defobj->compart_id).val);
	PATCH_I_TYPE(push_frame, target, target_off - pcc_off);
	landing_off = PATCH_OFF(push_frame, landing);
	/*
	 * The number of return value registers is encoded as follows:
	 * - TWO:	0b00
	 * - ONE:	0b01
	 * - NONE:	0b10
	 * - INDIRECT:	0b11
	 */
	PATCH_I_TYPE(push_frame, n_rets,
	    data->sig.valid ? data->sig.ret_args : 0);

	if (ld_compartment_unwind != NULL)
		COPY(update_fp);
	else
		COPY(update_fp_untagged);

	if (data->sig.valid) {
		/* Each instruction here is 2 bytes long. */
		unused_regs = (8 - data->sig.reg_args) *
		    sizeof(*tramp_clear_args) / 2;
		memcpy(buf + size, tramp_clear_args, unused_regs);
		size += unused_regs;
	}
	COPY(invoke);
	PATCH_LANDING(landing_off, size - pcc_off);

	COPY(pop_frame);
	pcc_off = PATCH_OFF(pop_frame, pcc);
	PATCH_I_TYPE(pop_frame, unsealer, sealer_off - pcc_off);

	return (size);
}
