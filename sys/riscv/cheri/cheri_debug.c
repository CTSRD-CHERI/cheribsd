/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011-2017 Robert N. M. Watson
 * All rights reserved.
 * Copyright (c) 2020 John Baldwin
 *
 * Portions of this software were developed by SRI International and
 * the University of Cambridge Computer Laboratory under DARPA/AFRL
 * contract (FA8750-10-C-0237) ("CTSRD"), as part of the DARPA CRASH
 * research programme.
 *
 * Portions of this software were developed by SRI International and
 * the University of Cambridge Computer Laboratory (Department of
 * Computer Science and Technology) under DARPA contract
 * HR0011-18-C-0016 ("ECATS"), as part of the DARPA SSITH research
 * programme.
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

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>

#include <ddb/ddb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

static inline void
db_print_cap(const char* msg, void * __capability cap)
{
	db_printf("%s" _CHERI_PRINTF_CAP_FMT "\n", msg,
	    _CHERI_PRINTF_CAP_ARG(cap));
}

static const char *scr_names[] = {
	[0] = "pcc",
	[1] = "ddc",
	[4] = "utcc",
	[5] = "utdc",
	[6] = "uscratchc",
	[7] = "uepcc",
	[12] = "stcc",
	[13] = "stdc",
	[14] = "sscratchc",
	[15] = "sepcc",
	[28] = "mtcc",
	[29] = "mtdc",
	[30] = "mscratchc",
	[31] = "mepcc"
};

/*
 * Show the special capability registers that aren't GPRs.
 */
DB_SHOW_COMMAND(scr, ddb_dump_scr)
{
	uint64_t sccsr;
	uint8_t cause, cap_idx;

	sccsr = csr_read(sccsr);
	cause = (sccsr & SCCSR_CAUSE_MASK) >> SCCSR_CAUSE_SHIFT;
	cap_idx = (sccsr & SCCSR_CAP_IDX_MASK) >> SCCSR_CAP_IDX_SHIFT;
	db_printf("sccsr: %s, %s, cause: 0x%02x,  ", sccsr & SCCSR_E ?
	    "enabled" : "disabled", sccsr & SCCSR_D ? "dirty" : "clean",
	    cause);
	if (cap_idx < 32)
		db_printf("reg: c%d ", cap_idx);
	else if (cap_idx - 32 < nitems(scr_names) &&
	    scr_names[cap_idx - 32] != NULL)
		db_printf("reg: %s ", scr_names[cap_idx - 32]);
	else
		db_printf("reg: invalid (%d) ", cap_idx);
	db_printf("(%s)\n", cheri_exccode_string(cause));

	db_print_cap("ddc: ",  scr_read(ddc));
	db_print_cap("pcc: ",  scr_read(pcc));
	db_print_cap("stcc: ",  scr_read(stcc));
	db_print_cap("stdc: ",  scr_read(stdc));
	db_print_cap("sscratchc: ",  scr_read(sscratchc));
	db_print_cap("sepcc: ",  scr_read(sepcc));

	/* XXX: Do user-mode registers if we support N? */
}
