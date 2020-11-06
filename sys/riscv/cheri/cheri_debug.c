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

/*
 * Show the special capability registers that aren't GPRs.
 */
DB_SHOW_COMMAND(scr, ddb_dump_scr)
{
	uint64_t sccsr;

	sccsr = csr_read(sccsr);
	db_printf("sccsr: %s, %s\n", sccsr & SCCSR_E ? "enabled" : "disabled",
	    sccsr & SCCSR_D ? "dirty" : "clean");

	db_printf("ddc: %#.16lp\n",  scr_read(ddc));
	db_printf("pcc: %#.16lp\n",  scr_read(pcc));
	db_printf("stcc: %#.16lp\n",  scr_read(stcc));
	db_printf("stdc: %#.16lp\n",  scr_read(stdc));
	db_printf("sscratchc: %#.16lp\n",  scr_read(sscratchc));
	db_printf("sepcc: %#.16lp\n",  scr_read(sepcc));

	/* XXX: Do user-mode registers if we support N? */
}
