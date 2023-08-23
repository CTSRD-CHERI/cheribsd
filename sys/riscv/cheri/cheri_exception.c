/*-
 * Copyright (c) 2011-2018 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/param.h>
#include <sys/signal.h>
#include <sys/systm.h>

#include <cheri/cheri.h>

#include <machine/riscvreg.h>

static const char *cheri_exccode_descr[] = {
	[CHERI_EXCCODE_NONE] = "none",
	[CHERI_EXCCODE_LENGTH] = "length violation",
	[CHERI_EXCCODE_TAG] = "tag violation",
	[CHERI_EXCCODE_SEAL] = "seal violation",
	[CHERI_EXCCODE_TYPE] = "type violation",
	[CHERI_EXCCODE_PERM_USER] = "user-defined permission violation",
	[CHERI_EXCCODE_IMPRECISE] = "bounds cannot be represented precisely",
	[CHERI_EXCCODE_UNALIGNED_BASE] = "Unaligned PCC base",
	[CHERI_EXCCODE_GLOBAL] = "global violation",
	[CHERI_EXCCODE_PERM_EXECUTE] = "permit execute violation",
	[CHERI_EXCCODE_PERM_LOAD] = "permit load violation",
	[CHERI_EXCCODE_PERM_STORE] = "permit store violation",
	[CHERI_EXCCODE_PERM_LOADCAP] = "permit load capability violation",
	[CHERI_EXCCODE_PERM_STORECAP] = "permit store capability violation",
	[CHERI_EXCCODE_STORE_LOCALCAP] = "permit store local capability violation",
	[CHERI_EXCCODE_PERM_SEAL] = "permit seal violation",
	[CHERI_EXCCODE_SYSTEM_REGS] = "access system registers violation",
	[CHERI_EXCCODE_PERM_CINVOKE] = "permit cinvoke violation",
	[CHERI_EXCCODE_PERM_UNSEAL] = "permit unseal violation",
	[CHERI_EXCCODE_PERM_SET_CID] = "permit CSetCID violation",
};

static const char *cheri_cap_idx_descr[] = {
	[0] = "cnull",
	[1] = "cra",
	[2] = "csp",
	[3] = "cgp",
	[4] = "ctp",
	[5] = "ct0",
	[6] = "ct1",
	[7] = "ct2",
	[8] = "cs0",
	[9] = "cs1",
	[10] = "ca0",
	[11] = "ca1",
	[12] = "ca2",
	[13] = "ca3",
	[14] = "ca4",
	[15] = "ca5",
	[16] = "ca6",
	[17] = "ca7",
	[18] = "cs2",
	[19] = "cs3",
	[20] = "cs4",
	[21] = "cs5",
	[22] = "cs6",
	[23] = "cs7",
	[24] = "cs8",
	[25] = "cs9",
	[26] = "cs10",
	[27] = "cs11",
	[28] = "ct3",
	[29] = "ct4",
	[30] = "ct5",
	[31] = "ct6",
	[32 + 0] = "pcc",
	[32 + 1] = "ddc",
	[32 + 4] = "utcc",
	[32 + 5] = "utdc",
	[32 + 6] = "uscratchc",
	[32 + 7] = "uepcc",
	[32 + 12] = "stcc",
	[32 + 13] = "stdc",
	[32 + 14] = "sscratchc",
	[32 + 15] = "sepcc",
	[32 + 28] = "mtcc",
	[32 + 29] = "mtdc",
	[32 + 30] = "mscratchc",
	[32 + 31] = "mepcc",
};

const char *
cheri_exccode_string(uint8_t exccode)
{
	static char buf[16];

	if (exccode >= nitems(cheri_exccode_descr) ||
	    cheri_exccode_descr[exccode] == NULL) {
		snprintf(buf, sizeof(buf), "exception %#x", exccode);
		return (buf);
	}
	return (cheri_exccode_descr[exccode]);
}

const char *
cheri_cap_idx_string(uint8_t cap_idx)
{
	static char buf[16];

	if (cap_idx >= nitems(cheri_cap_idx_descr) ||
	    cheri_cap_idx_descr[cap_idx] == NULL) {
		snprintf(buf, sizeof(buf), "unknown SCR %u", cap_idx - 32);
		return (buf);
	}
	return (cheri_cap_idx_descr[cap_idx]);
}

int
cheri_stval_to_sicode(register_t stval)
{
	uint8_t exccode;

	exccode = TVAL_CAP_CAUSE(stval);
	switch (exccode) {
	case CHERI_EXCCODE_LENGTH:
		return (PROT_CHERI_BOUNDS);

	case CHERI_EXCCODE_TAG:
		return (PROT_CHERI_TAG);

	case CHERI_EXCCODE_SEAL:
		return (PROT_CHERI_SEALED);

	case CHERI_EXCCODE_TYPE:
		return (PROT_CHERI_TYPE);

	case CHERI_EXCCODE_PERM_EXECUTE:
	case CHERI_EXCCODE_PERM_LOAD:
	case CHERI_EXCCODE_PERM_STORE:
	case CHERI_EXCCODE_PERM_LOADCAP:
	case CHERI_EXCCODE_PERM_STORECAP:
	case CHERI_EXCCODE_PERM_SEAL:
	case CHERI_EXCCODE_PERM_UNSEAL:
	case CHERI_EXCCODE_USER_PERM:
	case CHERI_EXCCODE_PERM_SET_CID:
		return (PROT_CHERI_PERM);

	case CHERI_EXCCODE_IMPRECISE:
		return (PROT_CHERI_IMPRECISE);

	case CHERI_EXCCODE_UNALIGNED_BASE:
		return (PROT_CHERI_UNALIGNED_BASE);

	case CHERI_EXCCODE_GLOBAL:
	case CHERI_EXCCODE_STORE_LOCALCAP:
		return (PROT_CHERI_STORELOCAL);

	case CHERI_EXCCODE_PERM_CINVOKE:
		return (PROT_CHERI_CINVOKE);

	case CHERI_EXCCODE_SYSTEM_REGS:
		return (PROT_CHERI_SYSREG);

	case CHERI_EXCCODE_NONE:
	default:
		printf(
		    "%s: Warning: Unknown exccode %u, returning si_code 0\n",
		    __func__, exccode);
		return (0);
	}
}
