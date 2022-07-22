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

const char *
cheri_exccode_string(uint8_t exccode)
{

	if (exccode >= nitems(cheri_exccode_descr) ||
	    cheri_exccode_descr[exccode] == NULL) {
		return ("unknown ISA exception");
	}
	return (cheri_exccode_descr[exccode]);
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
