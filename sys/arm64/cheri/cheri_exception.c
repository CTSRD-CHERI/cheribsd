/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Brett F. Gutstein
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <machine/armreg.h>

/*
 * Data Abort DFSC values are a superset
 * of Instruction Abort IFSC values.
 */

#define CHERI_FSC_SHIFT ISS_DATA_DFSC_CAP_TAG
static const char *cheri_fsc_descr[] = {
	[ISS_DATA_DFSC_CAP_TAG - CHERI_FSC_SHIFT] = "tag violation",
	[ISS_DATA_DFSC_CAP_SEALED - CHERI_FSC_SHIFT] = "seal violation",
	[ISS_DATA_DFSC_CAP_BOUND - CHERI_FSC_SHIFT] = "bounds violation",
	[ISS_DATA_DFSC_CAP_PERM - CHERI_FSC_SHIFT] = "permissions violation"
};

const char *
cheri_fsc_string(uint8_t fsc)
{
	uint8_t shifted = fsc - CHERI_FSC_SHIFT;
	if (shifted < 0 || shifted >= nitems(cheri_fsc_descr)) {
		return ("unknown fault status code");
	}
	return (cheri_fsc_descr[shifted]);
}

int
cheri_esr_to_sicode(uint64_t esr)
{
	uint8_t fsc = esr & ISS_DATA_DFSC_MASK;
	switch (fsc) {
	case ISS_DATA_DFSC_CAP_TAG:
		return (PROT_CHERI_TAG);
	case ISS_DATA_DFSC_CAP_SEALED:
		return (PROT_CHERI_SEALED);
	case ISS_DATA_DFSC_CAP_BOUND:
		return (PROT_CHERI_BOUNDS);
	case ISS_DATA_DFSC_CAP_PERM:
		return (PROT_CHERI_PERM);
	default:
		printf("%s: Warning: Unknown abort %x, returning si_code 0\n",
		    __func__, fsc);
		return (0);
	}
}

