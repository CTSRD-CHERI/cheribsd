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
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/pcb.h>
#include <machine/sysarch.h>

static const char *cheri_exccode_descr[] = {
	[CHERI_EXCCODE_NONE] = "none",
	[CHERI_EXCCODE_LENGTH] = "length violation",
	[CHERI_EXCCODE_TAG] = "tag violation",
	[CHERI_EXCCODE_SEAL] = "seal violation",
	[CHERI_EXCCODE_TYPE] = "type violation",
	[CHERI_EXCCODE_CALL] = "call trap",
	[CHERI_EXCCODE_RETURN] = "return trap",
	[CHERI_EXCCODE_UNDERFLOW] = "underflow of trusted system stack",
	[CHERI_EXCCODE_PERM_USER] = "user-defined permission violation",
	[CHERI_EXCCODE_TLBSTORE] = "TLB prohibits store capability",
	[CHERI_EXCCODE_IMPRECISE] = "bounds cannot be represented precisely",
	[CHERI_EXCCODE_GLOBAL] = "global violation",
	[CHERI_EXCCODE_PERM_EXECUTE] = "permit execute violation",
	[CHERI_EXCCODE_PERM_LOAD] = "permit load violation",
	[CHERI_EXCCODE_PERM_STORE] = "permit store violation",
	[CHERI_EXCCODE_PERM_LOADCAP] = "permit load capability violation",
	[CHERI_EXCCODE_PERM_STORECAP] = "permit store capability violation",
	[CHERI_EXCCODE_STORE_LOCALCAP] = "permit store local capability violation",
	[CHERI_EXCCODE_PERM_SEAL] = "permit seal violation",
	[CHERI_EXCCODE_SYSTEM_REGS] = "access system registers violation",
	[CHERI_EXCCODE_PERM_CCALL] = "permit ccall violation",
	[CHERI_EXCCODE_CCALL_IDC] = "access ccall IDC violation",
	[CHERI_EXCCODE_PERM_UNSEAL] = "permit unseal violation",
	[CHERI_EXCCODE_PERM_SET_CID] = "permit CSetCID violation",
};

const char *
cheri_exccode_string(uint8_t exccode)
{

	if (exccode >= nitems(cheri_exccode_descr) ||
	    cheri_exccode_descr[exccode] == NULL) {
		if (exccode >= CHERI_EXCCODE_SW_BASE)
			return ("unknown software exception");
		else
			return ("unknown ISA exception");
	}
	return (cheri_exccode_descr[exccode]);
}

static inline void
cheri_copy_and_validate(void * __capability *dst, void * __capability *src,
    register_t *capvalid, int which, bool strip_tags)
{

	*capvalid |= (register_t)cheri_gettag(*src) << which;
	if (strip_tags)
		*dst = cheri_cleartag(*src);
	else
		*dst = *src;
}

/*
 * Externalise in-kernel trapframe state to the user<->kernel ABI, struct
 * cheri_frame.
 */
void
_cheri_trapframe_to_cheriframe(struct trapframe *frame,
    struct cheri_frame *cfp, bool strip_tags)
{

	/*
	 * Handle the layout of the target structure very explicitly, to avoid
	 * future surprises (e.g., relating to padding, rearrangements, etc).
	 */
	bzero(cfp, sizeof(*cfp));

	cheri_copy_and_validate(&cfp->cf_ddc, &frame->ddc, &cfp->cf_capvalid, 0,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c1, &frame->c1, &cfp->cf_capvalid, 1,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c2, &frame->c2, &cfp->cf_capvalid, 2,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c3, &frame->c3, &cfp->cf_capvalid, 3,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c4, &frame->c4, &cfp->cf_capvalid, 4,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c5, &frame->c5, &cfp->cf_capvalid, 5,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c6, &frame->c6, &cfp->cf_capvalid, 6,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c7, &frame->c7, &cfp->cf_capvalid, 7,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c8, &frame->c8, &cfp->cf_capvalid, 8,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c9, &frame->c9, &cfp->cf_capvalid, 9,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c10, &frame->c10, &cfp->cf_capvalid, 10,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_csp, &frame->csp, &cfp->cf_capvalid, 11,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c12, &frame->c12, &cfp->cf_capvalid, 12,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c13, &frame->c13, &cfp->cf_capvalid, 13,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c14, &frame->c14, &cfp->cf_capvalid, 14,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c15, &frame->c15, &cfp->cf_capvalid, 15,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c16, &frame->c16, &cfp->cf_capvalid, 16,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c17, &frame->c17, &cfp->cf_capvalid, 17,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c18, &frame->c18, &cfp->cf_capvalid, 18,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c19, &frame->c19, &cfp->cf_capvalid, 19,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c20, &frame->c20, &cfp->cf_capvalid, 20,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c21, &frame->c21, &cfp->cf_capvalid, 21,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c22, &frame->c22, &cfp->cf_capvalid, 22,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c23, &frame->c23, &cfp->cf_capvalid, 23,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c24, &frame->c24, &cfp->cf_capvalid, 24,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c25, &frame->c25, &cfp->cf_capvalid, 25,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_idc, &frame->idc, &cfp->cf_capvalid, 26,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c27, &frame->c27, &cfp->cf_capvalid, 27,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c28, &frame->c28, &cfp->cf_capvalid, 28,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c29, &frame->c29, &cfp->cf_capvalid, 29,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c30, &frame->c30, &cfp->cf_capvalid, 30,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_c31, &frame->c31, &cfp->cf_capvalid, 31,
	    strip_tags);
	cheri_copy_and_validate(&cfp->cf_pcc, (void * __capability *)&frame->pc,
	    &cfp->cf_capvalid, 32, strip_tags);
	cfp->cf_capcause = frame->capcause;
}

/*
 * Internalise in-kernel trapframe state from the user<->kernel ABI, struct
 * cheri_frame.
 */
void
cheri_trapframe_from_cheriframe(struct trapframe *frame,
    struct cheri_frame *cfp)
{

	frame->ddc = cfp->cf_ddc;
	frame->c1 = cfp->cf_c1;
	frame->c2 = cfp->cf_c2;
	frame->c3 = cfp->cf_c3;
	frame->c4 = cfp->cf_c4;
	frame->c5 = cfp->cf_c5;
	frame->c6 = cfp->cf_c6;
	frame->c7 = cfp->cf_c7;
	frame->c8 = cfp->cf_c8;
	frame->c9 = cfp->cf_c9;
	frame->c10 = cfp->cf_c10;
	frame->csp = cfp->cf_csp;
	frame->c12 = cfp->cf_c12;
	frame->c13 = cfp->cf_c13;
	frame->c14 = cfp->cf_c14;
	frame->c15 = cfp->cf_c15;
	frame->c16 = cfp->cf_c16;
	frame->c17 = cfp->cf_c17;
	frame->c18 = cfp->cf_c18;
	frame->c19 = cfp->cf_c19;
	frame->c20 = cfp->cf_c20;
	frame->c21 = cfp->cf_c21;
	frame->c22 = cfp->cf_c22;
	frame->c23 = cfp->cf_c23;
	frame->c24 = cfp->cf_c24;
	frame->c25 = cfp->cf_c25;
	frame->idc = cfp->cf_idc;
	frame->c27 = cfp->cf_c27;
	frame->c28 = cfp->cf_c28;
	frame->c29 = cfp->cf_c29;
	frame->c30 = cfp->cf_c30;
	frame->c31 = cfp->cf_c31;
	frame->pcc = cfp->cf_pcc;
	frame->capcause = cfp->cf_capcause;
}

void
cheri_log_exception_registers(struct trapframe *frame)
{

	printf("$ddc: %#.16lp\n", frame->ddc);
	printf("$c01: %#.16lp\n", frame->c1);
	printf("$c02: %#.16lp\n", frame->c2);
	printf("$c03: %#.16lp\n", frame->c3);
	printf("$c04: %#.16lp\n", frame->c4);
	printf("$c05: %#.16lp\n", frame->c5);
	printf("$c06: %#.16lp\n", frame->c6);
	printf("$c07: %#.16lp\n", frame->c7);
	printf("$c08: %#.16lp\n", frame->c8);
	printf("$c09: %#.16lp\n", frame->c9);
	printf("$c10: %#.16lp\n", frame->c10);
	printf("$c11: %#.16lp\n", frame->csp);
	printf("$c12: %#.16lp\n", frame->c12);
	printf("$c13: %#.16lp\n", frame->c13);
	printf("$c14: %#.16lp\n", frame->c14);
	printf("$c15: %#.16lp\n", frame->c15);
	printf("$c16: %#.16lp\n", frame->c16);
	printf("$c17: %#.16lp\n", frame->c17);
	printf("$c18: %#.16lp\n", frame->c18);
	printf("$c19: %#.16lp\n", frame->c19);
	printf("$c20: %#.16lp\n", frame->c20);
	printf("$c21: %#.16lp\n", frame->c21);
	printf("$c22: %#.16lp\n", frame->c22);
	printf("$c23: %#.16lp\n", frame->c23);
	printf("$c24: %#.16lp\n", frame->c24);
	printf("$c25: %#.16lp\n", frame->c25);
	printf("$c26: %#.16lp\n", frame->idc);
	printf("$c27: %#.16lp\n", frame->c27);
	printf("$c28: %#.16lp\n", frame->c28);
	printf("$c29: %#.16lp\n", frame->c29);
	printf("$c30: %#.16lp\n", frame->c30);
	printf("$c31: %#.16lp\n", frame->c31);
	printf("$pcc: %#.16lp\n", frame->pcc);
}

void
cheri_log_exception(struct trapframe *frame, int trap_type)
{
	register_t cause;
	uint8_t exccode, regnum;

#ifdef SMP
	printf("cpuid = %d\n", PCPU_GET(cpuid));
#endif
	if ((trap_type == T_C2E) || (trap_type == T_C2E + T_USER)) {
		cause = frame->capcause;
		exccode = CHERI_CAPCAUSE_EXCCODE(cause);
		regnum = CHERI_CAPCAUSE_REGNUM(cause);
		printf("CHERI cause: ExcCode: 0x%02x ", exccode);
		if (regnum < 32)
			printf("RegNum: $c%02d ", regnum);
		else if (regnum == 255)
			printf("RegNum: $pcc ");
		else
			printf("RegNum: invalid (%d) ", regnum);
		printf("(%s)\n", cheri_exccode_string(exccode));
	}
	cheri_log_exception_registers(frame);
}

int
cheri_capcause_to_sicode(register_t capcause)
{
	uint8_t exccode;

	exccode = CHERI_CAPCAUSE_EXCCODE(capcause);
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

	case CHERI_EXCCODE_TLBSTORE:
		panic("TLBSTORE uses SIGSEGV");

	case CHERI_EXCCODE_IMPRECISE:
		return (PROT_CHERI_IMPRECISE);

	case CHERI_EXCCODE_GLOBAL:
	case CHERI_EXCCODE_STORE_LOCALCAP:
		return (PROT_CHERI_STORELOCAL);

	case CHERI_EXCCODE_CALL:
		return (PROT_CHERI_CCALL);

	case CHERI_EXCCODE_RETURN:
		return (PROT_CHERI_CRETURN);

	case CHERI_EXCCODE_SYSTEM_REGS:
		return (PROT_CHERI_SYSREG);

	case CHERI_EXCCODE_NONE:
	default:
		printf(
		    "%s: Warning: Unknown capcause %u, returning si_code 0\n",
		    __func__, exccode);
		return (0);
	}
}
