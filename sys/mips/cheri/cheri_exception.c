/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
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

static const char *cheri_exccode_isa_array[] = {
	"none",					/* CHERI_EXCCODE_NONE */
	"length violation",			/* CHERI_EXCCODE_LENGTH */
	"tag violation",			/* CHERI_EXCCODE_TAG */
	"seal violation",			/* CHERI_EXCCODE_SEAL */
	"type violation",			/* CHERI_EXCCODE_TYPE */
	"call trap",				/* CHERI_EXCCODE_CALL */
	"return trap",				/* CHERI_EXCCODE_RETURN */
	"underflow of trusted system stack",	/* CHERI_EXCCODE_UNDERFLOW */
	"user-defined permission violation",	/* CHERI_EXCCODE_PERM_USER */
	"TLB prohibits store capability",	/* CHERI_EXCCODE_TLBSTORE */
    "Bounds cannot be represented precisely", /* 0xa: CHERI_EXCCODE_IMPRECISE */
	"reserved",				/* 0xb: TBD */
	"reserved",				/* 0xc: TBD */
	"reserved",				/* 0xd: TBD */
	"reserved",				/* 0xe: TBD */
	"reserved",				/* 0xf: TBD */
	"global violation",			/* CHERI_EXCCODE_GLOBAL */
	"permit execute violation",		/* CHERI_EXCCODE_PERM_EXECUTE */
	"permit load violation",		/* CHERI_EXCCODE_PERM_LOAD */
	"permit store violation",		/* CHERI_EXCCODE_PERM_STORE */
	"permit load capability violation",	/* CHERI_EXCCODE_PERM_LOADCAP */
	"permit store capability violation",   /* CHERI_EXCCODE_PERM_STORECAP */
     "permit store local capability violation", /* CHERI_EXCCODE_STORE_LOCAL */
	"permit seal violation",		/* CHERI_EXCCODE_PERM_SEAL */
	"access system registers violation",	/* CHERI_EXCCODE_SYSTEM_REGS */
	"permit ccall violation",		/* CHERI_EXCCODE_PERM_CCALL */
	"access ccall IDC violation",		/* CHERI_EXCCODE_CCALL_IDC */
	"reserved",				/* 0x1b */
	"reserved",				/* 0x1c */
	"reserved",				/* 0x1d */
	"reserved",				/* 0x1e */ 
	"reserved",				/* 0x1f */
};
static const int cheri_exccode_isa_array_length =
    sizeof(cheri_exccode_isa_array) / sizeof(cheri_exccode_isa_array[0]);

static const char *cheri_exccode_sw_array[] = {
	"local capability in argument",		/* CHERI_EXCCODE_SW_LOCALARG */
	"local capability in return value",	/* CHERI_EXCCODE_SW_LOCALRET */
	"incorrect CCall registers",		/* CHERI_EXCCODE_SW_CCALLREGS */
	"trusted stack overflow",		/* CHERI_EXCCODE_SW_OVERFLOW */
	"trusted stack underflow",		/* CHERI_EXCCODE_SW_UNDERFLOW */
};
static const int cheri_exccode_sw_array_length =
    sizeof(cheri_exccode_sw_array) / sizeof(cheri_exccode_sw_array[0]);

const char *
cheri_exccode_string(uint8_t exccode)
{

	if (exccode >= CHERI_EXCCODE_SW_BASE) {
		exccode -= CHERI_EXCCODE_SW_BASE;
		if (exccode >= cheri_exccode_sw_array_length)
			return ("unknown software exception");
		return (cheri_exccode_sw_array[exccode]);
	} else {
		if (exccode >= cheri_exccode_isa_array_length)
			return ("unknown ISA exception");
		return (cheri_exccode_isa_array[exccode]);
	}
}

static inline void
cheri_copy_and_validate(void * __capability *dst, void * __capability *src,
    register_t *capvalid, int which)
{

	*capvalid |= cheri_gettag(*src) << which;
	*dst = *src;
}

/*
 * Externalise in-kernel trapframe state to the user<->kernel ABI, struct
 * cheri_frame.
 */
void
cheri_trapframe_to_cheriframe(struct trapframe *frame,
    struct cheri_frame *cfp)
{

	/*
	 * Handle the layout of the target structure very explicitly, to avoid
	 * future surprises (e.g., relating to padding, rearrangements, etc).
	 */
	bzero(cfp, sizeof(*cfp));

	cheri_copy_and_validate(&cfp->cf_ddc, &frame->ddc, &cfp->cf_capvalid, 0);
	cheri_copy_and_validate(&cfp->cf_c1, &frame->c1, &cfp->cf_capvalid, 1);
	cheri_copy_and_validate(&cfp->cf_c2, &frame->c2, &cfp->cf_capvalid, 2);
	cheri_copy_and_validate(&cfp->cf_c3, &frame->c3, &cfp->cf_capvalid, 3);
	cheri_copy_and_validate(&cfp->cf_c4, &frame->c4, &cfp->cf_capvalid, 4);
	cheri_copy_and_validate(&cfp->cf_c5, &frame->c5, &cfp->cf_capvalid, 5);
	cheri_copy_and_validate(&cfp->cf_c6, &frame->c6, &cfp->cf_capvalid, 6);
	cheri_copy_and_validate(&cfp->cf_c7, &frame->c7, &cfp->cf_capvalid, 7);
	cheri_copy_and_validate(&cfp->cf_c8, &frame->c8, &cfp->cf_capvalid, 8);
	cheri_copy_and_validate(&cfp->cf_c9, &frame->c9, &cfp->cf_capvalid, 9);
	cheri_copy_and_validate(&cfp->cf_c10, &frame->c10, &cfp->cf_capvalid, 10);
	cheri_copy_and_validate(&cfp->cf_csp, &frame->csp, &cfp->cf_capvalid, 11);
	cheri_copy_and_validate(&cfp->cf_c12, &frame->c12, &cfp->cf_capvalid, 12);
	cheri_copy_and_validate(&cfp->cf_c13, &frame->c13, &cfp->cf_capvalid, 13);
	cheri_copy_and_validate(&cfp->cf_c14, &frame->c14, &cfp->cf_capvalid, 14);
	cheri_copy_and_validate(&cfp->cf_c15, &frame->c15, &cfp->cf_capvalid, 15);
	cheri_copy_and_validate(&cfp->cf_c16, &frame->c16, &cfp->cf_capvalid, 16);
	cheri_copy_and_validate(&cfp->cf_c17, &frame->c17, &cfp->cf_capvalid, 17);
	cheri_copy_and_validate(&cfp->cf_c18, &frame->c18, &cfp->cf_capvalid, 18);
	cheri_copy_and_validate(&cfp->cf_c19, &frame->c19, &cfp->cf_capvalid, 19);
	cheri_copy_and_validate(&cfp->cf_c20, &frame->c20, &cfp->cf_capvalid, 20);
	cheri_copy_and_validate(&cfp->cf_c21, &frame->c21, &cfp->cf_capvalid, 21);
	cheri_copy_and_validate(&cfp->cf_c22, &frame->c22, &cfp->cf_capvalid, 22);
	cheri_copy_and_validate(&cfp->cf_c23, &frame->c23, &cfp->cf_capvalid, 23);
	cheri_copy_and_validate(&cfp->cf_c24, &frame->c24, &cfp->cf_capvalid, 24);
	cheri_copy_and_validate(&cfp->cf_c25, &frame->c25, &cfp->cf_capvalid, 25);
	cheri_copy_and_validate(&cfp->cf_idc, &frame->idc, &cfp->cf_capvalid, 26);
	cheri_copy_and_validate(&cfp->cf_pcc, &frame->pcc, &cfp->cf_capvalid, 27);
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
	frame->pcc = cfp->cf_pcc;
	frame->capcause = cfp->cf_capcause;
}

void
cheri_log_exception_registers(struct trapframe *frame)
{

	cheri_log_cheri_frame(frame);
}

void
cheri_log_cheri_frame(struct trapframe *frame)
{

	/* C0 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->ddc, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 0);

	/* C1 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c1, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 1);

	/* C2 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c2, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 2);

	/* C3 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c3, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 3);

	/* C4 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c4, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 4);

	/* C5 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c5, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 5);

	/* C6 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c6, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 6);

	/* C7 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c7, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 7);

	/* C8 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c8, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 8);

	/* C9 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c9, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 9);

	/* C10 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c10, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 10);

	/* C11 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->csp, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 11);

	/* C12 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c12, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 12);

	/* C13 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c13, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 13);

	/* C14 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c14, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 14);

	/* C15 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c15, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 15);

	/* C16 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c16, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 16);

	/* C17 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c17, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 17);

	/* C18 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c18, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 18);

	/* C19 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c19, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 19);

	/* C20 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c20, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 20);

	/* C21 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c21, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 21);

	/* C22 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c22, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 22);

	/* C23 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c23, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 23);

	/* C24 */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->c24, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 24);

	/* C26 - $idc */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->idc, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 26);

	/* C31 - saved $pcc */
	CHERI_CLC(CHERI_CR_CTEMP0, CHERI_CR_KDC, &frame->pcc, 0);
	CHERI_REG_PRINT(CHERI_CR_CTEMP0, 31);
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
		exccode = (cause & CHERI_CAPCAUSE_EXCCODE_MASK) >>
		    CHERI_CAPCAUSE_EXCCODE_SHIFT;
		regnum = cause & CHERI_CAPCAUSE_REGNUM_MASK;
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

	exccode = (capcause & CHERI_CAPCAUSE_EXCCODE_MASK) >>
	    CHERI_CAPCAUSE_EXCCODE_SHIFT;
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
	case CHERI_EXCCODE_USER_PERM:
		return (PROT_CHERI_PERM);

	case CHERI_EXCCODE_TLBSTORE:
		return (PROT_CHERI_STORETAG);

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

	case CHERI_EXCCODE_SW_OVERFLOW:
		return (PROT_CHERI_OVERFLOW);

	case CHERI_EXCCODE_SW_UNDERFLOW:
		return (PROT_CHERI_UNDERFLOW);

	case CHERI_EXCCODE_SW_CCALLREGS:
		return (PROT_CHERI_CCALLREGS);

	case CHERI_EXCCODE_SW_LOCALARG:
		return (PROT_CHERI_LOCALARG);

	case CHERI_EXCCODE_SW_LOCALRET:
		return (PROT_CHERI_LOCALRET);

	case CHERI_EXCCODE_NONE:
	default:
		printf(
		    "%s: Warning: Unknown capcause %u, returning si_code 0\n",
		    __func__, exccode);
		return (0);
	}
}
