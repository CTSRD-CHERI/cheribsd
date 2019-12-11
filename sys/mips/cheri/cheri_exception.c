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
    "bounds cannot be represented precisely", /* 0xa: CHERI_EXCCODE_IMPRECISE */
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
	"permit unseal violation",		/* CHERI_EXCODE_PERM_UNSEAL */
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
	cheri_copy_and_validate(&cfp->cf_pcc, (void *__capability *)&frame->pc,
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

	cheri_log_cheri_frame(frame);
}

static inline void
cheri_cap_print(void* __capability cap)
{
	uintmax_t c_perms, c_otype, c_base, c_length, c_offset;
	u_int ctag, c_sealed;

	ctag = cheri_gettag(cap);
	c_sealed = cheri_getsealed(cap);
	c_perms = cheri_getperm(cap);
	c_otype = cheri_gettype(cap);
	c_base = cheri_getbase(cap);
	c_length = cheri_getlen(cap);
	c_offset = cheri_getoffset(cap);
	printf("v:%u s:%u p:%08jx b:%016jx l:%016jx o:%jx t:%s%jx\n",
	    ctag, c_sealed, c_perms, c_base, c_length, c_offset,
	    (c_otype == - 1 ? "-" : ""), (c_otype == -1 ? 1 : c_otype));
}

#define	CHERI_REG_PRINT(cap, num) do {					\
	printf("$c%02u: ", num);					\
	cheri_cap_print(cap);						\
} while (0)

void
cheri_log_cheri_frame(struct trapframe *frame)
{

	/* C0 - $ddc */
	printf("$ddc: ");
	cheri_cap_print(frame->ddc);
	/* C1 */
	CHERI_REG_PRINT(frame->c1, 1);
	/* C2 */
	CHERI_REG_PRINT(frame->c2, 2);
	/* C3 */
	CHERI_REG_PRINT(frame->c3, 3);
	/* C4 */
	CHERI_REG_PRINT(frame->c4, 4);
	/* C5 */
	CHERI_REG_PRINT(frame->c5, 5);
	/* C6 */
	CHERI_REG_PRINT(frame->c6, 6);
	/* C7 */
	CHERI_REG_PRINT(frame->c7, 7);
	/* C8 */
	CHERI_REG_PRINT(frame->c8, 8);
	/* C9 */
	CHERI_REG_PRINT(frame->c9, 9);
	/* C10 */
	CHERI_REG_PRINT(frame->c10, 10);
	/* C11 */
	CHERI_REG_PRINT(frame->csp, 11);
	/* C12 */
	CHERI_REG_PRINT(frame->c12, 12);
	/* C13 */
	CHERI_REG_PRINT(frame->c13, 13);
	/* C14 */
	CHERI_REG_PRINT(frame->c14, 14);
	/* C15 */
	CHERI_REG_PRINT(frame->c15, 15);
	/* C16 */
	CHERI_REG_PRINT(frame->c16, 16);
	/* C17 */
	CHERI_REG_PRINT(frame->c17, 17);
	/* C18 */
	CHERI_REG_PRINT(frame->c18, 18);
	/* C19 */
	CHERI_REG_PRINT(frame->c19, 19);
	/* C20 */
	CHERI_REG_PRINT(frame->c20, 20);
	/* C21 */
	CHERI_REG_PRINT(frame->c21, 21);
	/* C22 */
	CHERI_REG_PRINT(frame->c22, 22);
	/* C23 */
	CHERI_REG_PRINT(frame->c23, 23);
	/* C24 */
	CHERI_REG_PRINT(frame->c24, 24);
	/* C25 */
	CHERI_REG_PRINT(frame->c25, 25);
	/* C26 - $idc / $cgp */
	CHERI_REG_PRINT(frame->idc, 26);
	/* C27 */
	CHERI_REG_PRINT(frame->c27, 27);
	/* C28 */
	CHERI_REG_PRINT(frame->c28, 28);
	/* C29 */
	CHERI_REG_PRINT(frame->c29, 29);
	/* C30 */
	CHERI_REG_PRINT(frame->c30, 30);
	/* C31 */
	CHERI_REG_PRINT(frame->c31, 31);
	/* saved $pcc */
	printf("$pcc: ");
	cheri_cap_print(frame->pcc);
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
	case CHERI_EXCCODE_PERM_UNSEAL:
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
