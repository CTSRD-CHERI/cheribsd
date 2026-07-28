/*-
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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

#ifndef _MACHINE_ASM_H_
#define	_MACHINE_ASM_H_

#undef __FBSDID
#if !defined(lint) && !defined(STRIP_FBSDID)
#define	__FBSDID(s)	.ident s
#else
#define	__FBSDID(s)	/* nothing */
#endif /* not lint and not STRIP_FBSDID */

#define	_C_LABEL(x)	x

#define	ENTRY(sym)						\
	.text; .globl sym; .type sym,@function; .align 4; sym: .cfi_startproc;
#define	END(sym) .cfi_endproc; .size sym, . - sym

#define	EENTRY(sym)						\
	.globl	sym; .type sym,@function; sym:
#define	EEND(sym) .size sym, . - sym

#define	WEAK_REFERENCE(sym, alias)				\
	.weak alias;						\
	.set alias,sym

#define	SET_FAULT_HANDLER(handler, tmp)					\
	L_PTR	tmp, PC_CURTHREAD(tp);				\
	L_PTR	tmp, TD_PCB(tmp);		/* Load the pcb */	\
	S_PTR	handler, PCB_ONFAULT(tmp)	/* Set the handler */

#define	ENTER_USER_ACCESS(tmp)						\
	li	tmp, SSTATUS_SUM;					\
	csrs	sstatus, tmp

#define	EXIT_USER_ACCESS(tmp)						\
	li	tmp, SSTATUS_SUM;					\
	csrc	sstatus, tmp

#define	SBI_CALL(ext, func)						\
	li	a7, ext;						\
	li	a6, func;						\
	ecall

/*
 * Abstract CSR manipulation that requires different
 * instructions across RV64, xcheri and RV64Y.
 */
#ifdef __riscv_xcheri
#define	GET_DDC(rd)				\
	cspecialr	CAP(rd), ddc

#define	SET_DDC(rs)				\
	cspecialw	ddc, CAP(rs)

#define	GET_PCC(rd)				\
	cspecialr	CAP(rd), pcc
#else /* !__riscv_xcheri */
/*
 * RVY hybrid is required for DDC
 * Note: these macros require capability mode
 * to use CLEN registers.
 */
#define	GET_DDC(rd)				\
	csrr		rd, ddc

#define	SET_DDC(rs)				\
	csrw		ddc, rs

#define	GET_PCC(rd)				\
	auipc		rd, 0
#endif /* !__riscv_xcheri */


#if __has_feature(capabilities) && defined(__riscv_xcheri)
#define	CSRR_CAP(rd, csrn)			\
	cspecialr	CAP(rd), csrn ## c

#define	CSRW_CAP(csrn, rs)			\
	cspecialw	csrn ## c, CAP(rs)

#define	CSRRW_CAP(rd, csrn, rs)				\
	cspecialrw	CAP(rd), csrn ## c, CAP(rs)
#else
#define	CSRR_CAP(rd, csrn)			\
	csrr		rd, csrn

#define	CSRW_CAP(csrn, rs)			\
	csrw		csrn, rs

#define	CSRRW_CAP(rd, csrn, rs)			\
	csrrw		rd, csrn, rs
#endif

/*
 * Instruction and register aliases for assembly that
 * operates on pointers.
 */

#define	INT_WIDTH	8

#if __has_feature(capabilities)
#ifdef __riscv_xcheri
#define	CAP(x)		c ## x
#else
#define	CAP(x)		x
#endif
#define	CAP_WIDTH	16

#define	L_CAP		ly
#define	S_CAP		sy
#define	MV_CAP		ymv
#define	ADD_CAP		yadd
#define	ADDI_CAP	yaddi
#ifdef __riscv_xcheri
/*
 * The MODESW macros are only relevant in the hybrid kernel.
 * In the pure-capability kernel, the MODESW macros become no-ops.
 */
#define	MODESW_CAP(tmp, tmp1)					\
	lla		tmp1, 99f;				\
	cspecialr	CAP(tmp), pcc;				\
	csetaddr CAP(tmp), CAP(tmp), tmp1;			\
	li		tmp1, 1;				\
	csetflags	CAP(tmp), CAP(tmp), tmp1;		\
	jr.cap		CAP(tmp);				\
	99:
#define	MODESW_INT(tmp)						\
	llc		CAP(tmp), 99f;				\
	csetflags	CAP(tmp), CAP(tmp), zero;		\
	jr.cap		CAP(tmp);				\
	99:
#define	YMODE_ENTER
#define	YMODE_EXIT
#elif defined(__riscv_zcheripurecap)
#define	MODESW_CAP(tmp, tmp1)	modesw.cap
#define	MODESW_INT(tmp)		modesw.int
#ifdef __CHERI_HYBRID__
#define	YMODE_ENTER				\
	modesw.cap;				\
	.option capmode
#define	YMODE_EXIT				\
	modesw.int;				\
	.option nocapmode
#else
#define	YMODE_ENTER
#define	YMODE_EXIT
#endif
#elif defined(__riscv_y)
#define	MODESW_CAP(tmp, tmp1)	ymodeswy
#define	MODESW_INT(tmp)		ymodeswi
#ifdef __CHERI_HYBRID__
/*
 * RVY uses additional mode switches because it has a more
 * constrained set of features available in hybrid mode.
 * These differ from the MODESW macros because they become
 * no-ops in a purecap kernel.
 */
#define	YMODE_ENTER				\
	ymodeswy;				\
	.option capmode
#define	YMODE_EXIT				\
	ymodeswi;				\
	.option nocapmode
#else
#define	YMODE_ENTER
#define	YMODE_EXIT
#endif
#endif /* __riscv_y */
#else /* !__has_feature(capabilities) */
#define	CAP(x)		x
#define	CAP_WIDTH	INT_WIDTH

#define	L_CAP		ld
#define	S_CAP		sd
#define	MV_CAP		mv
#define	ADD_CAP		add
#define	ADDI_CAP	addi
#define	MODESW_CAP(tmp, tmp1)
#define	MODESW_INT(tmp)
#define	YMODE_ENTER
#define	YMODE_EXIT
#endif  /* !__has_feature(capabilities) */

#ifdef __CHERI__
#define	PTR_WIDTH	CAP_WIDTH

#define	MV_PTR		ymv
#define	ADD_PTR		yadd
#define	ADDI_PTR	yaddi
#define	L_PTR		ly
#define	S_PTR		sy
#define	LLA_PTR		lly
#define	LA_PTR		lgy
#else /* !__CHERI__ */
#define	PTR_WIDTH	INT_WIDTH

#define	MV_PTR		mv
#define	ADD_PTR		add
#define	ADDI_PTR	addi
#define	L_PTR		ld
#define	S_PTR		sd
#define	LLA_PTR		lla
#define	LA_PTR		la
#endif /* !__CHERI__ */

#endif /* _MACHINE_ASM_H_ */
// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "header",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
