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

#ifdef __CHERI_PURE_CAPABILITY__
#define	SET_FAULT_HANDLER(handler, tmp)					\
	lc	tmp, PC_CURTHREAD(ctp);					\
	lc	tmp, TD_PCB(tmp);		/* Load the pcb */	\
	sc	handler, PCB_ONFAULT(tmp)	/* Set the handler */
#else
#define	SET_FAULT_HANDLER(handler, tmp)					\
	ld	tmp, PC_CURTHREAD(tp);					\
	ld	tmp, TD_PCB(tmp);		/* Load the pcb */	\
	sd	handler, PCB_ONFAULT(tmp)	/* Set the handler */
#endif

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
 * Instruction and register aliases for assembly that
 * operates on pointers.
 * Alias mnemonics follow the Zcheri draft specification naming convention.
 */

#define	INT_WIDTH	8

#if __has_feature(capabilities)
#define	CAP(x)	c ## x
#define	CAPN(n)	c ## n
#define	CAP_CSR(x)	x ## c
#define	CAP_WIDTH	16

#ifdef __riscv_xcheri
#define	_CAP_INSTR(x)	c ## x
// Note: in xcheri mode switching must be handled separately
#define	_MODESW_CAP
#define	_MODESW_INT
#else /* defined(__riscv_zcheripurecap) */
#define	_CAP_INSTR(x)	x
#define	_MODESW_CAP				\
	modesw.cap;				\
	.option capmode
#define	_MODESW_INT				\
	modesw.int;				\
	.option nocapmode
#endif /* defined(__riscv_xcheripurecap) */
#else /* !__has_feature(capabilities) */
#define	CAP(x)	x
#define	CAPN(n)	x ## n
#define	CAP_CSR(x)	x
#define	CAP_WIDTH	INT_WIDTH
#define	_CAP_INSTR(x)	x
#define	_MODESW_CAP
#define	_MODESW_INT
#endif  /* !__has_feature(capabilities) */

#ifdef __CHERI_PURE_CAPABILITY__
#define	PTR(x)	CAP(x)
#define	PTRN(n)	CAPN(n)
#define	PTR_CSR(x)	CAP_CSR(x)
#define	PTR_WIDTH	CAP_WIDTH
#define	_PTR_INSTR(x)	_CAP_INSTR(x)
#define	MODESW_CAP
#define	MODESW_INT
#ifdef __riscv_xcheri
#else /* defined(__riscv_xcheripurecap) */
#endif /* defined(__riscv_xcheripurecap) */
#else /* !defined(__CHERI_PURE_CAPABILITY__) */
#define	PTR(x)	x
#define	PTRN(n)	x ## n
#define	PTR_CSR(x)	x
#define	PTR_WIDTH	INT_WIDTH
#define	_PTR_INSTR(x)	x
#define	MODESW_CAP	_MODESW_CAP
#define	MODESW_INT	_MODESW_INT
#endif /* !defined(__CHERI_PURE_CAPABILITY__) */

/*
 * Load and store instruction aliases.
 *
 * _Lx _Sx: Memory operand is a pointer
 * L_PTR S_PTR: load / store pointer via a pointer
 * _LC _SC: load / store capability via a pointer
 * Lx_CAP Sx_CAP: memory operand is a capability when in integer mode
 */
#define	_LD	_PTR_INSTR(ld)
#define	_LW	_PTR_INSTR(lw)
#define	_LHU	_PTR_INSTR(lhu)
#define	_LB	_PTR_INSTR(lb)
#define	_LBU	_PTR_INSTR(lbu)
#define	_SD	_PTR_INSTR(sd)
#define	_SW	_PTR_INSTR(sw)
#define	_SH	_PTR_INSTR(sh)
#define	_SB	_PTR_INSTR(sb)
#define	_FLD	_PTR_INSTR(fld)
#define	_FSD	_PTR_INSTR(fsd)
#ifdef __CHERI_PURE_CAPABILITY__
#define	L_PTR	_LC
#define	S_PTR	_SC
#define	_LC	_PTR_INSTR(lc)
#define	_SC	_PTR_INSTR(sc)
#define	LB_CAP	_LB
#define	LBU_CAP	_LBU
#define	LHU_CAP	_LHU
#define	LW_CAP	_LW
#define	LD_CAP	_LD
#define	LC_CAP	_LC
#define	SB_CAP	_SB
#define	SH_CAP	_SH
#define	SW_CAP	_SW
#define	SD_CAP	_SD
#define	SC_CAP	S_PTR
#else /* !defined(__CHERI_PURE_CAPABILITY__) */
#define	L_PTR	ld
#define	S_PTR	sd
#if __has_feature(capabilities)
#define	_LC	lc
#define	_SC	sc
#else
#define	_LC	L_PTR
#define	_SC	S_PTR
#endif
#ifdef __riscv_xcheri
/*
 * These are only valid in xcheri, zcheri needs
 * to modesw.cap.
 */
#define	LB_CAP	lb.cap
#define	LBU_CAP	lbu.cap
#define	LHU_CAP	lhu.cap
#define	LW_CAP	lw.cap
#define	LD_CAP	ld.cap
#define	LC_CAP	lc.cap
#define	SB_CAP	sb.cap
#define	SH_CAP	sh.cap
#define	SW_CAP	sw.cap
#define	SD_CAP	sd.cap
#define	SC_CAP	sc.cap
#else /* __riscv_zcheripurecap */
#define	LB_CAP	lb
#define	LBU_CAP	lbu
#define	LHU_CAP	lhu
#define	LW_CAP	lw
#define	LD_CAP	ld
#define	LC_CAP	lc
#define	SB_CAP	sb
#define	SH_CAP	sh
#define	SW_CAP	sw
#define	SD_CAP	sd
#define	SC_CAP	sc
#endif /* __riscv_xcheri */
#endif /* !defined(__CHERI_PURE_CAPABILITY__) */

/* Relocation pseudo instructions */
#ifdef __CHERI_PURE_CAPABILITY__
#define	_LLC	_PTR_INSTR(llc)
#define	_LGC	_PTR_INSTR(lgc)
#else
#define	_LLC	lla
#define	_LGC	lga
#endif

/* Control flow instructions and pseudo */
#define	_JALR	_PTR_INSTR(jalr)
#define	_JAL	_PTR_INSTR(jal)
#define	_JR	_PTR_INSTR(jr)
#define	RETURN	_PTR_INSTR(ret)
#define	_CALL	_PTR_INSTR(call)
#define	_TAIL	_PTR_INSTR(tail)

/* Pointer arithmetic */
#define	CMV_INT	mv
#define	CADD_INT	add
#define	CADDI_INT	addi
#if __has_feature(capabilities)
#ifdef __riscv_xcheri
#define	CMV_CAP	cmove
#define	CADD_CAP	cincoffset
#define	CADDI_CAP	CADD_CAP
#define	_SCBNDS		csetboundsexact
#define	_SCBNDSR	csetbounds
#define	_SCADDR		csetaddr
#define	_ACPERM		candperm
#define	_CBLD		cbuildcap
#else /* defined(__riscv_zcheripurecap) */
#define	CMV_CAP	cmv
#define	CADD_CAP	cadd
#define	CADDI_CAP	caddi
#define	_SCBNDS		scbnds
#define	_SCBNDSR	scbndsr
#define	_SCADDR		scaddr
#define	_ACPERM		acperm
#define	_CBLD		cbld
#endif /* defined(__riscv_zcheripurecap) */
#else /* !__has_feature(capabilities) */
#define	CMV_CAP	CMV_INT
#define	CADD_CAP	CADD_INT
#define	CADDI_CAP	CADDI_INT
#endif /* !__has_feature(capabilities) */

#ifdef __CHERI_PURE_CAPABILITY__
#define	_CMV	CMV_CAP
#define	_CADD	CADD_CAP
#define	_CADDI	CADDI_CAP
#else
#define	_CMV	CMV_INT
#define	_CADD	CADD_INT
#define	_CADDI	CADDI_INT
#endif

/* Atomic instructions */
#define	AMOADD_W	_PTR_INSTR(amoadd.w)
#if __has_feature(capabilities) && defined(__riscv_xcheri)
#ifdef __CHERI_PURE_CAPABILITY__
#define	LR_W_CAP	clr.w
#define	LR_D_CAP	clr.d
#else
#define	LR_W_CAP	lr.w.cap
#define	LR_D_CAP	lr.d.cap
#endif
#else /* !__has_feature(capabilities) || __riscv_zcheripurecap */
/* Note: zcheri must manually modesw to use these */
#define	LR_W_CAP	lr.w
#define	LR_D_CAP	lr.d
#endif  /* !__has_features(capabilities) || __riscv_zcheripurecap */

/* Pointer-wide CSR access */
#define	_CSRRW_INT(x)	csr ## x
#ifdef __riscv_xcheri
#define	_CSRRW_CAP(x)	cspecial ## x
#else /* defined(__riscv_zcheripurecap) || !__has_feature(capabilities) */
#define	_CSRRW_CAP(x)	csr ## x
#endif

#define	CSRRW_CAP	_CSRRW_CAP(rw)
#define	CSRR_CAP	_CSRRW_CAP(r)
#define	CSRW_CAP	_CSRRW_CAP(w)
#ifdef __CHERI_PURE_CAPABILITY__
#define	_CSRRW		CSRRW_CAP
#define	_CSRR		CSRR_CAP
#define	_CSRW		CSRW_CAP
#else
#define	_CSRRW		_CSRRW_INT(rw)
#define	_CSRR		_CSRRW_INT(r)
#define	_CSRW		_CSRRW_INT(w)
#endif

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
