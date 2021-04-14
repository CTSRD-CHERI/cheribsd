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

#ifndef _MIPS_INCLUDE_CHERIREG_H_
#define	_MIPS_INCLUDE_CHERIREG_H_

/*
 * The size of in-memory capabilities in bytes; minimum alignment is also
 * assumed to be this size.
 */
#if defined(_MIPS_SZCAP) && (_MIPS_SZCAP != 128)
#error "_MIPS_SZCAP defined but is not 128"
#endif

#define	CHERICAP_SIZE   16
#define	CHERICAP_SHIFT	4

/*
 * CHERI ISA-defined constants for capabilities -- suitable for inclusion from
 * assembly source code.
 *
 * XXXRW: CHERI_UNSEALED is not currently considered part of the perms word,
 * but perhaps it should be.
 */
#define	CHERI_PERM_GLOBAL			(1 << 0)	/* 0x00000001 */
#define	CHERI_PERM_EXECUTE			(1 << 1)	/* 0x00000002 */
#define	CHERI_PERM_LOAD				(1 << 2)	/* 0x00000004 */
#define	CHERI_PERM_STORE			(1 << 3)	/* 0x00000008 */
#define	CHERI_PERM_LOAD_CAP			(1 << 4)	/* 0x00000010 */
#define	CHERI_PERM_STORE_CAP			(1 << 5)	/* 0x00000020 */
#define	CHERI_PERM_STORE_LOCAL_CAP		(1 << 6)	/* 0x00000040 */
#define	CHERI_PERM_SEAL				(1 << 7)	/* 0x00000080 */
#define	CHERI_PERM_CCALL			(1 << 8)	/* 0x00000100 */
#define	CHERI_PERM_UNSEAL			(1 << 9)	/* 0x00000200 */
#define	CHERI_PERM_SYSTEM_REGS			(1 << 10)	/* 0x00000400 */
#define	CHERI_PERM_SET_CID			(1 << 11)	/* 0x00000800 */

/* User-defined permission bits. */
#define	CHERI_PERM_SW0			(1 << 15)	/* 0x00008000 */
#define	CHERI_PERM_SW1			(1 << 16)	/* 0x00010000 */
#define	CHERI_PERM_SW2			(1 << 17)	/* 0x00020000 */
#define	CHERI_PERM_SW3			(1 << 18)	/* 0x00040000 */

/*
 * Macros defining initial permission sets for various scenarios; details
 * depend on the permissions available on 256-bit or 128-bit CHERI:
 *
 * CHERI_PERMS_SWALL: Mask of all available software-defined permissions
 * CHERI_PERMS_HWALL: Mask of all available hardware-defined permissions
 */
#define	CHERI_PERMS_SWALL						\
	(CHERI_PERM_SW0 | CHERI_PERM_SW1 | CHERI_PERM_SW2 |		\
	CHERI_PERM_SW3)

#define	CHERI_PERMS_HWALL						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_EXECUTE |			\
	CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP |	\
	CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP |		\
	CHERI_PERM_SEAL | CHERI_PERM_CCALL | CHERI_PERM_UNSEAL |	\
	CHERI_PERM_SYSTEM_REGS | CHERI_PERM_SET_CID)

/*
 * vm_prot_t to capability permission bits
 */
#define	CHERI_PERMS_PROT2PERM_READ					\
	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define	CHERI_PERMS_PROT2PERM_WRITE					\
	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |			\
	 CHERI_PERM_STORE_LOCAL_CAP)
#define	CHERI_PERMS_PROT2PERM_EXEC					\
	(CHERI_PERM_EXECUTE | CHERI_PERMS_PROT2PERM_READ)

/*
 * Basic userspace permission mask; CHERI_PERM_EXECUTE will be added for
 * executable capabilities ($pcc); CHERI_PERM_STORE, CHERI_PERM_STORE_CAP,
 * and CHERI_PERM_STORE_LOCAL_CAP will be added for data permissions ($ddc).
 *
 * All user software permissions are included along with
 * CHERI_PERM_SYSCALL.  CHERI_PERM_CHERIABI_VMMAP will be added for
 * permissions returned from mmap().
 *
 * No variation required between 256-bit and 128-bit CHERI.
 */
#define	CHERI_PERMS_USERSPACE						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |	\
	CHERI_PERM_CCALL | (CHERI_PERMS_SWALL & ~CHERI_PERM_CHERIABI_VMMAP))

#define	CHERI_PERMS_USERSPACE_CODE					\
	(CHERI_PERMS_USERSPACE | CHERI_PERM_EXECUTE)

#define	CHERI_PERMS_USERSPACE_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

#define	CHERI_PERMS_USERSPACE_DATA					\
	(CHERI_PERMS_USERSPACE | CHERI_PERM_STORE |			\
	CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP)

/*
 * Corresponding permission masks for kernel code and data; these are
 * currently a bit broad, and should be narrowed over time as the kernel
 * becomes more capability-aware.
 */
#define	CHERI_PERMS_KERNEL						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)	\

#define	CHERI_PERMS_KERNEL_CODE						\
	(CHERI_PERMS_KERNEL | CHERI_PERM_EXECUTE | CHERI_PERM_SYSTEM_REGS)

#define	CHERI_PERMS_KERNEL_DATA						\
	(CHERI_PERMS_KERNEL | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |	\
	CHERI_PERM_STORE_LOCAL_CAP)

#define	CHERI_PERMS_KERNEL_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

/*
 * The CHERI object-type space is split between userspace and kernel,
 * permitting kernel object references to be delegated to userspace (if
 * desired).  Currently, we provide 17 bits of namespace to each, with the top
 * bit set for kernel object types, but it is easy to imagine other splits.
 * User and kernel software should be written so as to not place assumptions
 * about the specific values used here, as they may change.
 */
#define	CHERI_OTYPE_BITS	(18)
#define	CHERI_OTYPE_USER_MIN	(0)
#define	CHERI_OTYPE_USER_MAX	((1 << (CHERI_OTYPE_BITS - 1)) - 1)
#define	CHERI_OTYPE_KERN_MIN	(1 << (CHERI_OTYPE_BITS - 1))
#define	CHERI_OTYPE_KERN_MAX	((1 << CHERI_OTYPE_BITS) - 1)
#define	CHERI_OTYPE_KERN_FLAG	(1 << (CHERI_OTYPE_BITS - 1))
#define	CHERI_OTYPE_ISKERN(x)	(((x) & CHERI_OTYPE_KERN_FLAG) != 0)
#define	CHERI_OTYPE_ISUSER(x)	(!(CHERI_OTYPE_ISKERN(x)))

/* Reserved CHERI object types: */
#define	CHERI_OTYPE_UNSEALED	(-1l)
#define	CHERI_OTYPE_SENTRY	(-2l)

/*
 * When performing a userspace-to-userspace CCall, capability flow-control
 * checks normally prevent local capabilities from being delegated.  This can
 * be disabled on call (but not return) by using an object type with the 22nd
 * bit set -- combined with a suitable selector on the CCall instruction to
 * ensure that this behaviour is intended.
 */
#define	CHERI_OTYPE_LOCALOK_SHIFT	(CHERI_OTYPE_BITS - 2)
#define	CHERI_OTYPE_LOCALOK_FLAG	(1 << CHERI_OTYPE_LOCALOK_SHIFT
#define	CHERI_OTYPE_IS_LOCALOK(x)	(((x) & CHERI_OTYPE_LOCALOK_FLAG) != 0)

/*
 * A blend of hardware and software allocation of capability registers.
 * Ideally, this list wouldn't exist here, but be purely in the assembler.
 */
#define	CHERI_CR_C0	0	/*   MIPS fetch/load/store capability. */
#define	CHERI_CR_DDC	CHERI_CR_C0
#define	CHERI_CR_C1	1
#define	CHERI_CR_C2	2
#define	CHERI_CR_C3	3
#define	CHERI_CR_C4	4
#define	CHERI_CR_C5	5
#define	CHERI_CR_C6	6
#define	CHERI_CR_C7	7
#define	CHERI_CR_C8	8
#define	CHERI_CR_C9	9
#define	CHERI_CR_C10	10
#define	CHERI_CR_C11	11
#define	CHERI_CR_STC	CHERI_CR_C11
#define	CHERI_CR_C12	12
#define	CHERI_CR_C13	13
#define	CHERI_CR_C14	14
#define	CHERI_CR_C15	15
#define	CHERI_CR_C16	16
#define	CHERI_CR_C17	17
#define	CHERI_CR_C18	18
#define	CHERI_CR_C19	19
#define	CHERI_CR_C20	20
#define	CHERI_CR_C21	21
#define	CHERI_CR_C22	22
#define	CHERI_CR_C23	23
#define	CHERI_CR_C24	24
#define	CHERI_CR_C25	25
#define	CHERI_CR_C26	26
#define	CHERI_CR_IDC	CHERI_CR_C26
#define	CHERI_CR_C27	27
#define	CHERI_CR_C28	28
#define	CHERI_CR_C29	29
#define	CHERI_CR_C30	30
#define	CHERI_CR_C31	31

/*
 * Offsets of registers in struct cheri_kframe -- must match the definition in
 * cheri.h.
 */
#define	CHERIKFRAME_OFF_C17	0
#define	CHERIKFRAME_OFF_C18	1
#define	CHERIKFRAME_OFF_C19	2
#define	CHERIKFRAME_OFF_C20	3
#define	CHERIKFRAME_OFF_C21	4
#define	CHERIKFRAME_OFF_C22	5
#define	CHERIKFRAME_OFF_C23	6
#define	CHERIKFRAME_OFF_C24	7
#define	CHERIKFRAME_OFF_C26	8
#define	CHERIKFRAME_OFF_PCC	9
#define	CHERIKFRAME_OFF_STC	10


/*
 * List of CHERI capability cause code constants, which are used to
 * characterise various CP2 exceptions.
 */
#define	CHERI_EXCCODE_NONE		0x00
#define	CHERI_EXCCODE_LENGTH		0x01
#define	CHERI_EXCCODE_TAG		0x02
#define	CHERI_EXCCODE_SEAL		0x03
#define	CHERI_EXCCODE_TYPE		0x04
#define	CHERI_EXCCODE_CALL		0x05
#define	CHERI_EXCCODE_RETURN		0x06
#define	CHERI_EXCCODE_UNDERFLOW		0x07
#define	CHERI_EXCCODE_USER_PERM		0x08
#define	CHERI_EXCCODE_PERM_USER		CHERI_EXCCODE_USER_PERM
#define	CHERI_EXCCODE_MMUSTORE		0x09
#define	CHERI_EXCCODE_TLBSTORE		CHERI_EXCCODE_MMUSTORE
#define	CHERI_EXCCODE_IMPRECISE		0x0a
#define	_CHERI_EXCCODE_RESERVED0b	0x0b
#define	_CHERI_EXCCODE_RESERVED0c	0x0c
#define	_CHERI_EXCCODE_RESERVED0d	0x0d
#define	_CHERI_EXCCODE_RESERVED0e	0x0e
#define	_CHERI_EXCCODE_RESERVED0f	0x0f
#define	CHERI_EXCCODE_GLOBAL		0x10
#define	CHERI_EXCCODE_PERM_EXECUTE	0x11
#define	CHERI_EXCCODE_PERM_LOAD		0x12
#define	CHERI_EXCCODE_PERM_STORE	0x13
#define	CHERI_EXCCODE_PERM_LOADCAP	0x14
#define	CHERI_EXCCODE_PERM_STORECAP	0x15
#define	CHERI_EXCCODE_STORE_LOCALCAP	0x16
#define	CHERI_EXCCODE_PERM_SEAL		0x17
#define	CHERI_EXCCODE_SYSTEM_REGS	0x18
#define	CHERI_EXCCODE_PERM_CCALL	0x19
#define	CHERI_EXCCODE_CCALL_IDC		0x1a
#define	CHERI_EXCCODE_PERM_UNSEAL	0x1b
#define	CHERI_EXCCODE_PERM_SET_CID	0x1c
#define	_CHERI_EXCCODE_RESERVED1d	0x1d
#define	_CHERI_EXCCODE_RESERVED1e	0x1e
#define	_CHERI_EXCCODE_RESERVED1f	0x1f

/*
 * User-defined CHERI exception codes are numbered 128...255.
 */
#define	CHERI_EXCCODE_SW_BASE		0x80

/*
 * How to turn the cause register into an exception code and register number.
 */
#define	CHERI_CAPCAUSE_EXCCODE_MASK	0xff00
#define	CHERI_CAPCAUSE_EXCCODE_SHIFT	8
#define	CHERI_CAPCAUSE_REGNUM_MASK	0xff
#define	CHERI_CAPCAUSE_EXCCODE(capcause)				\
	(((capcause) & CHERI_CAPCAUSE_EXCCODE_MASK) >>			\
	    CHERI_CAPCAUSE_EXCCODE_SHIFT)
#define	CHERI_CAPCAUSE_REGNUM(capcause)					\
	((capcause) & CHERI_CAPCAUSE_REGNUM_MASK)

/*
 * Location of the CHERI CCall/CReturn software-path exception vector.
 */
#define	CHERI_CCALL_EXC_VEC	MIPS_KSEG0((intptr_t)(int32_t)0x80000280)

#endif /* _MIPS_INCLUDE_CHERIREG_H_ */
// CHERI CHANGES START
// {
//   "updated": 20200706,
//   "target_type": "header",
//   "changes_purecap": [
//     "pointer_as_integer",
//     "support"
//   ]
// }
// CHERI CHANGES END
