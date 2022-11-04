/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
 * Copyright (c) 2016-2020 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
 *
 * $FreeBSD$
 */
#ifndef _ARM64_INCLUDE_CHERIREG_H_
#define	_ARM64_INCLUDE_CHERIREG_H_

#define	CHERICAP_SIZE   16
#define	CHERICAP_SHIFT	4

/*
 * CHERI ISA-defined constants for capabilities -- suitable for inclusion from
 * assembly source code.
 */
#define	CHERI_PERM_GLOBAL			(1 << 0)	/* 0x00000001 */
#define	CHERI_PERM_EXECUTIVE			(1 << 1)	/* 0x00000002 */
#define	CHERI_PERM_SW0				(1 << 2)	/* 0x00000004 */
#define	CHERI_PERM_SW1				(1 << 3)	/* 0x00000008 */
#define	CHERI_PERM_SW2				(1 << 4)	/* 0x00000010 */
#define	CHERI_PERM_SW3				(1 << 5)	/* 0x00000020 */
#define	CHERI_PERM_MUTABLE_LOAD			(1 << 6)	/* 0x00000040 */
#define	CHERI_PERM_COMPARTMENT_ID		(1 << 7)	/* 0x00000080 */
#define	CHERI_PERM_BRANCH_SEALED_PAIR		(1 << 8)	/* 0x00000100 */
#define	CHERI_PERM_CCALL			CHERI_PERM_BRANCH_SEALED_PAIR
#define	CHERI_PERM_SYSTEM			(1 << 9)	/* 0x00000200 */
#define	CHERI_PERM_SYSTEM_REGS			CHERI_PERM_SYSTEM
#define	CHERI_PERM_UNSEAL			(1 << 10)	/* 0x00000400 */
#define	CHERI_PERM_SEAL				(1 << 11)	/* 0x00000800 */
#define	CHERI_PERM_STORE_LOCAL_CAP		(1 << 12)	/* 0x00001000 */
#define	CHERI_PERM_STORE_CAP			(1 << 13)	/* 0x00002000 */
#define	CHERI_PERM_LOAD_CAP			(1 << 14)	/* 0x00004000 */
#define	CHERI_PERM_EXECUTE			(1 << 15)	/* 0x00008000 */
#define	CHERI_PERM_STORE			(1 << 16)	/* 0x00010000 */
#define	CHERI_PERM_LOAD				(1 << 17)	/* 0x00020000 */

/*
 * Macros defining initial permission sets:
 *
 * CHERI_PERMS_SWALL: Mask of all available software-defined permissions
 * CHERI_PERMS_HWALL: Mask of all available hardware-defined permissions
 */
#define	CHERI_PERMS_SWALL						\
	(CHERI_PERM_SW0 | CHERI_PERM_SW1 | CHERI_PERM_SW2 |		\
	CHERI_PERM_SW3)

#define	CHERI_PERMS_HWALL						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_EXECUTIVE |			\
	CHERI_PERM_MUTABLE_LOAD | CHERI_PERM_COMPARTMENT_ID |		\
	CHERI_PERM_BRANCH_SEALED_PAIR | CHERI_PERM_SYSTEM |		\
	CHERI_PERM_UNSEAL | CHERI_PERM_SEAL | 				\
	CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_STORE_CAP |		\
	CHERI_PERM_LOAD_CAP | CHERI_PERM_EXECUTE | CHERI_PERM_STORE |	\
	CHERI_PERM_LOAD)

/*
 * vm_prot_t to capability permission bits
 */
#define	CHERI_PERMS_PROT2PERM_READ					\
	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP | CHERI_PERM_MUTABLE_LOAD)
#define	CHERI_PERMS_PROT2PERM_WRITE					\
	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |			\
	 CHERI_PERM_STORE_LOCAL_CAP)
#define	CHERI_PERMS_PROT2PERM_EXEC					\
	(CHERI_PERM_EXECUTE | CHERI_PERM_EXECUTIVE |			\
	 CHERI_PERMS_PROT2PERM_READ)

/*
 * Basic userspace permission mask; CHERI_PERM_EXECUTE will be added for
 * executable capabilities (pcc); CHERI_PERM_STORE, CHERI_PERM_STORE_CAP,
 * and CHERI_PERM_STORE_LOCAL_CAP will be added for data permissions (ddc).
 */
#define	CHERI_PERMS_USERSPACE						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |	\
	CHERI_PERM_BRANCH_SEALED_PAIR |					\
	(CHERI_PERMS_SWALL & ~CHERI_PERM_SW_VMEM))

#define	CHERI_PERMS_USERSPACE_CODE					\
	(CHERI_PERMS_USERSPACE | CHERI_PERM_EXECUTE |			\
	CHERI_PERM_EXECUTIVE | CHERI_PERM_MUTABLE_LOAD)

#define	CHERI_PERMS_USERSPACE_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

#define	CHERI_PERMS_USERSPACE_DATA					\
	(CHERI_PERMS_USERSPACE | CHERI_PERM_STORE |			\
	CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP |		\
	CHERI_PERM_MUTABLE_LOAD)

#define	CHERI_PERMS_USERSPACE_RODATA					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD)

/*
 * Corresponding permission masks for kernel code and data; these are
 * currently a bit broad, and should be narrowed over time as the kernel
 * becomes more capability-aware.
 */
#define	CHERI_PERMS_KERNEL						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |	\
		CHERI_PERM_MUTABLE_LOAD)

#define	CHERI_PERMS_KERNEL_CODE						\
	(CHERI_PERMS_KERNEL | CHERI_PERM_EXECUTE |			\
	CHERI_PERM_SYSTEM_REGS | CHERI_PERM_EXECUTIVE)

#define	CHERI_PERMS_KERNEL_DATA						\
	(CHERI_PERMS_KERNEL | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |	\
	CHERI_PERM_STORE_LOCAL_CAP)

#define	CHERI_PERMS_KERNEL_RODATA					\
	(CHERI_PERMS_KERNEL)

#define	CHERI_PERMS_KERNEL_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

#define	CHERI_PERMS_KERNEL_DATA_NOCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE)

/*
 * The CHERI object-type space is split between userspace and kernel,
 * permitting kernel object references to be delegated to userspace (if
 * desired).  Currently, we provide 13 bits of namespace to each, with the top
 * bit set for kernel object types, but it is easy to imagine other splits.
 * User and kernel software should be written so as to not place assumptions
 * about the specific values used here, as they may change.
 *
 * On Morello otype 0 is unsealed, and 1-3 are reserved.
 */
#define	CHERI_OTYPE_BITS	(14)
#define	CHERI_OTYPE_USER_MIN	(4)
#define	CHERI_OTYPE_USER_MAX	((1 << (CHERI_OTYPE_BITS - 1)) - 1)
#define	CHERI_OTYPE_KERN_MIN	(1 << (CHERI_OTYPE_BITS - 1))
#define	CHERI_OTYPE_KERN_MAX	((1 << CHERI_OTYPE_BITS) - 1)
#define	CHERI_OTYPE_KERN_FLAG	(1 << (CHERI_OTYPE_BITS - 1))
#define	CHERI_OTYPE_ISKERN(x)	(((x) & CHERI_OTYPE_KERN_FLAG) != 0)
#define	CHERI_OTYPE_ISUSER(x)	(!(CHERI_OTYPE_ISKERN(x)))

/* Reserved CHERI object types: */
#define	CHERI_OTYPE_UNSEALED	(0l)
#define	CHERI_OTYPE_SENTRY	(1l)

#endif /* _ARM64_INCLUDE_CHERIREG_H_ */
