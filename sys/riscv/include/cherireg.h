/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011-2018 Robert N. M. Watson
 * All rights reserved.
 * Copyright (c) 2020 John Baldwin
 *
 * Portions of this software were developed by SRI International and
 * the University of Cambridge Computer Laboratory under DARPA/AFRL
 * contract (FA8750-10-C-0237) ("CTSRD"), as part of the DARPA CRASH
 * research programme.
 *
 * Portions of this software were developed by SRI International and
 * the University of Cambridge Computer Laboratory (Department of
 * Computer Science and Technology) under DARPA contract
 * HR0011-18-C-0016 ("ECATS"), as part of the DARPA SSITH research
 * programme.
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

#ifndef _MACHINE_CHERIREG_H_
#define	_MACHINE_CHERIREG_H_

#define	CHERICAP_SIZE		__SIZEOF_CHERI_CAPABILITY__

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
#define	CHERI_PERM_INVOKE			(1 << 8)	/* 0x00000100 */
#define	CHERI_PERM_UNSEAL			(1 << 9)	/* 0x00000200 */
#define	CHERI_PERM_SYSTEM_REGS			(1 << 10)	/* 0x00000400 */
#define	CHERI_PERM_SET_CID			(1 << 11)	/* 0x00000800 */

/* User-defined permission bits. */
#define	CHERI_PERM_SW0			(1 << 15)	/* 0x00008000 */
#define	CHERI_PERM_SW1			(1 << 16)	/* 0x00010000 */
#define	CHERI_PERM_SW2			(1 << 17)	/* 0x00020000 */
#define	CHERI_PERM_SW3			(1 << 18)	/* 0x00040000 */

/*
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
	CHERI_PERM_SEAL | CHERI_PERM_INVOKE | CHERI_PERM_UNSEAL |	\
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
 * Hardware defines a kind of tripartite taxonomy: memory, type, and CID.
 * They're all squished together in the permission bits, so define masks
 * that give us a kind of "kind" for capabilities.  A capability may belong
 * to zero, one, or more than one of these.
 */

#define CHERI_PERMS_HWALL_MEMORY                                        \
	(CHERI_PERM_EXECUTE | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |   \
		CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |               \
		CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL)

#define CHERI_PERMS_HWALL_OTYPE	(CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

// TODO #define CHERI_PERMS_HWALL_CID	(CHERI_PERM_SETCID)

/*
 * Basic userspace permission mask; CHERI_PERM_EXECUTE will be added for
 * executable capabilities ($pcc); CHERI_PERM_STORE, CHERI_PERM_STORE_CAP,
 * and CHERI_PERM_STORE_LOCAL_CAP will be added for data permissions ($dcc).
 *
 * All user software permissions are included along with
 * CHERI_PERM_SYSCALL.  CHERI_PERM_SW_VMEM will be added for
 * permissions returned from mmap().
 */
#define	CHERI_PERMS_USERSPACE						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |	\
	CHERI_PERM_INVOKE | (CHERI_PERMS_SWALL & ~CHERI_PERM_SW_VMEM))

#define	CHERI_PERMS_USERSPACE_CODE					\
	(CHERI_PERMS_USERSPACE | CHERI_PERM_EXECUTE)

#define	CHERI_PERMS_USERSPACE_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

#define	CHERI_PERMS_USERSPACE_DATA					\
	(CHERI_PERMS_USERSPACE | CHERI_PERM_STORE |			\
	CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP)

#define	CHERI_PERMS_USERSPACE_RODATA					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD)

/*
 * Corresponding permission masks for kernel code and data; these are
 * currently a bit broad, and should be narrowed over time as the kernel
 * becomes more capability-aware.
 */
#define	CHERI_PERMS_KERNEL						\
	(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)	\

#define	CHERI_PERMS_KERNEL_CODE						\
	(CHERI_PERMS_KERNEL | CHERI_PERM_EXECUTE | CHERI_PERM_SYSTEM_REGS)

#define	CHERI_PERMS_KERNEL_DATA				       		\
	(CHERI_PERMS_KERNEL | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
	CHERI_PERM_STORE_LOCAL_CAP)

#define	CHERI_PERMS_KERNEL_RODATA			       		\
	(CHERI_PERMS_KERNEL)

#define	CHERI_PERMS_KERNEL_SEALCAP					\
	(CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL)

#define	CHERI_FLAGS_CAP_MODE	0x1

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
 * List of CHERI capability cause code constants.
 */
#define	CHERI_EXCCODE_NONE		0x00
#define	CHERI_EXCCODE_LENGTH		0x01
#define	CHERI_EXCCODE_TAG		0x02
#define	CHERI_EXCCODE_SEAL		0x03
#define	CHERI_EXCCODE_TYPE		0x04
#define	_CHERI_EXCCODE_RESERVED05	0x05
#define	_CHERI_EXCCODE_RESERVED06	0x06
#define	_CHERI_EXCCODE_RESERVED07	0x07
#define	CHERI_EXCCODE_USER_PERM		0x08
#define	CHERI_EXCCODE_PERM_USER		CHERI_EXCCODE_USER_PERM
#define	_CHERI_EXCCODE_RESERVED09	0x09
#define	CHERI_EXCCODE_IMPRECISE		0x0a
#define	CHERI_EXCCODE_UNALIGNED_BASE	0x0b
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
#define	CHERI_EXCCODE_PERM_CINVOKE	0x19
#define	_CHERI_EXCCODE_RESERVED1a	0x1a
#define	CHERI_EXCCODE_PERM_UNSEAL	0x1b
#define	CHERI_EXCCODE_PERM_SET_CID	0x1c
#define	_CHERI_EXCCODE_RESERVED1d	0x1d
#define	_CHERI_EXCCODE_RESERVED1e	0x1e
#define	_CHERI_EXCCODE_RESERVED1f	0x1f

#endif /* !_MACHINE_CHERIREG_H_ */
