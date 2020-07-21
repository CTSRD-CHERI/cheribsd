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

#ifndef __SYS_CHERIREG_H__
#define	__SYS_CHERIREG_H__

#include <machine/cherireg.h>

/* Machine-independent capability field values. */

/*
 * The kernel snags one of the software-defined permissions for the purposes
 * of authorising system calls from $pcc.  This is a bit of an oddity:
 * normally, we check permissions on data capabilities, not code capabilities,
 * but aligns with 'privilege' checks: e.g., $epcc access.  We may wish to
 * switch to another model, such as having userspace register one or more
 * class capabilities as suitable for system-call use.
 */
#define	CHERI_PERM_SYSCALL			CHERI_PERM_SW0

/*
 * Use another software-defined permission to restrict the ability to change
 * the page mapping underlying a capability.  This can't be the same
 * permission bit as CHERI_PERM_SYSCALL because $pcc should not confer the
 * right rewrite or remap executable memory.
 */
#define	CHERI_PERM_CHERIABI_VMMAP		CHERI_PERM_SW1

/*
 * Definition for a highly privileged kernel capability able to name the
 * entire address space, and suitable to derive all other kernel-related
 * capabilities from, including sealing capabilities.
 */
#define	CHERI_CAP_KERN_PERMS						\
	(CHERI_PERMS_SWALL | CHERI_PERMS_HWALL)
#define	CHERI_CAP_KERN_BASE		0x0
#define	CHERI_CAP_KERN_LENGTH		0xffffffffffffffff
#define	CHERI_CAP_KERN_OFFSET		0x0

/*
 * Definition for userspace "unprivileged" capabilities able to name the user
 * portion of the address space.
 */
#define	CHERI_CAP_USER_CODE_PERMS	CHERI_PERMS_USERSPACE_CODE
#define	CHERI_CAP_USER_CODE_BASE	VM_MINUSER_ADDRESS
#define	CHERI_CAP_USER_CODE_LENGTH	(VM_MAXUSER_ADDRESS - VM_MINUSER_ADDRESS)
#define	CHERI_CAP_USER_CODE_OFFSET	0x0

#define	CHERI_CAP_USER_DATA_PERMS	CHERI_PERMS_USERSPACE_DATA
#define	CHERI_CAP_USER_DATA_BASE	VM_MINUSER_ADDRESS
#define	CHERI_CAP_USER_DATA_LENGTH	(VM_MAXUSER_ADDRESS - VM_MINUSER_ADDRESS)
#define	CHERI_CAP_USER_DATA_OFFSET	0x0

#define	CHERI_CAP_USER_MMAP_PERMS					\
	(CHERI_PERMS_USERSPACE_DATA | CHERI_PERMS_USERSPACE_CODE |	\
	CHERI_PERM_CHERIABI_VMMAP)
/* Start at 256MB to avoid low PC values in sandboxes */
#define	CHERI_CAP_USER_MMAP_BASE	(VM_MINUSER_ADDRESS + 0x10000000)
#define	CHERI_CAP_USER_MMAP_LENGTH					\
    (VM_MAXUSER_ADDRESS - CHERI_CAP_USER_MMAP_BASE)
#define	CHERI_CAP_USER_MMAP_OFFSET	0x0

/*
 * Root sealing capability for all userspace object capabilities.  This is
 * made available to userspace via a sysarch(2).
 */
#define	CHERI_SEALCAP_USERSPACE_PERMS	CHERI_PERMS_USERSPACE_SEALCAP
#define	CHERI_SEALCAP_USERSPACE_BASE	CHERI_OTYPE_USER_MIN
#define	CHERI_SEALCAP_USERSPACE_LENGTH	\
    (CHERI_OTYPE_USER_MAX - CHERI_OTYPE_USER_MIN + 1)
#define	CHERI_SEALCAP_USERSPACE_OFFSET	0x0

/*
 * Root sealing capability for kernel managed objects.
 */
#define	CHERI_SEALCAP_KERNEL_PERMS	CHERI_PERMS_KERNEL_SEALCAP
#define CHERI_SEALCAP_KERNEL_BASE	CHERI_OTYPE_KERN_MIN
#define	CHERI_SEALCAP_KERNEL_LENGTH	\
    (CHERI_OTYPE_KERN_MAX - CHERI_OTYPE_KERN_MIN + 1)
#define	CHERI_SEALCAP_KERNEL_OFFSET	0x0

/* Reserved CHERI object types: */
#define	CHERI_OTYPE_UNSEALED	(-1l)
#define	CHERI_OTYPE_SENTRY	(-2l)

#if __has_feature(capabilities)
#define	CHERI_REPRESENTABLE_LENGTH(len) \
	__builtin_cheri_round_representable_length(len)
#define	CHERI_REPRESENTABLE_ALIGNMENT_MASK(len) \
	__builtin_cheri_representable_alignment_mask(len)
#else
#define	CHERI_REPRESENTABLE_LENGTH(len) (len)
#define	CHERI_REPRESENTABLE_ALIGNMENT_MASK(len) UINT64_MAX
#endif

/* Provide macros to make it easier to work with the raw CRAM/CRRL results: */
#define	CHERI_REPRESENTABLE_ALIGNMENT(len) \
	(~CHERI_REPRESENTABLE_ALIGNMENT_MASK(len) + 1)
#define	CHERI_REPRESENTABLE_BASE(base, len) \
	((base) & CHERI_REPRESENTABLE_ALIGNMENT_MASK(len))

/*
 * In the current encoding sealed and unsealed capabilities have the same
 * alignment constraints.
 */
#define	CHERI_SEALABLE_LENGTH(len)	\
	CHERI_REPRESENTABLE_LENGTH(len)
#define	CHERI_SEALABLE_ALIGNMENT_MASK(len)	\
	CHERI_REPRESENTABLE_ALIGNMENT_MASK(len)
#define	CHERI_SEALABLE_ALIGNMENT(len)	\
	CHERI_REPRESENTABLE_ALIGNMENT(len)
#define	CHERI_SEALABLE_BASE(base, len)	\
	CHERI_REPRESENTABLE_BASE(base, len)

/* A mask for the lower bits, i.e. the negated alignment mask */
#define	CHERI_SEAL_ALIGN_MASK(l)	~(CHERI_SEALABLE_ALIGNMENT_MASK(l))
#define	CHERI_ALIGN_MASK(l)		~(CHERI_REPRESENTABLE_ALIGNMENT_MASK(l))

/*
 * TODO: avoid using these since count leading/trailing zeroes is expensive on
 * BERI/CHERI
 */
#define	CHERI_ALIGN_SHIFT(l)	\
	__builtin_ctzll(CHERI_REPRESENTABLE_ALIGNMENT_MASK(l))
#define	CHERI_SEAL_ALIGN_SHIFT(l)	\
	__builtin_ctzll(CHERI_SEALABLE_ALIGNMENT_MASK(l))

#endif /* !__SYS_CHERIREG_H__ */
