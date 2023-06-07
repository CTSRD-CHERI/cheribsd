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
 *
 * This permission was historically named CHERI_PERM_CHERIABI_VMMAP.
 */
#define	CHERI_PERM_SW_VMEM			CHERI_PERM_SW1
#define	CHERI_PERM_CHERIABI_VMMAP \
    _Pragma("GCC warning \"CHERI_PERM_CHERIABI_VMMAP is deprecated, use CHERI_PERM_SW_VMEM\"") \
    CHERI_PERM_SW_VMEM

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

#define	CHERI_CAP_USER_RODATA_PERMS	CHERI_PERMS_USERSPACE_RODATA

/*
 * Root sealing capability for all userspace object capabilities.
 */
#define	CHERI_SEALCAP_USERSPACE_PERMS	CHERI_PERMS_USERSPACE_SEALCAP
#define	CHERI_SEALCAP_USERSPACE_BASE	CHERI_OTYPE_USER_MIN
#define	CHERI_SEALCAP_USERSPACE_LENGTH	\
    (CHERI_OTYPE_USER_MAX - CHERI_OTYPE_USER_MIN + 1)
#define	CHERI_SEALCAP_USERSPACE_OFFSET	0x0

/*
 * Definition for mapping vm_prot_t to capability permission
 */
#define	CHERI_PROT2PERM_READ_PERMS	CHERI_PERMS_PROT2PERM_READ
#define	CHERI_PROT2PERM_WRITE_PERMS	CHERI_PERMS_PROT2PERM_WRITE
#define	CHERI_PROT2PERM_EXEC_PERMS	CHERI_PERMS_PROT2PERM_EXEC
#define	CHERI_PROT2PERM_MASK						\
    (CHERI_PROT2PERM_READ_PERMS | CHERI_PROT2PERM_WRITE_PERMS |		\
    CHERI_PROT2PERM_EXEC_PERMS)

/*
 * Root sealing capability for kernel managed objects.
 */
#define	CHERI_SEALCAP_KERNEL_PERMS	CHERI_PERMS_KERNEL_SEALCAP
#define CHERI_SEALCAP_KERNEL_BASE	CHERI_OTYPE_KERN_MIN
#define	CHERI_SEALCAP_KERNEL_LENGTH	\
    (CHERI_OTYPE_KERN_MAX - CHERI_OTYPE_KERN_MIN + 1)
#define	CHERI_SEALCAP_KERNEL_OFFSET	0x0

/*
 * Sealing capability for capability pairs returned by cosetup(2).
 */
#define	CHERI_SEALCAP_SWITCHER_PERMS	CHERI_PERMS_KERNEL_SEALCAP
#define	CHERI_SEALCAP_SWITCHER_BASE	CHERI_OTYPE_KERN_MIN + 1
#define	CHERI_SEALCAP_SWITCHER_LENGTH	1
#define	CHERI_SEALCAP_SWITCHER_OFFSET	0x0

/*
 * Sealing capability for capabilities returned by coregister(2)/colookup(2).
 */
#define	CHERI_SEALCAP_SWITCHER2_PERMS	CHERI_PERMS_KERNEL_SEALCAP
#define	CHERI_SEALCAP_SWITCHER2_BASE	CHERI_OTYPE_KERN_MIN + 2
#define	CHERI_SEALCAP_SWITCHER2_LENGTH	1
#define	CHERI_SEALCAP_SWITCHER2_OFFSET	0x0

#endif /* !__SYS_CHERIREG_H__ */
