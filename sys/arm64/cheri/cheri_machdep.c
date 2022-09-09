/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/devmap.h>
#include <sys/proc.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/frame.h>
#include <machine/pte.h>
#include <machine/vmparam.h>

void * __capability sentry_unsealcap;
void * __capability smccc_ddc_el0;
#ifdef __CHERI_PURE_CAPABILITY__
void *kernel_root_cap = (void *)(intcap_t)-1;
#endif

void __nosanitizecoverage
cheri_init_capabilities(void * __capability kroot)
{
	void * __capability ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_SEALCAP_KERNEL_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_SEALCAP_KERNEL_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_SEALCAP_KERNEL_PERMS);
	kernel_root_sealcap = ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_CAP_USER_DATA_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_CAP_USER_DATA_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_CAP_USER_DATA_PERMS |
	    CHERI_CAP_USER_CODE_PERMS | CHERI_PERM_SW_VMEM);
	userspace_root_cap = ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_SEALCAP_USERSPACE_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_SEALCAP_USERSPACE_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_SEALCAP_USERSPACE_PERMS);
	userspace_root_sealcap = ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_OTYPE_SENTRY);
	ctemp = cheri_setbounds(ctemp, 1);
	ctemp = cheri_andperm(ctemp, CHERI_PERM_GLOBAL | CHERI_PERM_UNSEAL);
	sentry_unsealcap = ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_SEALCAP_SWITCHER_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_SEALCAP_SWITCHER_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_SEALCAP_SWITCHER_PERMS);
	switcher_sealcap = ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_SEALCAP_SWITCHER2_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_SEALCAP_SWITCHER2_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_SEALCAP_SWITCHER2_PERMS);
	switcher_sealcap2 = ctemp;

	smccc_ddc_el0 = kroot;

	swap_restore_cap = kroot;

#ifdef __CHERI_PURE_CAPABILITY__
	ctemp = cheri_setaddress(kroot, VM_MAX_KERNEL_ADDRESS -
	    PMAP_MAPDEV_EARLY_SIZE);
	ctemp = cheri_setboundsexact(ctemp, PMAP_MAPDEV_EARLY_SIZE);
	ctemp = cheri_andperm(ctemp, CHERI_PERMS_KERNEL_DATA);
	devmap_init_capability(ctemp);

	kernel_root_cap = cheri_andperm(kroot,
	    ~(CHERI_PERM_SEAL | CHERI_PERM_UNSEAL));
#endif
}

void
hybridabi_thread_setregs(struct thread *td, unsigned long entry_addr)
{
	struct trapframe *tf;

	tf = td->td_frame;

	/* Set DDC to full user privilege. */
	tf->tf_ddc = (uintcap_t)cheri_capability_build_user_rwx(
	    CHERI_CAP_USER_DATA_PERMS | CHERI_PERM_SW_VMEM,
	    CHERI_CAP_USER_DATA_BASE, CHERI_CAP_USER_DATA_LENGTH,
	    CHERI_CAP_USER_DATA_OFFSET);

	/* Use 'entry_addr' as offset of PCC. */
	trapframe_set_elr(tf, (uintcap_t)cheri_capability_build_user_code(
	    td, CHERI_CAP_USER_CODE_PERMS, CHERI_CAP_USER_CODE_BASE,
	    CHERI_CAP_USER_CODE_LENGTH, entry_addr));
}
