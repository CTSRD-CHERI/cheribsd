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
#include <sys/elf.h>
#include <sys/imgact.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

/*
 * Helper routines to construct initial capabilities for CheriABI
 * programs.
 */

/*
 * Construct a capability stack pointer for the main thread.
 */
void * __capability
cheri_exec_stack_pointer(struct image_params *imgp, uintcap_t stack)
{
	vm_offset_t stackbase, stacktop;
	size_t stacklen;
	char * __capability csp;

	KASSERT(__builtin_is_aligned(stack, sizeof(void * __capability)),
	    ("CheriABI stack pointer not properly aligned"));

	/*
	 * Restrict the stack capability to the maximum region allowed
	 * for this process and adjust csp accordingly.
	 */
	stackbase = (vaddr_t)imgp->proc->p_vmspace->vm_maxsaddr;
	stacktop = (__cheri_addr vaddr_t)stack;
	KASSERT(stacktop > stackbase,
	    ("top of stack 0x%lx is below stack base 0x%lx", stacktop,
	    stackbase));
	stacklen = stacktop - stackbase;

	/*
	 * Round the stack down as required to make it representable.
	 */
	stacklen = rounddown2(stacklen,
	    CHERI_REPRESENTABLE_ALIGNMENT(stacklen));
	KASSERT(stackbase == CHERI_REPRESENTABLE_BASE(stackbase, stacklen),
	    ("%s: rounded base (0x%zx) != base (0x%zx)", __func__,
		CHERI_REPRESENTABLE_BASE(stackbase, stacklen), stackbase));
	csp = cheri_setaddress((void * __capability)stack, stackbase);
	csp = cheri_setbounds(csp, stacklen);
	return (csp + stacklen);
}

/*
 * Build a capability to describe the MMAP'able space from the end of
 * the program's heap to the bottom of the stack.
 *
 * XXX: We could probably use looser bounds and rely on the VM system
 * to manage the address space via vm_map instead of the more complex
 * calculations here.
 */
void
cheri_set_mmap_capability(struct thread *td, struct image_params *imgp,
	void * __capability csp)
{
	vm_offset_t map_base, stack_base, text_end;
	size_t map_length;

	stack_base = cheri_getbase(csp);
	text_end = roundup2(imgp->end_addr,
	    CHERI_SEALABLE_ALIGNMENT(imgp->end_addr - imgp->start_addr));

	/*
	 * Less confusing rounded up to a page and 256-bit
	 * requires no other rounding.
	 */
	text_end = roundup2(text_end, PAGE_SIZE);
	KASSERT(text_end <= stack_base,
	    ("text_end 0x%zx > stack_base 0x%lx", text_end, stack_base));

	map_base = (text_end == stack_base) ?
	    CHERI_CAP_USER_MMAP_BASE :
	    roundup2(text_end,
		CHERI_REPRESENTABLE_ALIGNMENT(stack_base - text_end));
	KASSERT(map_base < stack_base,
	    ("map_base 0x%zx >= stack_base 0x%lx", map_base, stack_base));
	map_length = stack_base - map_base;
	map_length = rounddown2(map_length,
	    CHERI_REPRESENTABLE_ALIGNMENT(map_length));

	/*
	 * Use cheri_capability_build_user_rwx so mmap() can return
	 * appropriate permissions derived from a single capability.
	 */
	td->td_cheri_mmap_cap = cheri_capability_build_user_rwx(
	    CHERI_CAP_USER_MMAP_PERMS, map_base, map_length,
	    CHERI_CAP_USER_MMAP_OFFSET);
	KASSERT(cheri_getperm(td->td_cheri_mmap_cap) &
	    CHERI_PERM_CHERIABI_VMMAP,
	    ("%s: mmap() cap lacks CHERI_PERM_CHERIABI_VMMAP", __func__));
}

void * __capability
cheri_exec_pcc(struct image_params *imgp)
{
	vm_offset_t code_start, code_end;
	size_t code_length;

	/*
	 * If we are executing a static binary we use end_addr as the
	 * end of the text segment. If $pcc is the start of rtld we
	 * use interp_end.  If we are executing rtld directly we can
	 * use end_addr to find the end of the rtld mapping.
	 */
	if (imgp->interp_end != 0) {
		code_start = imgp->reloc_base;
		code_end = imgp->interp_end;
	} else {
		code_start = imgp->start_addr;
		code_end = imgp->end_addr;
	}

	/* Ensure CHERI128 representability */
	code_length = code_end - code_start;
	code_start = CHERI_REPRESENTABLE_BASE(code_start, code_length);
	code_length = CHERI_REPRESENTABLE_LENGTH(code_length);
	KASSERT(code_start + code_length >= code_end,
	    ("%s: truncated PCC", __func__));
	return (cheri_capability_build_user_code(CHERI_CAP_USER_CODE_PERMS,
	    code_start, code_length, imgp->entry_addr - code_start));
}

void * __capability
cheri_sigcode_capability(struct thread *td)
{
	struct sysentvec *sv;

	sv = td->td_proc->p_sysent;
	KASSERT(sv->sv_sigcode_base != 0,
	    ("CheriABI requires shared page for sigcode"));
	return (cheri_capability_build_user_code(CHERI_CAP_USER_CODE_PERMS,
	    sv->sv_sigcode_base, *sv->sv_szsigcode, 0));
}

void * __capability
cheri_auxv_capability(struct image_params *imgp, uintcap_t stack)
{
	void * __capability auxv;

	auxv = ((void * __capability * __capability)stack +
	    imgp->args->argc + 1 + imgp->args->envc + 1);
	return (cheri_setbounds(auxv, AT_COUNT * sizeof(Elf_Auxinfo)));
}
