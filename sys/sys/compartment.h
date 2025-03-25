/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#ifndef _SYS_COMPARTMENT_H_
#define	_SYS_COMPARTMENT_H_

#ifdef _KERNEL

#include <sys/_compartment.h>
#include <sys/malloc.h>
#include <sys/linker.h>
#include <sys/queue.h>

#ifdef CHERI_COMPARTMENTALIZE_KERNEL
#include <machine/compartment.h>

SYSCTL_DECL(_security_compartment);

struct thread;

struct compartment {
	u_long		 c_id;
	struct thread	*c_thread;
	vm_pointer_t	 c_kstack;
	vm_pointer_t	 c_kstackptr;
	TAILQ_ENTRY(compartment) c_next;	/* Next in a thread. */
	TAILQ_ENTRY(compartment) c_mnext;	/* Next with the same id. */
};

u_long compartment_id_create(const char *name, uintcap_t base,
    elf_object_t object);
void compartment_linkup0(struct compartment *compartment, struct thread *td);
struct compartment *compartment_create_for_thread(struct thread *td, u_long id);
void compartment_destroy(struct compartment *compartment);
void compartment_trampoline_destroy(uintptr_t func);
vm_pointer_t compartment_entry_stackptr(u_long id, int type);
void *compartment_entry_for_kernel(uintptr_t func);
void *compartment_entry(uintptr_t func);
void *executive_entry_for_kernel(uintptr_t func);
void *executive_get_function(uintptr_t func);

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_COMPARTMENT);
#endif
#else	/* CHERI_COMPARTMENTALIZE_KERNEL */
#define	COMPARTMENT_ENTRY(ret_type, name, args)				\
	ret_type							\
	COMPARTMENT_ENTRY_NAME(name) args

#define	EXECUTIVE_ENTRY(ret_type, name, args)				\
	ret_type							\
	EXECUTIVE_ENTRY_NAME(name) args
#endif

#endif	/* _KERNEL */

#endif	/* !_SYS_COMPARTMENT_H_ */
