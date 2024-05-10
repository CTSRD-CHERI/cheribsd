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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/compartment.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/tree.h>

#include <cheri/cheric.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>

#include <machine/compartment.h>
#include <machine/cpufunc.h>
#include <machine/elf.h>
#include <machine/md_var.h>

MALLOC_DEFINE(M_COMPARTMENT, "compartment", "kernel compartment");

SYSCTL_NODE(_security, OID_AUTO, compartment, CTLFLAG_RD, 0,
    "Compartment subsystem");
SYSCTL_NODE(_security_compartment, OID_AUTO, counters, CTLFLAG_RD, 0,
    "Counters for compartment trampolines");

#define	TRAMPOLINE_TYPE_COMPARTMENT_ENTRY	0
#define	TRAMPOLINE_TYPE_SUPERVISOR_ENTRY	1
#define	TRAMPOLINE_TYPE_MAX			TRAMPOLINE_TYPE_SUPERVISOR_ENTRY

unsigned long compartment_trampoline_counters[TRAMPOLINE_TYPE_MAX + 1];

SYSCTL_ULONG(_security_compartment_counters, OID_AUTO, compartment_entry,
    CTLFLAG_RW,
    &compartment_trampoline_counters[TRAMPOLINE_TYPE_COMPARTMENT_ENTRY], 0,
    "Number of compartment entry calls");

SYSCTL_ULONG(_security_compartment_counters, OID_AUTO, supervisor_entry,
    CTLFLAG_RW,
    &compartment_trampoline_counters[TRAMPOLINE_TYPE_SUPERVISOR_ENTRY], 0,
    "Number of supervisor entry calls");

struct compartment_trampoline {
	int		ct_compartment_id;
	int		ct_type;
	uintcap_t	ct_compartment_func;
	uintcap_t	ct_compartment_stackptr_func;
	RB_ENTRY(compartment_trampoline) ct_node;
	char		ct_code[] __subobject_use_container_bounds;
};

static int
compartment_trampoline_compare(struct compartment_trampoline *a,
    struct compartment_trampoline *b)
{

	return ((ptraddr_t)a->ct_compartment_func -
	    (ptraddr_t)b->ct_compartment_func);
}

RB_HEAD(compartment_tree, compartment_trampoline) compartment_trampolines =
    RB_INITIALIZER(&compartment_trampolines);
RB_GENERATE_STATIC(compartment_tree, compartment_trampoline, ct_node,
    compartment_trampoline_compare);

static struct mtx compartment_trampolines_lock;
MTX_SYSINIT(compartmenttrampolines, &compartment_trampolines_lock,
    "compartment_trampolines", MTX_DEF);

static void
compartment_linkup(struct compartment *compartment, int id, struct thread *td)
{

	compartment->c_id = id;
	compartment->c_thread = td;

	TAILQ_INSERT_HEAD(&compartment->c_thread->td_compartments, compartment,
	    c_next);
}

void
compartment_linkup0(struct compartment *compartment, vm_pointer_t stack,
    struct thread *td)
{

	compartment->c_kstack = stack;
	compartment->c_kstackptr = stack + kstack_pages * PAGE_SIZE;

	compartment_linkup(compartment, COMPARTMENT_KERNEL_ID, td);
}

static struct compartment *
compartment_create(int id)
{
	struct compartment *compartment;

	compartment = malloc(sizeof(*compartment), M_COMPARTMENT, M_WAITOK |
	    M_ZERO);

	if (!vm_compartment_new(compartment)) {
		panic("compartment_create unable to allocate stack");
	}

	compartment_linkup(compartment, id, curthread);

	return (compartment);
}

void
compartment_destroy(struct compartment *compartment)
{

	TAILQ_REMOVE(&compartment->c_thread->td_compartments, compartment,
	    c_next);
	vm_compartment_dispose(compartment);
	free(compartment, M_COMPARTMENT);
}

static struct compartment *
compartment_find(int id)
{
	struct compartment *compartment;

	TAILQ_FOREACH(compartment, &curthread->td_compartments, c_next) {
		if (compartment->c_id == id)
			break;
	}
	return (compartment);
}

vm_pointer_t
compartment_entry_stackptr(int id, int type)
{
	struct compartment *compartment;

	/*
	 * TODO: Make compartment_trampoline_counters actual atomic counters.
	 */
	if (compartment_trampoline_counters[type] < ULONG_MAX)
		compartment_trampoline_counters[type]++;

	compartment = compartment_find(id);
	if (compartment == NULL)
		compartment = compartment_create(id);
	return (compartment->c_kstackptr);
}

static struct compartment_trampoline *
compartment_trampoline_create(const module_t mod, int type, void *data,
    size_t size, uintcap_t func)
{
	struct compartment_trampoline *trampoline, *oldtrampoline;
	struct compartment_trampoline tmptrampoline;
	uintcap_t dstfunc;

	KASSERT((cheri_getperm(cheri_getpcc()) & CHERI_PERM_EXECUTIVE) != 0,
	    ("compartment_trampoline_create: PCC %#lp has invalid permissions",
	    (void *)cheri_getpcc()));

	if (mod != NULL) {
		dstfunc = module_capability(mod, func);
	} else {
		dstfunc = (intcap_t)cheri_kern_setaddress(cheri_getpcc(),
		    (intptr_t)func);
		dstfunc = cheri_andperm(dstfunc, cheri_getperm(func));
		dstfunc = cheri_capmode(dstfunc);
		dstfunc = cheri_sealentry(dstfunc);
	}

	tmptrampoline.ct_compartment_func = dstfunc;
	oldtrampoline = RB_FIND(compartment_tree, &compartment_trampolines,
	    &tmptrampoline);
	if (oldtrampoline != NULL) {
		trampoline = oldtrampoline;
		goto out;
	}

	/*
	 * TODO: Free the trampoline.
	 */
	if (mod != NULL) {
		trampoline = SUPERVISOR_EXIT(malloc_exec,
		    (size, M_COMPARTMENT, M_WAITOK | M_ZERO));
	} else {
		if (compartment_entries_length >= PAGE_SIZE *
		    COMPARTMENT_ENTRY_PAGES) {
			panic("compartment_trampoline_create: cannot allocate memory");
		}
		trampoline = (void *)(compartment_entries +
		    compartment_entries_length);
		compartment_entries_length += size;
	}

	memcpy(trampoline, data, size);

	trampoline->ct_compartment_func = dstfunc;
	trampoline->ct_type = type;
	ELF_STATIC_RELOC_LABEL(trampoline->ct_compartment_stackptr_func,
	    compartment_entry_stackptr);
	trampoline->ct_compartment_stackptr_func =
	    cheri_sealentry(trampoline->ct_compartment_stackptr_func);

	if (mod != NULL) {
		trampoline->ct_compartment_id = module_getid(mod);

		cpu_dcache_wb_range((vm_pointer_t)trampoline, (vm_size_t)size);
		cpu_icache_sync_range((vm_pointer_t)trampoline,
		    (vm_size_t)size);

		mtx_lock(&compartment_trampolines_lock);
	} else {
		trampoline->ct_compartment_id = COMPARTMENT_KERNEL_ID;
	}

	oldtrampoline = RB_INSERT(compartment_tree, &compartment_trampolines,
	    trampoline);
	KASSERT(oldtrampoline == NULL,
	    ("Trampoline for 0x%#lp already exists",
	    (void *)trampoline->ct_compartment_func));

	if (mod != NULL) {
		mtx_unlock(&compartment_trampolines_lock);
	}

out:
	func = (intcap_t)cheri_kern_setaddress(cheri_getpcc(),
	    (intptr_t)trampoline);
	/*
	 * XXXKW: The bounds cover both metadata and code of the trampoline to
	 * allow the code to access the metadata.
	 */
	func = cheri_kern_setbounds(func, size);
	func = (intcap_t)cheri_kern_setaddress(func,
	    (intptr_t)&trampoline->ct_code);
	func = cheri_capmode(func);
	func = cheri_sealentry(func);
	return ((void *)func);
}

void
compartment_trampoline_destroy(uintptr_t func)
{
	struct compartment_trampoline *trampoline;

	trampoline = __containerof((char (*)[])func,
	    struct compartment_trampoline, ct_code);
	free(trampoline, M_COMPARTMENT);
}

void *
compartment_call(uintptr_t func)
{

	return ((void *)cheri_sealentry(cheri_clearperm(func,
	    CHERI_PERM_EXECUTIVE)));
}

void *
compartment_entry_for_kernel(uintptr_t func)
{

	func = cheri_clearperm(func, CHERI_PERM_EXECUTIVE);
	return (compartment_trampoline_create(NULL,
	    TRAMPOLINE_TYPE_COMPARTMENT_ENTRY, compartment_entry_trampoline,
	    szcompartment_entry_trampoline, func));
}

SUPERVISOR_ENTRY(void *, compartment_entry_for_module, (const module_t mod,
    uintptr_t func))
{

	func = cheri_clearperm(func, CHERI_PERM_EXECUTIVE);
	return (compartment_trampoline_create(mod,
	    TRAMPOLINE_TYPE_COMPARTMENT_ENTRY, compartment_entry_trampoline,
	    szcompartment_entry_trampoline, func));
}

SUPERVISOR_ENTRY(void *, compartment_entry, (uintptr_t func))
{
	void *codeptr;
	module_t mod;

	MOD_SLOCK;

	mod = module_lookupbyptr((uintptr_t)func);
	if (mod == NULL)
		panic("compartment_entry: unable to find module");

	codeptr = SUPERVISOR_ENTRY_NAME(compartment_entry_for_module)(mod,
	    func);

	MOD_SUNLOCK;
	return (codeptr);
}

void *
supervisor_entry_for_kernel(uintptr_t func)
{

	KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
	    ("Supervisor entry capability %#lp has invalid permissions",
	     (void *)func));
	return (compartment_trampoline_create(NULL,
	    TRAMPOLINE_TYPE_SUPERVISOR_ENTRY, supervisor_entry_trampoline,
	    szsupervisor_entry_trampoline, func));
}

void *
supervisor_get_function(uintptr_t func)
{
	struct compartment_trampoline *trampoline;

	KASSERT((cheri_getperm(cheri_getpcc()) & CHERI_PERM_EXECUTIVE) != 0,
	    ("PCC %#lp has invalid permissions",
	    (void *)cheri_getpcc()));
	KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
	    ("Supervisor trampoline capability %#lp has invalid permissions",
	     (void *)func));

	trampoline = cheri_kern_setaddress(cheri_getpcc(), func - 1);
	trampoline = __containerof((char (*)[])trampoline,
	    struct compartment_trampoline, ct_code);
	KASSERT(trampoline->ct_type == TRAMPOLINE_TYPE_SUPERVISOR_ENTRY,
	    ("Invalid trampoline type"));

	return ((void *)trampoline->ct_compartment_func);
}
