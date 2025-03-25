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
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
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

unsigned long compartment_trampoline_counters[TRAMPOLINE_TYPE_MAX + 1];

SYSCTL_ULONG(_security_compartment_counters, OID_AUTO, compartment_entry,
    CTLFLAG_RW,
    &compartment_trampoline_counters[TRAMPOLINE_TYPE_COMPARTMENT_ENTRY], 0,
    "Number of compartment entry calls");

SYSCTL_ULONG(_security_compartment_counters, OID_AUTO, executive_entry,
    CTLFLAG_RW,
    &compartment_trampoline_counters[TRAMPOLINE_TYPE_EXECUTIVE_ENTRY], 0,
    "Number of executive entry calls");

struct compartment_trampoline {
	u_long		ct_compartment_id;
	int		ct_type;
	uintcap_t	ct_compartment_func;
	uintcap_t	ct_compartment_stackptr_func;
	RB_ENTRY(compartment_trampoline) ct_node;
	char		ct_code[] __subobject_use_container_bounds;
};

static u_long compartment_lastid = COMPARTMENT_KERNEL_ID;

static int
compartment_trampoline_compare(struct compartment_trampoline *a,
    struct compartment_trampoline *b)
{

	EXECUTIVE_ASSERT();

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

u_long
compartment_id_create(void)
{

	atomic_add_long(&compartment_lastid, 1);
	return (compartment_lastid);
}

static void
compartment_linkup(struct compartment *compartment, u_long id,
    struct thread *td)
{

	EXECUTIVE_ASSERT();

	compartment->c_id = id;
	compartment->c_thread = td;

	TAILQ_INSERT_HEAD(&compartment->c_thread->td_compartments, compartment,
	    c_next);
}

void
compartment_linkup0(struct compartment *compartment, struct thread *td)
{

	EXECUTIVE_ASSERT();

	TAILQ_INIT(&td->td_compartments);
	compartment_linkup(compartment, COMPARTMENT_KERNEL_ID, td);
}

EXECUTIVE_ENTRY(struct compartment *, compartment_create_for_thread,
    (struct thread *td, u_long id))
{
	struct compartment *compartment;

	compartment = malloc(sizeof(*compartment), M_COMPARTMENT, M_NOWAIT |
	    M_USE_RESERVE | M_ZERO);
	KASSERT(compartment != NULL, ("%s: unable to allocate a compartment",
	    __func__));

	if (!vm_compartment_new(compartment)) {
		panic("compartment_create unable to allocate stack");
	}

	cpu_compartment_alloc(compartment);
	compartment_linkup(compartment, id, td);

	sx_slock(&compartment_metadatalock);
	KASSERT(id < compartment_maxnid,
	    ("%s: id %lu exceeds the maximum value %lu", __func__, id,
	     compartment_maxnid - 1));
	TAILQ_INSERT_TAIL(&compartment_metadata[id]->cm_compartments,
	    compartment, c_mnext);
	sx_sunlock(&compartment_metadatalock);

	return (compartment);
}

static struct compartment *
compartment_create(u_long id)
{

	EXECUTIVE_ASSERT();

	return (EXECUTIVE_ENTRY_NAME(compartment_create_for_thread)
	    (curthread, id));
}

EXECUTIVE_ENTRY(void, compartment_destroy, (struct compartment *compartment))
{

	TAILQ_REMOVE(&compartment->c_thread->td_compartments, compartment,
	    c_next);
	vm_compartment_dispose(compartment);
	free(compartment, M_COMPARTMENT);
}

static struct compartment *
compartment_find(u_long id)
{
	struct compartment *compartment;

	EXECUTIVE_ASSERT();

	TAILQ_FOREACH(compartment, &curthread->td_compartments, c_next) {
		if (compartment->c_id == id)
			break;
	}
	return (compartment);
}

vm_pointer_t
compartment_entry_stackptr(u_long id, int type)
{
	struct compartment *compartment;

	EXECUTIVE_ASSERT();

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
compartment_trampoline_create(const linker_file_t lf, int type, void *data,
    size_t size, uintcap_t func)
{
	struct compartment_trampoline *trampoline, *oldtrampoline;
	struct compartment_trampoline tmptrampoline;
	uintcap_t dstfunc;
	u_long dstid;

	EXECUTIVE_ASSERT();

	if (lf != NULL) {
		elf_compartment_entry(lf, func, &dstid, &dstfunc);
	} else {
		/*
		 * We're creating a trampoline for the kernel while the kernel
		 * is being relocated and elf_compartment_entry() isn't
		 * available.
		 *
		 * Use PCC instead of the base address of the linker file.
		 */
		dstid = COMPARTMENT_KERNEL_ID;
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
	if (lf != NULL) {
		trampoline = malloc_exec(size, M_COMPARTMENT, M_NOWAIT |
		    M_USE_RESERVE | M_ZERO);
		KASSERT(trampoline != NULL,
		    ("%s: unable to allocate a trampoline", __func__));
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

	trampoline->ct_compartment_id = dstid;
	if (lf != NULL) {
		cpu_dcache_wb_range((vm_pointer_t)trampoline, (vm_size_t)size);
		cpu_icache_sync_range((vm_pointer_t)trampoline,
		    (vm_size_t)size);

		mtx_lock(&compartment_trampolines_lock);
	}

	oldtrampoline = RB_INSERT(compartment_tree, &compartment_trampolines,
	    trampoline);
	KASSERT(oldtrampoline == NULL,
	    ("Trampoline for 0x%#lp already exists",
	    (void *)trampoline->ct_compartment_func));

	if (lf != NULL)
		mtx_unlock(&compartment_trampolines_lock);

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

EXECUTIVE_ENTRY(void, compartment_trampoline_destroy, (uintptr_t func))
{
	struct compartment_trampoline *trampoline;

	trampoline = __containerof((char (*)[])func,
	    struct compartment_trampoline, ct_code);
	free(trampoline, M_COMPARTMENT);
}

void *
compartment_entry_for_kernel(uintptr_t func)
{

	EXECUTIVE_ASSERT();

	func = cheri_clearperm(func, CHERI_PERM_EXECUTIVE);
	return (compartment_trampoline_create(NULL,
	    TRAMPOLINE_TYPE_COMPARTMENT_ENTRY, compartment_entry_trampoline,
	    szcompartment_entry_trampoline, func));
}

EXECUTIVE_ENTRY(void *, compartment_entry, (uintptr_t func))
{
	linker_file_t lf;

	lf = linker_find_file_by_ptr((uintptr_t)func);
	if (lf == NULL)
		panic("compartment_entry: unable to find a linker file");

	func = cheri_clearperm(func, CHERI_PERM_EXECUTIVE);
	return (compartment_trampoline_create(lf,
	    TRAMPOLINE_TYPE_COMPARTMENT_ENTRY, compartment_entry_trampoline,
	    szcompartment_entry_trampoline, func));
}

void *
executive_entry_for_kernel(uintptr_t func)
{

	EXECUTIVE_ASSERT();
	KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
	    ("Executive entry capability %#lp has invalid permissions",
	     (void *)func));

	return (compartment_trampoline_create(NULL,
	    TRAMPOLINE_TYPE_EXECUTIVE_ENTRY, executive_entry_trampoline,
	    szexecutive_entry_trampoline, func));
}

void *
executive_get_function(uintptr_t func)
{
	struct compartment_trampoline *trampoline;

	EXECUTIVE_ASSERT();
	KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
	    ("Executive trampoline capability %#lp has invalid permissions",
	     (void *)func));

	trampoline = cheri_kern_setaddress(cheri_getpcc(), func - 1);
	trampoline = __containerof((char (*)[])trampoline,
	    struct compartment_trampoline, ct_code);
	KASSERT(trampoline->ct_type == TRAMPOLINE_TYPE_EXECUTIVE_ENTRY,
	    ("Invalid trampoline type"));

	return ((void *)trampoline->ct_compartment_func);
}
