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
#include "opt_ddb.h"
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/compartment.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/tree.h>

#include <cheri/cheric.h>
#include <cheri/c18n.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

#include <machine/compartment.h>
#include <machine/cpufunc.h>
#include <machine/elf.h>
#include <machine/md_var.h>

#ifdef DDB
#include <ddb/ddb.h>
#endif

/*
 * Pre-allocate 2 times the number of compartments a thread can have.
 * This should cover compartments of a thread that is just scheduled for
 * execution and an interrupt thread that preempts the scheduled thread.
 */
#define	COMPARTMENT_CACHE_SIZE	(2 * (compartment_lastid + 1))

MALLOC_DEFINE(M_COMPARTMENT, "compartment", "kernel compartment");

#ifdef CHERI_COMPARTMENT_STATS
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
#endif

struct compartment_trampoline {
	int		ct_type;
	elf_compartment_t ct_elf_compartment;
	uintcap_t	ct_compartment_func;
	uintcap_t	ct_compartment_stackptr_func;
	RB_ENTRY(compartment_trampoline) ct_node;
	char		ct_code[] __subobject_use_container_bounds;
};

#if defined(__aarch64__) || defined(__riscv)
extern int early_boot;
#endif

u_long compartment_lastid = COMPARTMENT_FIRST_ID;
static uma_zone_t compartment_zone;

static int
compartment_trampoline_compare(struct compartment_trampoline *a,
    struct compartment_trampoline *b)
{

	EXECUTIVE_ASSERT();

	return ((ptraddr_t)a->ct_compartment_func -
	    (ptraddr_t)b->ct_compartment_func);
}

RB_GENERATE_STATIC(compartment_trampoline_tree, compartment_trampoline, ct_node,
    compartment_trampoline_compare);

static struct mtx compartment_trampolines_lock;
MTX_SYSINIT(compartmenttrampolines, &compartment_trampolines_lock,
    "compartment_trampolines", MTX_DEF);

static struct compartment *compartment_alloc(void);
static struct compartment *compartment_alloc_from_cache(struct thread *td);
DPCPU_DEFINE_STATIC(u_long, ncritical_compartments);
DPCPU_DEFINE_STATIC(struct compartment_list, critical_compartments);

/*
 * Fills the per-CPU cache of compartment contexts. Synchronize the operation
 * with compartment_alloc_from_cache().
 *
 * Requires the spinlock on entry and holds it on exit.
 */
void
compartment_cpu_cache_fill(void)
{
	struct compartment_list *critical_compartments;
	u_long ii, ncritical_compartments, needed;
	struct compartment *compartment;
	struct compartment_list list;
	u_int cpuid;

	/*
	 * Do not attempt to fill the cache if it is already happening.
	 * A thread would enter this function if it's rescheduled while it's
	 * executing the function.
	 */
	KASSERT(!curthread->td_incachefill,
	    ("%s: curthread is already filling the cache", __func__));
	curthread->td_incachefill = true;

	/*
	 * Pin to the current CPU to make sure that the spinlock section entered
	 * later is synchronised with compartment_alloc_from_cache().
	 */
	sched_pin();
	cpuid = curcpu;
	ncritical_compartments = DPCPU_ID_GET(cpuid, ncritical_compartments);
	spinlock_exit();

	/*
	 * Allocate compartments using UMA that must be preemptable.
	 */
	STAILQ_INIT(&list);
	needed = MAX(COMPARTMENT_CACHE_SIZE, ncritical_compartments) -
	    ncritical_compartments;
	for (ii = 0; ii < needed; ii++) {
		compartment = compartment_alloc();
		STAILQ_INSERT_HEAD(&list, compartment, c_critical_next);
	}

	/*
	 * Add as many objects as there were initially missing. The resulting
	 * cache size can be lower than COMPARTMENT_CACHE_SIZE if the thread was
	 * preempted by other thread that consumed the cache. We take that into
	 * account in the cache size.
	 */
	spinlock_enter();
	critical_compartments = DPCPU_ID_PTR(cpuid, critical_compartments);
	STAILQ_CONCAT(critical_compartments, &list);
	ncritical_compartments = DPCPU_ID_GET(cpuid, ncritical_compartments);
	DPCPU_ID_SET(cpuid, ncritical_compartments,
	    ncritical_compartments + needed);
	spinlock_exit();

	sched_unpin();
	curthread->td_incachefill = false;
}

static void
compartment_cpu_cache_init_cpu(u_int cpuid)
{
	struct compartment_list *critical_compartments;
	struct compartment *compartment;
	u_long ii, ncritical_compartments;

	ncritical_compartments = COMPARTMENT_CACHE_SIZE;
	critical_compartments = DPCPU_ID_PTR(cpuid, critical_compartments);
	STAILQ_INIT(critical_compartments);
	for (ii = 0; ii < ncritical_compartments; ii++) {
		compartment = compartment_alloc();
		STAILQ_INSERT_HEAD(critical_compartments, compartment,
		    c_critical_next);
	}

	DPCPU_ID_SET(cpuid, ncritical_compartments, ncritical_compartments);
}

static void
compartment_cpu_cache_init_bsp(void *arg __unused)
{
	compartment_zone = uma_zcreate("compartment_zone",
	    sizeof(struct compartment), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	if (compartment_zone == NULL)
		panic("%s: unable to allocate a zone", __func__);

	compartment_cpu_cache_init_cpu(0);
}

static void
compartment_cpu_cache_init_aps(void *arg __unused)
{
	u_int cpuid;

	CPU_FOREACH(cpuid) {
		if (cpuid == 0)
			continue;

		compartment_cpu_cache_init_cpu(cpuid);
	}
}

/*
 * NB: The zone and critical compartments can be allocated after PCPU/DPCPU
 * storage is initialised (on boot) and after the UMA subsystem is sufficiently
 * initialised. BSP must be initialised prior to module loading in case of new
 * SYSINITs, IFUNC resolvers, constructors, etc. APs cannot be initialised
 * until after mp_start (currently SI_SUB_CPU, SI_ORDER_THIRD) as we need
 * mp_maxid and all_cpus initialised for CPU_FOREACH to work.
 */
SYSINIT(compartment_cpu_cache_init_bsp, SI_SUB_KLD, SI_ORDER_FIRST,
    compartment_cpu_cache_init_bsp, NULL);
SYSINIT(compartment_cpu_cache_init_aps, SI_SUB_CPU, SI_ORDER_ANY,
    compartment_cpu_cache_init_aps, NULL);

void
compartment_trampoline_tree_remove_all(struct compartment_trampoline_tree *tree)
{
	struct compartment_trampoline *tmptrampoline, *trampoline;

	RB_FOREACH_SAFE(trampoline, compartment_trampoline_tree, tree,
	    tmptrampoline) {
		RB_REMOVE(compartment_trampoline_tree, tree, trampoline);
		free(trampoline, M_COMPARTMENT);
	}
	KASSERT(RB_EMPTY(tree), ("%s: tree is not empty.", __func__));
}

u_long
compartment_id_create(const char *name, uintcap_t base,
    elf_compartment_t elf_compartment)
{

	atomic_add_long(&compartment_lastid, 1);
	return (compartment_lastid);
}

void
compartment_linkup(struct compartment *compartment,
    elf_compartment_t elf_compartment, struct thread *td)
{

	EXECUTIVE_ASSERT();
	KASSERT(elf_compartment->id <= td->td_compartments_maxid,
	    ("%s: id %lu exceeds the maximum value %lu", __func__,
	     elf_compartment->id, td->td_compartments_maxid));

	compartment->c_elf_compartment = elf_compartment;
	/*
	 * Store the index as compartment->c_elf_compartment can be deallocated
	 * before the compartment is deallocated.
	 */
	compartment->c_ndx = TD_CIDNDX(compartment->c_elf_compartment->id);
	compartment->c_thread = td;
	td->td_compartments[compartment->c_ndx] = compartment;
}

void
compartment_init_stack(struct compartment *compartment, vm_pointer_t stack)
{

	compartment->c_kstack = stack;
	compartment->c_kstackptr = stack + kstack_pages * PAGE_SIZE;
	cpu_compartment_alloc(compartment);
}

static struct compartment *
compartment_alloc(void)
{
	struct compartment *compartment;

	compartment = uma_zalloc(compartment_zone, M_NOWAIT | M_ZERO);
	if (!vm_compartment_new(compartment)) {
		panic("%s: unable to allocate stack.", __func__);
	}
	return (compartment);
}

/*
 * Allocate a compartment context using the per-CPU cache. Synchronize the
 * operation with compartment_cpu_cache_fill().
 */
static struct compartment *
compartment_alloc_from_cache(struct thread *td)
{
	struct compartment_list *critical_compartments;
	struct compartment *compartment;
	u_long ncritical_compartments;

	spinlock_enter();

	critical_compartments = DPCPU_PTR(critical_compartments);
	ncritical_compartments = DPCPU_GET(ncritical_compartments);
	if (ncritical_compartments == 0)
		panic("%s: the cache is empty.", __func__);

	compartment = STAILQ_FIRST(critical_compartments);
	STAILQ_REMOVE_HEAD(critical_compartments, c_critical_next);

	DPCPU_SET(ncritical_compartments, ncritical_compartments - 1);

	spinlock_exit();
	return (compartment);
}

struct compartment *
compartment_create(struct thread *td, elf_compartment_t elf_compartment,
    bool usecache)
{
	struct compartment *compartment;

	if (usecache)
		compartment = compartment_alloc_from_cache(td);
	else {
		curthread->td_incachefill = true;
		compartment = compartment_alloc();
		curthread->td_incachefill = false;
	}
	compartment_linkup(compartment, elf_compartment, td);

	return (compartment);
}

void
compartment_destroy(struct compartment *compartment)
{

	if (compartment->c_thread != NULL) {
		compartment->c_thread->td_compartments[compartment->c_ndx] =
		    NULL;
	}

	vm_compartment_dispose(compartment);
	uma_zfree(compartment_zone, compartment);
}

static vm_pointer_t __used
compartment_entry_stackptr(elf_compartment_t elf_compartment, int type)
{
	struct compartment *compartment;

	EXECUTIVE_ASSERT();

#ifdef CHERI_COMPARTMENT_STATS
	/*
	 * TODO: Make compartment_trampoline_counters actual atomic counters.
	 */
	if (compartment_trampoline_counters[type] < ULONG_MAX)
		compartment_trampoline_counters[type]++;
#endif

	if (elf_compartment->id <= curthread->td_compartments_maxid)
		compartment =
		    curthread->td_compartments[TD_CIDNDX(elf_compartment->id)];
	else
		compartment = NULL;
	if (compartment == NULL)
		compartment = compartment_create(curthread, elf_compartment,
		    true);
	return (compartment->c_kstackptr);
}

static struct compartment_trampoline *
compartment_trampoline_create(const linker_file_t lf, int type, void *data,
    size_t size, uintcap_t func)
{
	struct compartment_trampoline *trampoline, *oldtrampoline;
	struct compartment_trampoline tmptrampoline;
	struct compartment_trampoline_tree *tree;
	elf_compartment_t dstelf_compartment;
	uintcap_t dstfunc;

	EXECUTIVE_ASSERT();
	KASSERT(lf != NULL,
	    ("%s: linker file cannot be NULL", __func__));

	elf_compartment_entry(lf, func, &dstelf_compartment, &dstfunc);
	tree = elf_compartment_trampoline_tree(lf);

	tmptrampoline.ct_compartment_func = dstfunc;
	oldtrampoline = RB_FIND(compartment_trampoline_tree, tree,
	    &tmptrampoline);
	if (oldtrampoline != NULL) {
		trampoline = oldtrampoline;
		goto out;
	}

	if (!early_boot) {
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

	trampoline->ct_elf_compartment = dstelf_compartment;
	trampoline->ct_compartment_func = dstfunc;
	trampoline->ct_type = type;
	ELF_STATIC_RELOC_LABEL(trampoline->ct_compartment_stackptr_func,
	    compartment_entry_stackptr);
	trampoline->ct_compartment_stackptr_func =
	    cheri_sealentry(trampoline->ct_compartment_stackptr_func);

	if (!early_boot) {
		cpu_dcache_wb_range(trampoline, (vm_size_t)size);
		cpu_icache_sync_range(trampoline, (vm_size_t)size);
	}

	oldtrampoline = RB_INSERT(compartment_trampoline_tree, tree,
	    trampoline);
	KASSERT(oldtrampoline == NULL,
	    ("Trampoline for 0x%#lp already exists",
	    (void *)trampoline->ct_compartment_func));

out:
	/*
	 * TODO: branch into the executive compartment before relocating the
	 * kernel. Currently, this function is called in different contexts
	 * depending if it's creating an entry to the kernel or kernel module.
	 */
	if (early_boot)
		func = (intcap_t)cheri_getpcc();
	else
		func = (intcap_t)kernel_executive_root_cap;
	func = (intcap_t)cheri_kern_address_set(func, (intptr_t)trampoline);
	/*
	 * XXXKW: The bounds cover both metadata and code of the trampoline to
	 * allow the code to access the metadata.
	 */
	func = cheri_kern_bounds_set(func, size);
	func = (intcap_t)cheri_kern_address_set(func,
	    (intptr_t)&trampoline->ct_code);
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	func = cheri_capmode(func);
#endif
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
compartment_entry_for_kernel(uintptr_t func)
{

	EXECUTIVE_ASSERT();

	if (elf_compartment_isdefault(linker_kernel_file, func)) {
		KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
		    ("Executive entry capability %#lp has invalid permissions",
		     (void *)func));

		return (compartment_trampoline_create(linker_kernel_file,
		    TRAMPOLINE_TYPE_EXECUTIVE_ENTRY, executive_entry_trampoline,
		    szexecutive_entry_trampoline, func));
	} else {
		func = cheri_clearperm(func, CHERI_PERM_EXECUTIVE);
		return (compartment_trampoline_create(linker_kernel_file,
		    TRAMPOLINE_TYPE_COMPARTMENT_ENTRY,
		    compartment_entry_trampoline,
		    szcompartment_entry_trampoline, func));
	}
}

void *
compartment_entry(uintptr_t func)
{
	linker_file_t lf;

	EXECUTIVE_ASSERT();

	lf = linker_find_file_by_ptr((uintptr_t)func);
	if (lf == NULL)
		panic("compartment_entry: unable to find a linker file");

	func = cheri_clearperm(func, CHERI_PERM_EXECUTIVE);
	return (compartment_trampoline_create(lf,
	    TRAMPOLINE_TYPE_COMPARTMENT_ENTRY, compartment_entry_trampoline,
	    szcompartment_entry_trampoline, func));
}

void *
compartment_target(uintptr_t func)
{
	struct compartment_trampoline *trampoline;

	EXECUTIVE_ASSERT();
	KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
	    ("Executive trampoline capability %#lp has invalid permissions",
	     (void *)func));

	trampoline = cheri_kern_address_set(kernel_executive_root_cap,
	    func & ~0x1);
	trampoline = __containerof((char (*)[])trampoline,
	    struct compartment_trampoline, ct_code);

	return ((void *)trampoline->ct_compartment_func);
}

#ifdef DDB
DB_COMMAND_FLAGS(c18nstat, db_c18nstat, DB_CMD_MEMSAFE)
{
	const struct proc *proc;
	struct thread *thread;
	const struct compartment *compartment;
	u_long ii;

#define	ADDRESS_WIDTH	((int)(sizeof(ptraddr_t) * 2 + 2))
	db_printf("ADDRESS%*c %6s %-20s %5s %6s %-20s %-20s\n",
	    ADDRESS_WIDTH - 7, ' ', "CID", "CNAME", "PID", "TID", "COMM",
	    "TDNAME");
#undef	ADDRESS_WIDTH
	ii = COMPARTMENT_FIRST_ID;
	for (; ii <= compartment_lastid; ii++) {
		for (thread = kdb_thr_first(); thread != NULL;
		    thread = kdb_thr_next(thread)) {
			if (db_pager_quit)
				return;
			if (thread->td_compartments[ii] == NULL)
				continue;
			if (TD_GET_STATE(thread) == TDS_INACTIVE)
				continue;
			compartment = thread->td_compartments[ii];
			proc = thread->td_proc;
			db_printf("0x%-16lx %6lu %-20s %5d %6d %-20s %-20s\n",
			    (ptraddr_t)compartment, ii,
			    compartment->c_elf_compartment->name, proc->p_pid,
			    thread->td_tid, proc->p_comm, thread->td_name);
		}
	}
}

DB_SHOW_COMMAND(compartment, db_show_compartment)
{
	const struct proc *proc;
	const struct thread *thread;
	const struct compartment *compartment;
	elf_compartment_t elf_compartment;

	if (!have_addr) {
		db_printf("show compartment addr\n");
		return;
	}

	compartment = DB_DATA_PTR(addr, struct compartment);
	elf_compartment = compartment->c_elf_compartment;
	thread = compartment->c_thread;
	proc = thread->td_proc;

	db_printf("Compartment at %p:\n", compartment);
	db_printf(" id: %lu\n", elf_compartment->id);
	db_printf(" name: %s\n", elf_compartment->name);
	db_printf(" PCC capability: %#p\n", (void *)elf_compartment->pcc->pcc);
	db_printf(" stack pointer: %#p\n", (void *)compartment->c_kstackptr);
	db_printf(" proc (pid %d): %p\n", proc->p_pid, proc);
	db_printf(" proc command: %s\n", proc->p_comm);
	db_printf(" thread (tid %d): %p\n", thread->td_tid, thread);
	db_printf(" thread name: %s\n", thread->td_name);
	db_printf(" imported symbols:\n");
	elf_ddb_show_compartment_symbols(elf_compartment);
}
#endif /* DDB */
