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
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/tree.h>

#include <cheri/cheric.h>

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

struct compartment_metadata {
	char		*cm_name;
	struct mtx	 cm_lock;
	uintcap_t	 cm_base;
	elf_compartment_t  cm_elf_compartment;
	TAILQ_HEAD(, compartment) cm_compartments;
};

struct compartment_trampoline {
	u_long		ct_compartment_id;
	int		ct_type;
	uintcap_t	ct_compartment_func;
	uintcap_t	ct_compartment_stackptr_func;
	RB_ENTRY(compartment_trampoline) ct_node;
	char		ct_code[] __subobject_use_container_bounds;
};

#if defined(__aarch64__) || defined(__riscv)
extern int early_boot;
#endif

u_long compartment_lastid = COMPARTMENT_KERNEL_ID;
static u_long compartment_maxnid;
static uma_zone_t compartment_zone;
static struct compartment_metadata **compartment_metadata;
static struct sx __exclusive_cache_line compartment_metadatalock;
static struct mtx compartment_metadataspinlock;
MTX_SYSINIT(compartment_metadataspinlock, &compartment_metadataspinlock,
    "compartment_metadataspinlock", MTX_SPIN);

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

static struct compartment *compartment_alloc(void);
static struct compartment *compartment_alloc_from_cache(struct thread *td);
DPCPU_DEFINE_STATIC(u_long, ncritical_compartments);
DPCPU_DEFINE_STATIC(struct compartment_list, critical_compartments);
DPCPU_DEFINE_STATIC(struct mtx, critical_compartments_spinlock);

void
compartment_cpu_cache_fill(u_int cpuid)
{
	struct mtx *critical_compartments_spinlock;
	struct compartment_list *critical_compartments;
	u_long ii, ncritical_compartments, needed;
	struct compartment *compartment;
	struct compartment_list list;

	critical_compartments_spinlock = DPCPU_ID_PTR(cpuid,
	    critical_compartments_spinlock);

	mtx_lock_spin(critical_compartments_spinlock);
	ncritical_compartments = DPCPU_ID_GET(cpuid, ncritical_compartments);
	mtx_unlock_spin(critical_compartments_spinlock);

	STAILQ_INIT(&list);
	needed = MAX(COMPARTMENT_CACHE_SIZE, ncritical_compartments) -
	    ncritical_compartments;
	for (ii = 0; ii < needed; ii++) {
		compartment = compartment_alloc();
		STAILQ_INSERT_HEAD(&list, compartment, c_critical_next);
	}

	mtx_lock_spin(critical_compartments_spinlock);
	critical_compartments = DPCPU_ID_PTR(cpuid, critical_compartments);
	STAILQ_CONCAT(critical_compartments, &list);
	ncritical_compartments = DPCPU_ID_GET(cpuid, ncritical_compartments);
	DPCPU_ID_SET(cpuid, ncritical_compartments,
	    ncritical_compartments + needed);
	mtx_unlock_spin(critical_compartments_spinlock);
}

static void
compartment_cpu_cache_init(void *arg __unused)
{
	struct compartment_list *critical_compartments;
	struct compartment *compartment;
	struct mtx *critical_compartments_spinlock;
	u_long ii, ncritical_compartments;
	u_int cpuid;

	compartment_zone = uma_zcreate("compartment_zone",
	    sizeof(struct compartment), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	if (compartment_zone == NULL)
		panic("compartment_cpu_cache_init: unable to allocate a zone.");

	ncritical_compartments = COMPARTMENT_CACHE_SIZE;
	CPU_FOREACH(cpuid) {
		critical_compartments = DPCPU_ID_PTR(cpuid,
		    critical_compartments);
		STAILQ_INIT(critical_compartments);
		for (ii = 0; ii < ncritical_compartments; ii++) {
			compartment = compartment_alloc();
			STAILQ_INSERT_HEAD(critical_compartments, compartment,
			    c_critical_next);
		}

		DPCPU_ID_SET(cpuid, ncritical_compartments,
		    ncritical_compartments);

		critical_compartments_spinlock = DPCPU_ID_PTR(cpuid,
		    critical_compartments_spinlock);
		mtx_init(critical_compartments_spinlock,
		    "critical_compartments_spinlock", NULL, MTX_SPIN);
	}
}

/*
 * NB: The zone and critical compartments can be allocated after PCPU/DPCPU
 * storage is initialised (on boot) and after the UMA subsystem is sufficiently
 * initialised (as part of SI_SUB_{VM_CONF,COUNTER} but not SI_SUB_TASKQ).
 */
SYSINIT(compartment_cpu_cache_init, SI_SUB_RUN_QUEUE, SI_ORDER_ANY,
    compartment_cpu_cache_init, NULL);

void
compartment_metadata_create(u_long id, const char *name, uintcap_t base,
    elf_compartment_t elf_compartment)
{
	struct compartment_metadata *metadata;
	struct compartment_metadata **newcompartment_metadata;
	struct compartment_metadata **oldcompartment_metadata;
	u_long oldcompartment_maxnid;

	sx_slock(&compartment_metadatalock);

	if (id >= compartment_maxnid) {
		/*
		 * Prevent any interruptible thread from reading
		 * compartment_metadata for the time we re-allocate it.
		 */
		if (!sx_try_upgrade(&compartment_metadatalock)) {
			sx_sunlock(&compartment_metadatalock);
			sx_xlock(&compartment_metadatalock);
		}

		oldcompartment_metadata = compartment_metadata;
		oldcompartment_maxnid = compartment_maxnid;

		compartment_maxnid *= 2;

		newcompartment_metadata =
		    malloc(sizeof(*compartment_metadata) * compartment_maxnid,
		    M_COMPARTMENT, M_NOWAIT | M_USE_RESERVE | M_ZERO);
		KASSERT(newcompartment_metadata != NULL,
		    ("%s: unable to reallocate compartment metadata array",
		     __func__));
		memcpy(newcompartment_metadata, compartment_metadata,
		    sizeof(*compartment_metadata) * oldcompartment_maxnid);

		/*
		 * Update compartment_metadata in a synchronous manner with
		 * uninterruptible threads.
		 */
		mtx_lock_spin(&compartment_metadataspinlock);
		compartment_metadata = newcompartment_metadata;
		mtx_unlock_spin(&compartment_metadataspinlock);

		sx_downgrade(&compartment_metadatalock);

		free(oldcompartment_metadata, M_COMPARTMENT);
	}

	/*
	 * NB: We can use a shared lock here as there are never two calls to
	 * this function with the same id.
	 */
	metadata = malloc(sizeof(**compartment_metadata),
	    M_COMPARTMENT, M_NOWAIT | M_USE_RESERVE | M_ZERO);
	KASSERT(metadata != NULL,
	    ("%s: unable to allocate compartment metadata", __func__));
	compartment_metadata[id] = metadata;

	sx_sunlock(&compartment_metadatalock);

	metadata->cm_name = strdup(name, M_COMPARTMENT);
	KASSERT(metadata->cm_name != NULL,
	    ("%s: unable to initialize compartment metadata", __func__));
	mtx_init(&metadata->cm_lock, "compartment_metadata", NULL, MTX_SPIN);
	metadata->cm_base = base;
	metadata->cm_elf_compartment = elf_compartment;
	TAILQ_INIT(&metadata->cm_compartments);
}

void
compartment_metadata_insert(struct compartment *compartment)
{
	struct compartment_metadata *metadata;

	/* NB: compartment_maxnid can be unlocked as it never decreases. */
	KASSERT(compartment->c_id < compartment_maxnid,
	    ("%s: id %lu exceeds the maximum value %lu", __func__,
	     compartment->c_id, compartment_maxnid - 1));

	sx_slock(&compartment_metadatalock);
	metadata = compartment_metadata[compartment->c_id];
	sx_sunlock(&compartment_metadatalock);

	mtx_lock_spin(&metadata->cm_lock);
	TAILQ_INSERT_TAIL(&metadata->cm_compartments, compartment, c_mnext);
	mtx_unlock_spin(&metadata->cm_lock);
}

static void
compartment_metadata_init(void *arg __unused)
{

	sx_init(&compartment_metadatalock, "compartment_metadata");

	compartment_maxnid = roundup_pow_of_two(compartment_lastid);
	compartment_metadata = malloc(sizeof(*compartment_metadata) *
	    compartment_maxnid, M_COMPARTMENT, M_NOWAIT | M_USE_RESERVE |
	    M_ZERO);
	KASSERT(compartment_metadata != NULL,
	    ("%s: unable to allocate compartment metadata array", __func__));
}

SYSINIT(compartment_metadata_init, SI_SUB_KLD, SI_ORDER_FIRST,
    compartment_metadata_init, NULL);

u_long
compartment_id_create(const char *name, uintcap_t base,
    elf_compartment_t elf_compartment)
{

	atomic_add_long(&compartment_lastid, 1);
	compartment_metadata_create(compartment_lastid, name, base,
	    elf_compartment);
	return (compartment_lastid);
}

void
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
		panic("compartment_create unable to allocate stack");
	}
	return (compartment);
}

static struct compartment *
compartment_alloc_from_cache(struct thread *td)
{
	struct mtx *critical_compartments_spinlock;
	struct compartment_list *critical_compartments;
	struct compartment *compartment;
	u_long ncritical_compartments;

	KASSERT(curthread->td_critnest > 0,
	    ("%s: called outside a critical section", __func__));

	critical_compartments_spinlock =
	    DPCPU_PTR(critical_compartments_spinlock);
	mtx_lock_spin(critical_compartments_spinlock);

	critical_compartments = DPCPU_PTR(critical_compartments);
	ncritical_compartments = DPCPU_GET(ncritical_compartments);
	if (ncritical_compartments == 0)
		panic("%s: the cache is empty.", __func__);

	compartment = STAILQ_FIRST(critical_compartments);
	STAILQ_REMOVE_HEAD(critical_compartments, c_critical_next);

	DPCPU_SET(ncritical_compartments, ncritical_compartments - 1);
	mtx_unlock_spin(critical_compartments_spinlock);

	return (compartment);
}

struct compartment *
compartment_create_for_thread(struct thread *td, u_long id)
{
	struct compartment_metadata *metadata;
	struct compartment *compartment;

	if (curthread->td_critnest == 0) {
		compartment = compartment_alloc();
	} else {
		compartment = compartment_alloc_from_cache(td);
	}
	compartment_linkup(compartment, id, td);

	/* NB: compartment_maxnid can be unlocked as it never decreases. */
	KASSERT(id < compartment_maxnid,
	    ("%s: id %lu exceeds the maximum value %lu", __func__, id,
	     compartment_maxnid - 1));

	mtx_lock_spin(&compartment_metadataspinlock);
	metadata = compartment_metadata[id];
	mtx_unlock_spin(&compartment_metadataspinlock);

	mtx_lock_spin(&metadata->cm_lock);
	TAILQ_INSERT_TAIL(&metadata->cm_compartments, compartment, c_mnext);
	mtx_unlock_spin(&metadata->cm_lock);

	return (compartment);
}

static struct compartment *
compartment_create(u_long id)
{

	EXECUTIVE_ASSERT();

	return (compartment_create_for_thread(curthread, id));
}

void
compartment_destroy(struct compartment *compartment)
{
	struct compartment_metadata *metadata;

	if (compartment->c_id > 0) {
		sx_slock(&compartment_metadatalock);
		metadata = compartment_metadata[compartment->c_id];
		sx_sunlock(&compartment_metadatalock);

		mtx_lock_spin(&metadata->cm_lock);
		TAILQ_REMOVE(&metadata->cm_compartments, compartment, c_mnext);
		mtx_unlock_spin(&metadata->cm_lock);
	}

	if (compartment->c_thread != NULL) {
		TAILQ_REMOVE(&compartment->c_thread->td_compartments,
		    compartment, c_next);
	}

	vm_compartment_dispose(compartment);
	uma_zfree(compartment_zone, compartment);
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

static vm_pointer_t __used
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
	KASSERT(lf != NULL,
	    ("%s: linker file cannot be NULL", __func__));

	elf_compartment_entry(lf, func, &dstid, &dstfunc);

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

	trampoline->ct_compartment_func = dstfunc;
	trampoline->ct_type = type;
	ELF_STATIC_RELOC_LABEL(trampoline->ct_compartment_stackptr_func,
	    compartment_entry_stackptr);
	trampoline->ct_compartment_stackptr_func =
	    cheri_sealentry(trampoline->ct_compartment_stackptr_func);

	trampoline->ct_compartment_id = dstid;
	if (!early_boot) {
		cpu_dcache_wb_range(trampoline, (vm_size_t)size);
		cpu_icache_sync_range(trampoline, (vm_size_t)size);

		mtx_lock(&compartment_trampolines_lock);
	}

	oldtrampoline = RB_INSERT(compartment_tree, &compartment_trampolines,
	    trampoline);
	KASSERT(oldtrampoline == NULL,
	    ("Trampoline for 0x%#lp already exists",
	    (void *)trampoline->ct_compartment_func));

	if (!early_boot)
		mtx_unlock(&compartment_trampolines_lock);

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
	func = (intcap_t)cheri_kern_setaddress(func, (intptr_t)trampoline);
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
executive_get_function(uintptr_t func)
{
	struct compartment_trampoline *trampoline;

	EXECUTIVE_ASSERT();
	KASSERT((cheri_getperm(func) & CHERI_PERM_EXECUTIVE) != 0,
	    ("Executive trampoline capability %#lp has invalid permissions",
	     (void *)func));

	trampoline = cheri_kern_setaddress(kernel_executive_root_cap, func - 1);
	trampoline = __containerof((char (*)[])trampoline,
	    struct compartment_trampoline, ct_code);
	KASSERT(trampoline->ct_type == TRAMPOLINE_TYPE_EXECUTIVE_ENTRY,
	    ("Invalid trampoline type"));

	return ((void *)trampoline->ct_compartment_func);
}

#ifdef DDB
DB_COMMAND_FLAGS(c18nstat, db_c18nstat, DB_CMD_MEMSAFE)
{
	const struct proc *proc;
	struct thread *thread;
	const struct compartment *compartment;
	bool verbose;
	u_long ii;

	verbose = false;
	for (ii = 0; modif[ii] != '\0'; ii++) {
		switch (modif[ii]) {
		case 'v':
			verbose = true;
			break;
		}
	}

#define	ADDRESS_WIDTH	((int)(sizeof(ptraddr_t) * 2 + 2))
	db_printf("ADDRESS%*c %6s %-20s %5s %6s %-20s %-20s\n",
	    ADDRESS_WIDTH - 7, ' ', "CID", "CNAME", "PID", "TID", "COMM",
	    "TDNAME");
	if (verbose) {
		ii = COMPARTMENT_KERNEL_ID;
	} else {
		db_printf("*%*c %6lu %-20s %5s %6s %-20s %-20s\n",
		    ADDRESS_WIDTH - 1, ' ', (u_long)COMPARTMENT_KERNEL_ID,
		    compartment_metadata[COMPARTMENT_KERNEL_ID]->cm_name,
		    "*", "*", "*", "*");
		ii = COMPARTMENT_KERNEL_ID + 1;
	}
#undef	ADDRESS_WIDTH
	for (; ii <= compartment_lastid; ii++) {
		if (db_pager_quit)
			return;
		if (TAILQ_EMPTY(&compartment_metadata[ii]->cm_compartments))
			continue;
		TAILQ_FOREACH(compartment,
		    &compartment_metadata[ii]->cm_compartments, c_mnext) {
			thread = compartment->c_thread;
			if (TD_GET_STATE(thread) == TDS_INACTIVE)
				continue;
			proc = thread->td_proc;
			db_printf("0x%-16lx %6lu %-20s %5d %6d %-20s %-20s\n",
			    (ptraddr_t)compartment, ii,
			    compartment_metadata[ii]->cm_name, proc->p_pid,
			    thread->td_tid, proc->p_comm, thread->td_name);
		}
	}
}

DB_SHOW_COMMAND(compartment, db_show_compartment)
{
	const struct proc *proc;
	const struct thread *thread;
	const struct compartment *compartment;
	const struct compartment_metadata *metadata;

	if (!have_addr) {
		db_printf("show compartment addr\n");
		return;
	}

	compartment = DB_DATA_PTR(addr, struct compartment);
	metadata = compartment_metadata[compartment->c_id];
	thread = compartment->c_thread;
	proc = thread->td_proc;

	db_printf("Compartment at %p:\n", compartment);
	db_printf(" id: %lu\n", compartment->c_id);
	db_printf(" name: %s\n", metadata->cm_name);
	db_printf(" base capability: %#p\n", (void *)metadata->cm_base);
	db_printf(" stack pointer: %#p\n", (void *)compartment->c_kstackptr);
	db_printf(" proc (pid %d): %p\n", proc->p_pid, proc);
	db_printf(" proc command: %s\n", proc->p_comm);
	db_printf(" thread (tid %d): %p\n", thread->td_tid, thread);
	db_printf(" thread name: %s\n", thread->td_name);
	if (metadata->cm_elf_compartment != NULL) {
		db_printf(" imported symbols:\n");
		elf_ddb_show_compartment_symbols(metadata->cm_elf_compartment);
	}
}
#endif /* DDB */
