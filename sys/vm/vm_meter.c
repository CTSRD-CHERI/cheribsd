/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vm_meter.c	8.4 (Berkeley) 1/4/94
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/vmmeter.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <sys/sysctl.h>

struct vmmeter __exclusive_cache_line vm_cnt = {
	.v_swtch = EARLY_COUNTER,
	.v_trap = EARLY_COUNTER,
	.v_syscall = EARLY_COUNTER,
	.v_intr = EARLY_COUNTER,
	.v_soft = EARLY_COUNTER,
	.v_vm_faults = EARLY_COUNTER,
	.v_io_faults = EARLY_COUNTER,
	.v_cow_faults = EARLY_COUNTER,
	.v_cow_optim = EARLY_COUNTER,
	.v_zfod = EARLY_COUNTER,
	.v_ozfod = EARLY_COUNTER,
	.v_swapin = EARLY_COUNTER,
	.v_swapout = EARLY_COUNTER,
	.v_swappgsin = EARLY_COUNTER,
	.v_swappgsout = EARLY_COUNTER,
	.v_vnodein = EARLY_COUNTER,
	.v_vnodeout = EARLY_COUNTER,
	.v_vnodepgsin = EARLY_COUNTER,
	.v_vnodepgsout = EARLY_COUNTER,
	.v_intrans = EARLY_COUNTER,
	.v_reactivated = EARLY_COUNTER,
	.v_pdwakeups = EARLY_COUNTER,
	.v_pdpages = EARLY_COUNTER,
	.v_pdshortfalls = EARLY_COUNTER,
	.v_dfree = EARLY_COUNTER,
	.v_pfree = EARLY_COUNTER,
	.v_tfree = EARLY_COUNTER,
	.v_forks = EARLY_COUNTER,
	.v_vforks = EARLY_COUNTER,
	.v_rforks = EARLY_COUNTER,
	.v_kthreads = EARLY_COUNTER,
	.v_forkpages = EARLY_COUNTER,
	.v_vforkpages = EARLY_COUNTER,
	.v_rforkpages = EARLY_COUNTER,
	.v_kthreadpages = EARLY_COUNTER,
};

static void
vmcounter_startup(void)
{
	counter_u64_t *cnt = (counter_u64_t *)&vm_cnt;

	COUNTER_ARRAY_ALLOC(cnt, VM_METER_NCOUNTERS, M_WAITOK);
}
SYSINIT(counter, SI_SUB_CPU, SI_ORDER_FOURTH + 1, vmcounter_startup, NULL);

SYSCTL_UINT(_vm, VM_V_FREE_MIN, v_free_min,
	CTLFLAG_RW, &vm_cnt.v_free_min, 0, "Minimum low-free-pages threshold");
SYSCTL_UINT(_vm, VM_V_FREE_TARGET, v_free_target,
	CTLFLAG_RW, &vm_cnt.v_free_target, 0, "Desired free pages");
SYSCTL_UINT(_vm, VM_V_FREE_RESERVED, v_free_reserved,
	CTLFLAG_RW, &vm_cnt.v_free_reserved, 0, "Pages reserved for deadlock");
SYSCTL_UINT(_vm, VM_V_INACTIVE_TARGET, v_inactive_target,
	CTLFLAG_RW, &vm_cnt.v_inactive_target, 0, "Pages desired inactive");
SYSCTL_UINT(_vm, VM_V_PAGEOUT_FREE_MIN, v_pageout_free_min,
	CTLFLAG_RW, &vm_cnt.v_pageout_free_min, 0, "Min pages reserved for kernel");
SYSCTL_UINT(_vm, OID_AUTO, v_free_severe,
	CTLFLAG_RW, &vm_cnt.v_free_severe, 0, "Severe page depletion point");

static int
sysctl_vm_loadavg(SYSCTL_HANDLER_ARGS)
{
	
#ifdef SCTL_MASK32
	u_int32_t la[4];

	if (req->flags & SCTL_MASK32) {
		la[0] = averunnable.ldavg[0];
		la[1] = averunnable.ldavg[1];
		la[2] = averunnable.ldavg[2];
		la[3] = averunnable.fscale;
		return SYSCTL_OUT(req, la, sizeof(la));
	} else
#endif
		return SYSCTL_OUT(req, &averunnable, sizeof(averunnable));
}
SYSCTL_PROC(_vm, VM_LOADAVG, loadavg, CTLTYPE_STRUCT | CTLFLAG_RD |
    CTLFLAG_MPSAFE, NULL, 0, sysctl_vm_loadavg, "S,loadavg",
    "Machine loadaverage history");

/*
 * This function aims to determine if the object is mapped,
 * specifically, if it is referenced by a vm_map_entry.  Because
 * objects occasionally acquire transient references that do not
 * represent a mapping, the method used here is inexact.  However, it
 * has very low overhead and is good enough for the advisory
 * vm.vmtotal sysctl.
 */
static bool
is_object_active(vm_object_t obj)
{

	return (obj->ref_count > obj->shadow_count);
}

static int
vmtotal(SYSCTL_HANDLER_ARGS)
{
	struct vmtotal total;
	vm_object_t object;
	struct proc *p;
	struct thread *td;

	bzero(&total, sizeof(total));

	/*
	 * Calculate process statistics.
	 */
	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		if ((p->p_flag & P_SYSTEM) != 0)
			continue;
		PROC_LOCK(p);
		if (p->p_state != PRS_NEW) {
			FOREACH_THREAD_IN_PROC(p, td) {
				thread_lock(td);
				switch (td->td_state) {
				case TDS_INHIBITED:
					if (TD_IS_SWAPPED(td))
						total.t_sw++;
					else if (TD_IS_SLEEPING(td)) {
						if (td->td_priority <= PZERO)
							total.t_dw++;
						else
							total.t_sl++;
						if (td->td_wchan ==
						    &vm_cnt.v_free_count)
							total.t_pw++;
					}
					break;
				case TDS_CAN_RUN:
					total.t_sw++;
					break;
				case TDS_RUNQ:
				case TDS_RUNNING:
					total.t_rq++;
					break;
				default:
					break;
				}
				thread_unlock(td);
			}
		}
		PROC_UNLOCK(p);
	}
	sx_sunlock(&allproc_lock);
	/*
	 * Calculate object memory usage statistics.
	 */
	mtx_lock(&vm_object_list_mtx);
	TAILQ_FOREACH(object, &vm_object_list, object_list) {
		/*
		 * Perform unsynchronized reads on the object.  In
		 * this case, the lack of synchronization should not
		 * impair the accuracy of the reported statistics.
		 */
		if ((object->flags & OBJ_FICTITIOUS) != 0) {
			/*
			 * Devices, like /dev/mem, will badly skew our totals.
			 */
			continue;
		}
		if (object->ref_count == 0) {
			/*
			 * Also skip unreferenced objects, including
			 * vnodes representing mounted file systems.
			 */
			continue;
		}
		if (object->ref_count == 1 &&
		    (object->flags & OBJ_NOSPLIT) != 0) {
			/*
			 * Also skip otherwise unreferenced swap
			 * objects backing tmpfs vnodes, and POSIX or
			 * SysV shared memory.
			 */
			continue;
		}
		total.t_vm += object->size;
		total.t_rm += object->resident_page_count;
		if (is_object_active(object)) {
			total.t_avm += object->size;
			total.t_arm += object->resident_page_count;
		}
		if (object->shadow_count > 1) {
			/* shared object */
			total.t_vmshr += object->size;
			total.t_rmshr += object->resident_page_count;
			if (is_object_active(object)) {
				total.t_avmshr += object->size;
				total.t_armshr += object->resident_page_count;
			}
		}
	}
	mtx_unlock(&vm_object_list_mtx);
	total.t_free = vm_cnt.v_free_count;
	return (sysctl_handle_opaque(oidp, &total, sizeof(total), req));
}

SYSCTL_PROC(_vm, VM_TOTAL, vmtotal, CTLTYPE_OPAQUE|CTLFLAG_RD|CTLFLAG_MPSAFE,
    0, sizeof(struct vmtotal), vmtotal, "S,vmtotal", 
    "System virtual memory statistics");
SYSCTL_NODE(_vm, OID_AUTO, stats, CTLFLAG_RW, 0, "VM meter stats");
static SYSCTL_NODE(_vm_stats, OID_AUTO, sys, CTLFLAG_RW, 0,
	"VM meter sys stats");
static SYSCTL_NODE(_vm_stats, OID_AUTO, vm, CTLFLAG_RW, 0,
	"VM meter vm stats");
SYSCTL_NODE(_vm_stats, OID_AUTO, misc, CTLFLAG_RW, 0, "VM meter misc stats");

static int
sysctl_handle_vmstat(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;
#ifdef COMPAT_FREEBSD11
	uint32_t val32;
#endif

	val = counter_u64_fetch(*(counter_u64_t *)arg1);
#ifdef COMPAT_FREEBSD11
	if (req->oldlen == sizeof(val32)) {
		val32 = val;		/* truncate */
		return (SYSCTL_OUT(req, &val32, sizeof(val32)));
	}
#endif
	return (SYSCTL_OUT(req, &val, sizeof(val)));
}

#define	VM_STATS(parent, var, descr) \
    SYSCTL_OID(parent, OID_AUTO, var, CTLTYPE_U64 | CTLFLAG_MPSAFE | \
    CTLFLAG_RD, &vm_cnt.var, 0, sysctl_handle_vmstat, "QU", descr);
#define	VM_STATS_VM(var, descr)		VM_STATS(_vm_stats_vm, var, descr)
#define	VM_STATS_SYS(var, descr)	VM_STATS(_vm_stats_sys, var, descr)

VM_STATS_SYS(v_swtch, "Context switches");
VM_STATS_SYS(v_trap, "Traps");
VM_STATS_SYS(v_syscall, "System calls");
VM_STATS_SYS(v_intr, "Device interrupts");
VM_STATS_SYS(v_soft, "Software interrupts");
VM_STATS_VM(v_vm_faults, "Address memory faults");
VM_STATS_VM(v_io_faults, "Page faults requiring I/O");
VM_STATS_VM(v_cow_faults, "Copy-on-write faults");
VM_STATS_VM(v_cow_optim, "Optimized COW faults");
VM_STATS_VM(v_zfod, "Pages zero-filled on demand");
VM_STATS_VM(v_ozfod, "Optimized zero fill pages");
VM_STATS_VM(v_swapin, "Swap pager pageins");
VM_STATS_VM(v_swapout, "Swap pager pageouts");
VM_STATS_VM(v_swappgsin, "Swap pages swapped in");
VM_STATS_VM(v_swappgsout, "Swap pages swapped out");
VM_STATS_VM(v_vnodein, "Vnode pager pageins");
VM_STATS_VM(v_vnodeout, "Vnode pager pageouts");
VM_STATS_VM(v_vnodepgsin, "Vnode pages paged in");
VM_STATS_VM(v_vnodepgsout, "Vnode pages paged out");
VM_STATS_VM(v_intrans, "In transit page faults");
VM_STATS_VM(v_reactivated, "Pages reactivated by pagedaemon");
VM_STATS_VM(v_pdwakeups, "Pagedaemon wakeups");
VM_STATS_VM(v_pdpages, "Pages analyzed by pagedaemon");
VM_STATS_VM(v_pdshortfalls, "Page reclamation shortfalls");
VM_STATS_VM(v_dfree, "Pages freed by pagedaemon");
VM_STATS_VM(v_pfree, "Pages freed by exiting processes");
VM_STATS_VM(v_tfree, "Total pages freed");
VM_STATS_VM(v_forks, "Number of fork() calls");
VM_STATS_VM(v_vforks, "Number of vfork() calls");
VM_STATS_VM(v_rforks, "Number of rfork() calls");
VM_STATS_VM(v_kthreads, "Number of fork() calls by kernel");
VM_STATS_VM(v_forkpages, "VM pages affected by fork()");
VM_STATS_VM(v_vforkpages, "VM pages affected by vfork()");
VM_STATS_VM(v_rforkpages, "VM pages affected by rfork()");
VM_STATS_VM(v_kthreadpages, "VM pages affected by fork() by kernel");

#define	VM_STATS_UINT(var, descr)	\
    SYSCTL_UINT(_vm_stats_vm, OID_AUTO, var, CTLFLAG_RD, &vm_cnt.var, 0, descr)
VM_STATS_UINT(v_page_size, "Page size in bytes");
VM_STATS_UINT(v_page_count, "Total number of pages in system");
VM_STATS_UINT(v_free_reserved, "Pages reserved for deadlock");
VM_STATS_UINT(v_free_target, "Pages desired free");
VM_STATS_UINT(v_free_min, "Minimum low-free-pages threshold");
VM_STATS_UINT(v_free_count, "Free pages");
VM_STATS_UINT(v_wire_count, "Wired pages");
VM_STATS_UINT(v_active_count, "Active pages");
VM_STATS_UINT(v_inactive_target, "Desired inactive pages");
VM_STATS_UINT(v_inactive_count, "Inactive pages");
VM_STATS_UINT(v_laundry_count, "Pages eligible for laundering");
VM_STATS_UINT(v_pageout_free_min, "Min pages reserved for kernel");
VM_STATS_UINT(v_interrupt_free_min, "Reserved pages for interrupt code");
VM_STATS_UINT(v_free_severe, "Severe page depletion point");

#ifdef COMPAT_FREEBSD11
/*
 * Provide compatibility sysctls for the benefit of old utilities which exit
 * with an error if they cannot be found.
 */
SYSCTL_UINT(_vm_stats_vm, OID_AUTO, v_cache_count, CTLFLAG_RD,
    SYSCTL_NULL_UINT_PTR, 0, "Dummy for compatibility");
SYSCTL_UINT(_vm_stats_vm, OID_AUTO, v_tcached, CTLFLAG_RD,
    SYSCTL_NULL_UINT_PTR, 0, "Dummy for compatibility");
#endif
