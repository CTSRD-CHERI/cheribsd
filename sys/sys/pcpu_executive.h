/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001 Wind River Systems, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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


#ifndef _SYS_PCPU_EXECUTIVE_H_
#define	_SYS_PCPU_EXECUTIVE_H_

#include <sys/param.h>
#include <sys/_cpuset.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/_sx.h>
#include <sys/queue.h>
#include <sys/_rmlock.h>
#include <sys/resource.h>
#include <machine/pcpu.h>

/*
 * This structure maps out the global data that needs to be kept on a
 * per-cpu basis.  The members are accessed via the PCPU_GET/SET/PTR
 * macros defined in <machine/pcpu.h>.  Machine dependent fields are
 * defined in the PCPU_MD_FIELDS macro defined in <machine/pcpu.h>.
 */
struct pcpu {
	struct thread	*pc_curthread;		/* Current thread */
	struct thread	*pc_idlethread;		/* Idle thread */
	struct thread	*pc_fpcurthread;	/* Fp state owner */
	struct thread	*pc_deadthread;		/* Zombie thread or NULL */
	struct pcb	*pc_curpcb;		/* Current pcb */
	void		*pc_sched;		/* Scheduler state */
	uint64_t	pc_switchtime;		/* cpu_ticks() at last csw */
	int		pc_switchticks;		/* `ticks' at last csw */
	u_int		pc_cpuid;		/* This cpu number */
	STAILQ_ENTRY(pcpu) pc_allcpu;
	struct lock_list_entry *pc_spinlocks;
	long		pc_cp_time[CPUSTATES];	/* statclock ticks */
	struct _device	*pc_device;		/* CPU device handle */
	void		*pc_netisr;		/* netisr SWI cookie */
	int8_t		pc_vfs_freevnodes;	/* freevnodes counter */
	char		pc_unused1[3];		/* unused pad */
	int		pc_domain;		/* Memory domain. */
	struct rm_queue	pc_rm_queue;		/* rmlock list of trackers */
	uintptr_t	pc_dynamic;		/* Dynamic per-cpu data area */
	uint64_t	pc_early_dummy_counter;	/* Startup time counter(9) */
	uintptr_t	pc_zpcpu_offset;	/* Offset into zpcpu allocs */

	/*
	 * Keep MD fields last, so that CPU-specific variations on a
	 * single architecture don't result in offset variations of
	 * the machine-independent fields of the pcpu.  Even though
	 * the pcpu structure is private to the kernel, some ports
	 * (e.g., lsof, part of gtop) define _KERNEL and include this
	 * header.  While strictly speaking this is wrong, there's no
	 * reason not to keep the offsets of the MI fields constant
	 * if only to make kernel debugging easier.
	 */
	PCPU_MD_FIELDS;
} __aligned(CACHE_LINE_SIZE);

#endif /* !_SYS_PCPU_EXECUTIVE_H_*/
