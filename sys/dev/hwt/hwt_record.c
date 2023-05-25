/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/rwlock.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>
#include <vm/vm_radix.h>
#include <vm/pmap.h>

#include <dev/hwt/hwtvar1.h>
#include <dev/hwt/hwtvar.h>
#include <dev/hwt/hwt.h>

void
hwt_record(struct thread *td, enum hwt_record_type record_type,
    struct hwt_record_entry *ent)
{
	struct hwt_record_entry *entry;
	struct hwt_context *ctx;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_lookup_ctx(p, cpu_id);
	if (ctx == NULL)
		return;

	switch (record_type) {
	case HWT_RECORD_MMAP:
		printf("%s: MMAP path %s addr %lx size %lx\n", __func__, ent->fullpath,
		    (unsigned long)ent->addr, ent->size);
		break;
	case HWT_RECORD_EXECUTABLE:
		printf("%s: EXEC path %s addr %lx size %lx\n", __func__, ent->fullpath,
		    (unsigned long)ent->addr, ent->size);
		break;
	case HWT_RECORD_INTERP:
		printf("%s: INTP path %s addr %lx size %lx\n", __func__, ent->fullpath,
		    (unsigned long)ent->addr, ent->size);
		break;
	case HWT_RECORD_MUNMAP:
	default:
		return;
	};

	entry = malloc(sizeof(struct hwt_record_entry), M_DEVBUF, M_WAITOK);
	entry->fullpath = strdup(ent->fullpath, M_DEVBUF);
	entry->td = td;
	entry->addr = ent->addr;
	entry->size = ent->size;

	mtx_lock_spin(&ctx->mtx);
	LIST_INSERT_HEAD(&ctx->records, entry, next);
	mtx_unlock_spin(&ctx->mtx);
}
