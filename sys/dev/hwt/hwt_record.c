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

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <vm/vm.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwtvar.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_thread.h>

#define	HWT_RECORD_DEBUG
#undef	HWT_RECORD_DEBUG

#ifdef	HWT_RECORD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

void
hwt_record(struct thread *td, enum hwt_record_type record_type,
    struct hwt_record_entry *ent)
{
	struct hwt_record_entry *entry;
	struct hwt_context *ctx;
	struct proc *p;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	/* We must have a ctx. */
	ctx = hwt_ctx_lookup_contexthash(p);

	switch (record_type) {
	case HWT_RECORD_MMAP:
		dprintf("%s: MMAP path %s addr %lx size %lx\n", __func__,
		    ent->fullpath, (unsigned long)ent->addr, ent->size);
		break;
	case HWT_RECORD_EXECUTABLE:
		dprintf("%s: EXEC path %s addr %lx size %lx\n", __func__,
		    ent->fullpath, (unsigned long)ent->addr, ent->size);
		break;
	case HWT_RECORD_INTERP:
		dprintf("%s: INTP path %s addr %lx size %lx\n", __func__,
		    ent->fullpath, (unsigned long)ent->addr, ent->size);
		break;
	case HWT_RECORD_MUNMAP:
		break;
	case HWT_RECORD_THREAD_CREATE:
		dprintf("%s: NEW thread %p, tid %d\n", __func__, td,
		    td->td_tid);
		hwt_thread_create(ctx, td);
		break;
	case HWT_RECORD_THREAD_SET_NAME:
		dprintf("%s: THREAD_SET_NAME %p\n", __func__, td);
		break;
	default:
		return;
	};

	entry = malloc(sizeof(struct hwt_record_entry), M_HWT, M_WAITOK);
	entry->record_type = record_type;
	entry->tid = td->td_tid;

	if (ent) {
		KASSERT(ent->fullpath != NULL, ("fullpath is NULL"));
		entry->fullpath = strdup(ent->fullpath, M_HWT);
		entry->addr = ent->addr;
		entry->size = ent->size;
	}

	mtx_lock(&ctx->mtx_records);
	LIST_INSERT_HEAD(&ctx->records, entry, next);
	mtx_unlock(&ctx->mtx_records);
}
