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
#include <sys/hwt.h>

#include <vm/vm.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_contexthash.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_record.h>

#define	HWT_RECORD_DEBUG
#undef	HWT_RECORD_DEBUG

#ifdef	HWT_RECORD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static MALLOC_DEFINE(M_HWT_RECORD, "hwt_record", "Hardware Trace");

void
hwt_record(struct thread *td, struct hwt_record_entry *ent)
{
	struct hwt_record_entry *entry;
	struct hwt_context *ctx;
	struct proc *p;

	p = td->td_proc;

	KASSERT(ent != NULL, ("ent is NULL"));
	KASSERT(ent->fullpath != NULL, ("fullpath is NULL"));

	entry = malloc(sizeof(struct hwt_record_entry), M_HWT_RECORD, M_WAITOK);
	entry->record_type = ent->record_type;
	entry->thread_id = -1;
	entry->fullpath = strdup(ent->fullpath, M_HWT_RECORD);
	entry->addr = ent->addr;
	entry->size = ent->size;

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL) {
		/* TODO: release resources. */
		return;
	}
	LIST_INSERT_HEAD(&ctx->records, entry, next);
	HWT_CTX_UNLOCK(ctx);
}

void
hwt_record_thread(struct hwt_thread *thr)
{
	struct hwt_record_entry *entry;
	struct hwt_context *ctx;

	ctx = thr->ctx;

	entry = malloc(sizeof(struct hwt_record_entry), M_HWT_RECORD,
	    M_WAITOK | M_ZERO);
	entry->record_type = HWT_RECORD_THREAD_CREATE;
	entry->thread_id = thr->session_id;

	HWT_CTX_LOCK(ctx);
	LIST_INSERT_HEAD(&ctx->records, entry, next);
	HWT_CTX_UNLOCK(ctx);
}

int
hwt_record_grab(struct hwt_context *ctx,
    struct hwt_record_user_entry *user_entry, int nitems_req)
{
	struct hwt_record_entry *entry;
	int i;

	for (i = 0; i < nitems_req; i++) {
		HWT_CTX_LOCK(ctx);
		entry = LIST_FIRST(&ctx->records);
		if (entry)
			LIST_REMOVE(entry, next);
		HWT_CTX_UNLOCK(ctx);

		if (entry == NULL)
			break;

		user_entry[i].addr = entry->addr;
		user_entry[i].size = entry->size;
		user_entry[i].record_type = entry->record_type;
		user_entry[i].thread_id = entry->thread_id;
		if (entry->fullpath != NULL) {
			strncpy(user_entry[i].fullpath, entry->fullpath,
			    MAXPATHLEN);
			free(entry->fullpath, M_HWT_RECORD);
		}

		free(entry, M_HWT_RECORD);
	}

	return (i);
}

int
hwt_record_send(struct hwt_context *ctx, struct hwt_record_get *record_get)
{
	struct hwt_record_user_entry *user_entry;
	int nitems_req;
	int error;
	int i;

	nitems_req = 0;

	error = copyin(record_get->nentries, &nitems_req, sizeof(int));
	if (error)
		return (error);

	if (nitems_req < 1 || nitems_req > 1024)
		return (ENXIO);

	user_entry = malloc(sizeof(struct hwt_record_user_entry) * nitems_req,
	    M_HWT_RECORD, M_WAITOK | M_ZERO);

	i = hwt_record_grab(ctx, user_entry, nitems_req);
	if (i > 0)
		error = copyout(user_entry, record_get->records,
		    sizeof(struct hwt_record_user_entry) * i);

	if (error == 0)
		error = copyout(&i, record_get->nentries, sizeof(int));

	free(user_entry, M_HWT_RECORD);

	return (error);
}
