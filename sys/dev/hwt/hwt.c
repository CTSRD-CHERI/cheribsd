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

/* Hardware Trace (HWT) framework. */

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/hwt.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwtvar.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_owner.h>
#include <dev/hwt/hwt_backend.h>

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

/* No real reason for this limitation except sanity checks. */
#define	HWT_MAXBUFSIZE		(1U * 1024 * 1024 * 1024) /* 1 GB */

MALLOC_DEFINE(M_HWT_RECORD, "hwt_record", "Hardware Trace");
MALLOC_DEFINE(M_HWT_CTX, "hwt_ctx", "Hardware Trace");
MALLOC_DEFINE(M_HWT_OWNER, "hwt_owner", "Hardware Trace");
MALLOC_DEFINE(M_HWT_THREAD, "hwt_thread", "Hardware Trace");

static eventhandler_tag hwt_exit_tag;
static struct cdev *hwt_cdev;

static int
hwt_ioctl_send_records(struct hwt_context *ctx,
    struct hwt_record_get *record_get)
{
	struct hwt_record_entry *entry, *entry1;
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

	i = 0;

	mtx_lock(&ctx->mtx_records);
	LIST_FOREACH_SAFE(entry, &ctx->records, next, entry1) {
		user_entry[i].addr = entry->addr;
		user_entry[i].size = entry->size;
		user_entry[i].record_type = entry->record_type;
		user_entry[i].tid = entry->tid;
		if (entry->fullpath != NULL) {
			strncpy(user_entry[i].fullpath, entry->fullpath,
			    MAXPATHLEN);
			free(entry->fullpath, M_HWT_RECORD);
		}
		LIST_REMOVE(entry, next);

		free(entry, M_HWT_RECORD);

		i += 1;

		if (i == nitems_req)
			break;
	}
	mtx_unlock(&ctx->mtx_records);

	if (i > 0)
		error = copyout(user_entry, record_get->records,
		    sizeof(struct hwt_record_user_entry) * i);

	if (error == 0)
		error = copyout(&i, record_get->nentries, sizeof(int));

	free(user_entry, M_HWT_RECORD);

	return (error);
}

/*
 * Check if owner process *o can trace target process *t;
 */

static int
hwt_priv_check(struct proc *o, struct proc *t)
{
	struct ucred *oc, *tc;
	int error;
	int i;

	PROC_LOCK(o);
	oc = o->p_ucred;
	crhold(oc);
	PROC_UNLOCK(o);

	PROC_LOCK_ASSERT(t, MA_OWNED);
	tc = t->p_ucred;
	crhold(tc);

	error = 0;

	/*
	 * The effective uid of the HWT owner should match at least one
	 * of the effective / real / saved uids of the target process.
	 */

	if (oc->cr_uid != tc->cr_uid &&
	    oc->cr_uid != tc->cr_svuid &&
	    oc->cr_uid != tc->cr_ruid) {
		error = EPERM;
		goto done;
	}

	/*
	 * Everyone of the target's group ids must be in the owner's
	 * group list.
	 */
	for (i = 0; i < tc->cr_ngroups; i++)
		if (!groupmember(tc->cr_groups[i], oc)) {
			error = EPERM;
			goto done;
		}

	/* Check the read and saved GIDs too. */
	if (!groupmember(tc->cr_rgid, oc) ||
	    !groupmember(tc->cr_svgid, oc)) {
			error = EPERM;
			goto done;
	}

done:
	crfree(tc);
	crfree(oc);

	return (error);
}

static int
hwt_ioctl_alloc(struct thread *td, struct hwt_alloc *halloc)
{
	char backend_name[HWT_BACKEND_MAXNAMELEN];
	struct hwt_backend *backend;
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct hwt_owner *ho;
	struct proc *p;
	int error;

	if (halloc->bufsize > HWT_MAXBUFSIZE)
		return (EINVAL);
	if (halloc->bufsize % PAGE_SIZE)
		return (EINVAL);
	if (halloc->backend_name == NULL)
		return (EINVAL);

	error = copyinstr(halloc->backend_name, (void *)backend_name,
	    HWT_BACKEND_MAXNAMELEN, NULL);
	if (error)
		return (error);

	backend = hwt_backend_lookup(backend_name);
	if (backend == NULL)
		return (ENXIO);

	/* First get the owner. */
	ho = hwt_owner_lookup(td->td_proc);
	if (ho) {
		/* Check if the owner have this pid configured already. */
		ctx = hwt_owner_lookup_ctx(ho, halloc->pid);
		if (ctx)
			return (EEXIST);
	} else {
		/* Create a new owner. */
		ho = malloc(sizeof(struct hwt_owner), M_HWT_OWNER,
		    M_WAITOK | M_ZERO);
		ho->p = td->td_proc;
		LIST_INIT(&ho->hwts);
		mtx_init(&ho->mtx, "hwts", NULL, MTX_DEF);

		hwt_owner_insert(ho);
	}

	/* Allocate a new HWT context. */
	ctx = hwt_ctx_alloc();
	ctx->bufsize = halloc->bufsize;
	ctx->pid = halloc->pid;
	ctx->hwt_backend = backend;
	ctx->hwt_owner = ho;

	/* Allocate first thread and buffers. */
	error = hwt_thread_alloc(&thr, ctx->bufsize);
	if (error) {
		free(ctx, M_HWT_CTX);
		return (error);
	}

	/* Since we done with malloc, now get the victim proc. */
	p = pfind(halloc->pid);
	if (p == NULL) {
		hwt_thread_free(thr);
		free(ctx, M_HWT_CTX);
		return (ENXIO);
	}

	error = hwt_priv_check(td->td_proc, p);
	if (error) {
		hwt_thread_free(thr);
		free(ctx, M_HWT_CTX);
		PROC_UNLOCK(p);
		return (error);
	}

	thr->ctx = ctx;
	thr->tid = FIRST_THREAD_IN_PROC(p)->td_tid;
	thr->thread_id = atomic_fetchadd_int(&ctx->thread_counter, 1);

	hwt_thread_insert(ctx, thr);

	mtx_lock(&ho->mtx);
	LIST_INSERT_HEAD(&ho->hwts, ctx, next_hwts);
	mtx_unlock(&ho->mtx);

	p->p_flag2 |= P2_HWT;

	PROC_UNLOCK(p);

	error = hwt_thread_create_cdev(thr);
	if (error) {
		/* TODO: deallocate resources. */
		return (error);
	}

	/* Pass thread ID to user for mmap. */

	struct hwt_record_entry *entry;
	entry = malloc(sizeof(struct hwt_record_entry), M_HWT_RECORD,
	    M_WAITOK | M_ZERO);
	entry->record_type = HWT_RECORD_THREAD_CREATE;
	entry->tid = thr->tid;

	mtx_lock(&ctx->mtx_records);
	LIST_INSERT_HEAD(&ctx->records, entry, next);
	mtx_unlock(&ctx->mtx_records);

	return (0);
}

static int
hwt_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwt_record_get *rget;
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct hwt_owner *ho;
	struct hwt_start *s;
	struct proc *p;
	int error;

	switch (cmd) {
	case HWT_IOC_ALLOC:
		/* Allocate HWT context. */
		error = hwt_ioctl_alloc(td, (struct hwt_alloc *)addr);
		return (error);

	case HWT_IOC_START:
		/* Start tracing. */
		s = (struct hwt_start *)addr;

		dprintf("%s: start, pid %d\n", __func__, s->pid);

		ho = hwt_owner_lookup(td->td_proc);
		if (ho == NULL)
			return (ENXIO);

		ctx = hwt_owner_lookup_ctx(ho, s->pid);
		if (ctx == NULL)
			return (ENXIO);

		mtx_lock_spin(&ctx->mtx_threads);
		thr = LIST_FIRST(&ctx->threads);
		mtx_unlock_spin(&ctx->mtx_threads);

		KASSERT(thr != NULL, ("thr is NULL"));

		error = hwt_backend_init(ctx);
		if (error)
			return (error);

		p = pfind(s->pid);
		if (p == NULL) {
			/* TODO: deinit backend. */
			return (ENXIO);
		}

		ctx->proc = p;

		hwt_ctx_insert_contexthash(ctx);
		PROC_UNLOCK(p);

		return (0);

	case HWT_IOC_RECORD_GET:
		rget = (struct hwt_record_get *)addr;

		/* Check if process is registered owner of any HWTs. */
		ho = hwt_owner_lookup(td->td_proc);
		if (ho == NULL)
			return (ENXIO);

		ctx = hwt_owner_lookup_ctx(ho, rget->pid);
		if (ctx == NULL)
			return (ENXIO);

		error = hwt_ioctl_send_records(ctx, rget);
		return (error);
	default:
		return (ENXIO);
	};

	/* Unreached. */

	return (ENXIO);
}

void
hwt_switch_in(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_ctx_lookup_contexthash(p);
	if (ctx == NULL)
		return;
	thr = hwt_thread_lookup(ctx, td);

	printf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwt_backend_configure(thr, cpu_id);
	hwt_backend_enable(thr, cpu_id);
}

void
hwt_switch_out(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_ctx_lookup_contexthash(p);
	if (ctx == NULL)
		return;
	thr = hwt_thread_lookup(ctx, td);

	printf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwt_backend_disable(thr, cpu_id);
}

void
hwt_thread_exit(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_ctx_lookup_contexthash(p);
	if (ctx == NULL)
		return;
	thr = hwt_thread_lookup(ctx, td);

	printf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwt_backend_disable(thr, cpu_id);
}

static struct cdevsw hwt_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_mmap_single	= NULL,
	.d_ioctl	= hwt_ioctl
};

static void
hwt_stop_owner_hwts(struct hwt_owner *ho)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;

	printf("%s: stopping hwt owner\n", __func__);

	while (1) {
		mtx_lock(&ho->mtx);
		ctx = LIST_FIRST(&ho->hwts);
		if (ctx)
			LIST_REMOVE(ctx, next_hwts);
		mtx_unlock(&ho->mtx);

		if (ctx == NULL)
			break;

		hwt_backend_deinit(ctx);

		/* TODO: ensure ctx is in context hash before removal. */
		hwt_ctx_remove(ctx);

		printf("%s: remove threads\n", __func__);

		while (1) {
			mtx_lock_spin(&ctx->mtx_threads);
			thr = LIST_FIRST(&ctx->threads);
			if (thr)
				LIST_REMOVE(thr, next);
			mtx_unlock_spin(&ctx->mtx_threads);

			if (thr == NULL)
				break;

			/* TODO: hwt_thread_free instead ? */
			hwt_thread_destroy_buffers(thr);
			destroy_dev_sched(thr->cdev);
			free(thr, M_HWT_THREAD);
		}

		free(ctx, M_HWT_CTX);
	}

	hwt_owner_destroy(ho);
}

static void
hwt_process_exit(void *arg __unused, struct proc *p)
{
	struct hwt_owner *ho;

	/* Stop HWTs associated with exiting owner, if any. */
	ho = hwt_owner_lookup(p);
	if (ho)
		hwt_stop_owner_hwts(ho);
}

static int
hwt_load(void)
{
	struct make_dev_args args;
	int error;

	make_dev_args_init(&args);
	args.mda_devsw = &hwt_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = NULL;

	error = make_dev_s(&args, &hwt_cdev, "hwt");
	if (error != 0)
		return (error);

	hwt_context_load();
	hwt_backend_load();

	hwt_exit_tag = EVENTHANDLER_REGISTER(process_exit, hwt_process_exit,
	    NULL, EVENTHANDLER_PRI_ANY);

	return (0);
}

static int
hwt_unload(void)
{

	dprintf("%s\n", __func__);

	destroy_dev(hwt_cdev);

	return (0);
}

static int
hwt_modevent(module_t mod, int type, void *data)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		error = hwt_load();
		break;
	case MOD_UNLOAD:
		error = hwt_unload();
		break;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t hwt_mod = {
	"hwt",
	hwt_modevent,
	NULL
};

DECLARE_MODULE(hwt, hwt_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(hwt, 1);
