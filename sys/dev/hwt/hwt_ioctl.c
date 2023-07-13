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
#include <sys/smp.h>
#include <sys/hwt.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_contexthash.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_owner.h>
#include <dev/hwt/hwt_ownerhash.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_record.h>
#include <dev/hwt/hwt_ioctl.h>
#include <dev/hwt/hwt_vm.h>

#define	HWT_IOCTL_DEBUG
#undef	HWT_IOCTL_DEBUG

#ifdef	HWT_IOCTL_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

/* No real reason for these limitations just sanity checks. */
#define	HWT_MAXBUFSIZE		(32UL * 1024 * 1024 * 1024) /* 32 GB */
#define	HWT_MAXCONFIGSIZE	1024

static MALLOC_DEFINE(M_HWT_IOCTL, "hwt_ioctl", "Hardware Trace");

/*
 * Check if owner process *o can trace target process *t.
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
hwt_ioctl_send_records(struct hwt_context *ctx,
    struct hwt_record_get *record_get)
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
	    M_HWT_IOCTL, M_WAITOK | M_ZERO);

	i = hwt_record_grab(ctx, user_entry, nitems_req);
	if (i > 0)
		error = copyout(user_entry, record_get->records,
		    sizeof(struct hwt_record_user_entry) * i);

	if (error == 0)
		error = copyout(&i, record_get->nentries, sizeof(int));

	free(user_entry, M_HWT_IOCTL);

	return (error);
}

static int
hwt_ioctl_alloc_mode_thread(struct thread *td, struct hwt_owner *ho,
    struct hwt_backend *backend, struct hwt_alloc *halloc)
{
	char path[MAXPATHLEN];
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int error;

	/* Check if the owner have this pid configured already. */
	ctx = hwt_owner_lookup_ctx(ho, halloc->pid);
	if (ctx)
		return (EEXIST);

	/* Allocate a new HWT context. */
	ctx = hwt_ctx_alloc();
	ctx->bufsize = halloc->bufsize;
	ctx->pid = halloc->pid;
	ctx->hwt_backend = backend;
	ctx->hwt_owner = ho;
	ctx->mode = HWT_MODE_THREAD;

	/* Allocate first thread and buffers. */
	error = hwt_thread_alloc(&thr, ctx->bufsize);
	if (error) {
		hwt_ctx_free(ctx);
		return (error);
	}
	thr->vm->ctx = ctx;

	/* Since we done with malloc, now get the victim proc. */
	p = pfind(halloc->pid);
	if (p == NULL) {
		hwt_thread_free(thr);
		hwt_ctx_free(ctx);
		return (ENXIO);
	}

	/* Ensure we can trace it. */
	error = hwt_priv_check(td->td_proc, p);
	if (error) {
		hwt_thread_free(thr);
		hwt_ctx_free(ctx);
		PROC_UNLOCK(p);
		return (error);
	}

	/* All good. */
	thr->ctx = ctx;
	thr->tid = FIRST_THREAD_IN_PROC(p)->td_tid;
	thr->session_id = atomic_fetchadd_int(&ctx->session_counter, 1);

	HWT_CTX_LOCK(ctx);
	hwt_thread_insert(ctx, thr);
	HWT_CTX_UNLOCK(ctx);

	/* hwt_owner_insert_ctx? */
	mtx_lock(&ho->mtx);
	LIST_INSERT_HEAD(&ho->hwts, ctx, next_hwts);
	mtx_unlock(&ho->mtx);

	p->p_flag2 |= P2_HWT;

	ctx->proc = p;
	hwt_contexthash_insert(ctx);
	PROC_UNLOCK(p);

	error = hwt_backend_init(ctx);
	if (error) {
		/* TODO: deallocate resources. */
		return (error);
	}

	sprintf(path, "hwt_%d_%d", ctx->pid, thr->tid);
	error = hwt_vm_create_cdev(thr->vm, path);
	if (error) {
		/* TODO: deallocate resources. */
		return (error);
	}

	/* Pass thread ID to user for mmap. */
	hwt_record_thread(thr);

	return (0);
}

static int
hwt_ioctl_alloc_mode_cpu(struct thread *td, struct hwt_owner *ho,
    struct hwt_backend *backend, struct hwt_alloc *halloc)
{
	struct hwt_context *ctx;
	struct hwt_vm *vm;
	char path[MAXPATHLEN];
	int error;
	int cpu;

	cpu = halloc->cpu;
	if (CPU_ABSENT(cpu) || CPU_ISSET(cpu, &hlt_cpus_mask))
		return (ENXIO);

	/* Check if the owner have this cpu configured already. */
	ctx = hwt_owner_lookup_ctx_by_cpu(ho, halloc->cpu);
	if (ctx)
		return (EEXIST);

	/* Allocate a new HWT context. */
	ctx = hwt_ctx_alloc();
	ctx->bufsize = halloc->bufsize;
	ctx->cpu = cpu;
	ctx->hwt_backend = backend;
	ctx->hwt_owner = ho;
	ctx->mode = HWT_MODE_CPU;

	vm = hwt_vm_alloc();
	vm->ctx = ctx;
	vm->npages = ctx->bufsize / PAGE_SIZE;

	ctx->vm = vm;

	/* Allocate buffers. */
	error = hwt_vm_alloc_buffers(vm);
	if (error) {
		hwt_ctx_free(ctx);
		return (error);
	}

	/* hwt_owner_insert_ctx? */
	mtx_lock(&ho->mtx);
	LIST_INSERT_HEAD(&ho->hwts, ctx, next_hwts);
	mtx_unlock(&ho->mtx);

	error = hwt_backend_init(ctx);
	if (error) {
		/* TODO: deallocate resources. */
		return (error);
	}

	sprintf(path, "hwt_%d", ctx->cpu);

	error = hwt_vm_create_cdev(ctx->vm, path);
	if (error) {
		/* TODO: deallocate resources. */
		return (error);
	}

	return (0);
}

static int
hwt_ioctl_alloc(struct thread *td, struct hwt_alloc *halloc)
{
	char backend_name[HWT_BACKEND_MAXNAMELEN];
	struct hwt_backend *backend;
	struct hwt_owner *ho;
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
	ho = hwt_ownerhash_lookup(td->td_proc);
	if (ho == NULL) {
		/* Create a new owner. */
		ho = hwt_owner_alloc(td->td_proc);
		if (ho == NULL)
			return (ENOMEM);
		hwt_ownerhash_insert(ho);
	}

	switch (halloc->mode) {
	case HWT_MODE_THREAD:
		error = hwt_ioctl_alloc_mode_thread(td, ho, backend, halloc);
		break;
	case HWT_MODE_CPU:
		error = hwt_ioctl_alloc_mode_cpu(td, ho, backend, halloc);
		break;
	default:
		error = ENXIO;
	};

	return (error);
}

static int
hwt_ioctl_set_config(struct thread *td, struct hwt_context *ctx,
    struct hwt_set_config *sconf)
{
	size_t config_size;
	void *old_config;
	void *config;
	int error;

	config_size = sconf->config_size;
	if (config_size == 0)
		return (0);

	if (config_size > HWT_MAXCONFIGSIZE)
		return (EFBIG);

	config = malloc(config_size, M_HWT_IOCTL, M_WAITOK | M_ZERO);

	error = copyin(sconf->config, config, config_size);
	if (error) {
		free(config, M_HWT_IOCTL);
		return (error);
	}

	HWT_CTX_LOCK(ctx);
	old_config = ctx->config;
	ctx->config = config;
	ctx->config_size = sconf->config_size;
	ctx->config_version = sconf->config_version;
	HWT_CTX_UNLOCK(ctx);

	if (old_config != NULL)
		free(old_config, M_HWT_IOCTL);

	return (error);
}

int
hwt_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwt_record_get *rget;
	struct hwt_set_config *sconf;
	struct hwt_context *ctx;
	struct hwt_owner *ho;
	struct hwt_start *s;
	struct hwt_wakeup *hwakeup;
	struct hwt_thread *thr;
	int error;

	/* Check if process is registered owner of any HWTs. */
	ho = hwt_ownerhash_lookup(td->td_proc);
	if (ho == NULL && cmd != HWT_IOC_ALLOC)
		return (ENXIO);

	switch (cmd) {
	case HWT_IOC_ALLOC:
		/* Allocate HWT context. */
		error = hwt_ioctl_alloc(td, (struct hwt_alloc *)addr);
		return (error);

	case HWT_IOC_START:
		/* Start tracing. */
		s = (struct hwt_start *)addr;
		dprintf("%s: start, pid %d\n", __func__, s->pid);
		ctx = hwt_owner_lookup_ctx(ho, s->pid);
		if (ctx == NULL)
			return (ENXIO);

		HWT_CTX_LOCK(ctx);
		if (ctx->state == CTX_STATE_RUNNING) {
			/* Already running ? */
			HWT_CTX_UNLOCK(ctx);
			return (ENXIO);
		}
		ctx->state = CTX_STATE_RUNNING;
		HWT_CTX_UNLOCK(ctx);

		return (0);

	case HWT_IOC_RECORD_GET:
		rget = (struct hwt_record_get *)addr;
		ctx = hwt_owner_lookup_ctx(ho, rget->pid);
		if (ctx == NULL)
			return (ENXIO);

		error = hwt_ioctl_send_records(ctx, rget);
		return (error);

	case HWT_IOC_SET_CONFIG:
		sconf = (struct hwt_set_config *)addr;
		ctx = hwt_owner_lookup_ctx(ho, sconf->pid);
		if (ctx == NULL)
			return (ENXIO);

		error = hwt_ioctl_set_config(td, ctx, sconf);
		if (error)
			return (error);

		ctx->pause_on_mmap = sconf->pause_on_mmap ? 1 : 0;

		return (0);
	case HWT_IOC_WAKEUP:
		hwakeup = (struct hwt_wakeup *)addr;
		ctx = hwt_owner_lookup_ctx(ho, hwakeup->pid);
		if (ctx == NULL)
			return (ENXIO);

		HWT_CTX_LOCK(ctx);
		thr = hwt_thread_lookup_by_tid(ctx, hwakeup->tid);
		if (thr)
			HWT_THR_LOCK(thr);
		HWT_CTX_UNLOCK(ctx);

		if (thr == NULL)
			return (ENOENT);

		wakeup(thr);

		HWT_THR_UNLOCK(thr);

		return (0);
	default:
		return (ENXIO);
	};
}
