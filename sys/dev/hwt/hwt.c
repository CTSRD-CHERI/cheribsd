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

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwtvar.h>
#include <dev/hwt/hwt.h>

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	HWT_PROCHASH_SIZE	1024
#define	HWT_OWNERHASH_SIZE	1024

/* No real reason for this limitation except sanity checks. */
#define	HWT_MAXBUFSIZE		(1U * 1024 * 1024 * 1024) /* 1 GB */

MALLOC_DEFINE(M_HWT, "hwt", "Hardware Trace");

/*
 * Hash function.  Discard the lower 2 bits of the pointer since
 * these are always zero for our uses.  The hash multiplier is
 * round((2^LONG_BIT) * ((sqrt(5)-1)/2)).
 */

#define	_HWT_HM	11400714819323198486u	/* hash multiplier */
#define	HWT_HASH_PTR(P, M)	((((unsigned long) (P) >> 2) * _HWT_HM) & (M))

static struct mtx hwt_contexthash_mtx;
static u_long hwt_contexthashmask;
static LIST_HEAD(hwt_contexthash, hwt_context)	*hwt_contexthash;

static struct mtx hwt_ownerhash_mtx;
static u_long hwt_ownerhashmask;
static LIST_HEAD(hwt_ownerhash, hwt_owner)	*hwt_ownerhash;

static eventhandler_tag hwt_exit_tag;
static struct cdev *hwt_cdev;

static struct mtx hwt_backend_mtx;
static LIST_HEAD(, hwt_backend)	hwt_backends;

static int
hwt_backend_init(struct hwt_thread *thr)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	ctx->hwt_backend->ops->hwt_backend_init(thr);

	return (0);
}

static int
hwt_backend_deinit(struct hwt_context *ctx)
{

	printf("%s\n", __func__);

	ctx->hwt_backend->ops->hwt_backend_deinit();

	return (0);
}

static int
hwt_backend_configure(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	ctx->hwt_backend->ops->hwt_backend_configure(thr, cpu_id);

	return (0);
}

static int
hwt_backend_enable(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	ctx->hwt_backend->ops->hwt_backend_enable(thr, cpu_id);

	return (0);
}

static int
hwt_backend_disable(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	ctx->hwt_backend->ops->hwt_backend_disable(thr, cpu_id);

	return (0);
}

static int __unused
hwt_backend_dump(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	ctx->hwt_backend->ops->hwt_backend_dump(thr, cpu_id);

	return (0);
}

static int
hwt_backend_read(struct hwt_thread *thr, int *curpage,
    vm_offset_t *curpage_offset)
{
	struct hwt_context *ctx;
	int error;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	error = ctx->hwt_backend->ops->hwt_backend_read(thr, 0, curpage,
	    curpage_offset);

	return (error);
}

static struct hwt_backend *
hwt_lookup_backend(const char *name)
{
	struct hwt_backend *backend;

	mtx_lock_spin(&hwt_backend_mtx);
	LIST_FOREACH(backend, &hwt_backends, next) {
		if (strcmp(backend->name, name) == 0) {
			mtx_unlock_spin(&hwt_backend_mtx);
			return (backend);
		}
	}
	mtx_unlock_spin(&hwt_backend_mtx);

	return (NULL);
}

int
hwt_register(struct hwt_backend *backend)
{

	if (backend == NULL ||
	    backend->name == NULL ||
	    backend->ops == NULL)
		return (EINVAL);

	mtx_lock_spin(&hwt_backend_mtx);
	LIST_INSERT_HEAD(&hwt_backends, backend, next);
	mtx_unlock_spin(&hwt_backend_mtx);

	return (0);
}

static int
hwt_fault(vm_object_t vm_obj, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{

	return (0);
}

static int
hwt_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	*color = 0;

	return (0);
}

static void
hwt_dtor(void *handle)
{

}

static struct cdev_pager_ops hwt_pager_ops = {
	.cdev_pg_fault = hwt_fault,
	.cdev_pg_ctor = hwt_ctor,
	.cdev_pg_dtor = hwt_dtor
}; 

static int
hwt_thread_alloc_pages(struct hwt_thread *thr)
{
	vm_paddr_t low, high, boundary;
	vm_memattr_t memattr;
	int alignment;
	vm_page_t m;
	int pflags;
	int tries;
	int i;

	alignment = PAGE_SIZE;
	low = 0;
	high = -1UL;
	boundary = 0;
	pflags = VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY | VM_ALLOC_WIRED |
	    VM_ALLOC_ZERO;
	memattr = VM_MEMATTR_DEVICE;

	thr->obj = cdev_pager_allocate(thr, OBJT_MGTDEVICE, &hwt_pager_ops,
	    thr->npages * PAGE_SIZE, PROT_READ, 0, curthread->td_ucred);

	for (i = 0; i < thr->npages; i++) {
		tries = 0;
retry:
		m = vm_page_alloc_noobj_contig(pflags, 1, low, high,
		    alignment, boundary, memattr);
		if (m == NULL) {
			if (tries < 3) {
				if (!vm_page_reclaim_contig(pflags, 1, low,
				    high, alignment, boundary))
					vm_wait(NULL);
				tries++;
				goto retry;
			}

			return (ENOMEM);
		}

#if 0
		/* TODO */
		vm_pointer_t va;

		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);

		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);
#endif
		m->valid = VM_PAGE_BITS_ALL;
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;
		thr->pages[i] = m;

		VM_OBJECT_WLOCK(thr->obj);
		vm_page_insert(m, thr->obj, i);
		VM_OBJECT_WUNLOCK(thr->obj);
	}

	return (0);
}

static int
hwt_open(struct cdev *cdev, int oflags, int devtype, struct thread *td)
{

	dprintf("%s\n", __func__);

	return (0);
}

static int
hwt_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct hwt_thread *thr;

	thr = cdev->si_drv1;

	if (nprot != PROT_READ || *offset != 0)
		return (ENXIO);

	*objp = thr->obj;

	return (0);
}

static struct hwt_context *
hwt_lookup_by_owner(struct hwt_owner *ho, pid_t pid)
{
	struct hwt_context *ctx;

	mtx_lock(&ho->mtx);
	LIST_FOREACH(ctx, &ho->hwts, next_hwts) {
		if (ctx->pid == pid) {
			mtx_unlock(&ho->mtx);
			return (ctx);
		}
	}
	mtx_unlock(&ho->mtx);

	return (NULL);
}

static struct hwt_owner *
hwt_lookup_ownerhash(struct proc *p)
{
	struct hwt_ownerhash *hoh;
	struct hwt_owner *ho;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_ownerhashmask);
	hoh = &hwt_ownerhash[hindex];

	mtx_lock_spin(&hwt_ownerhash_mtx);
	LIST_FOREACH(ho, hoh, next) {
		if (ho->p == p) {
			mtx_unlock_spin(&hwt_ownerhash_mtx);
			return (ho);
		}
	}
	mtx_unlock_spin(&hwt_ownerhash_mtx);

	return (NULL);
}

static struct hwt_context *
hwt_lookup_by_owner_p(struct proc *owner_p, pid_t pid)
{
	struct hwt_context *ctx;
	struct hwt_owner *ho;

	ho = hwt_lookup_ownerhash(owner_p);
	if (ho == NULL)
		return (NULL);

	ctx = hwt_lookup_by_owner(ho, pid);

	return (ctx);
}

static int
hwt_thread_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwt_bufptr_get *ptr_get;
	struct hwt_context *ctx;
	vm_offset_t curpage_offset;
	struct hwt_thread *thr;
	int curpage;
	int error;

	thr = dev->si_drv1;

	switch (cmd) {
	case HWT_IOC_BUFPTR_GET:
		ptr_get = (struct hwt_bufptr_get *)addr;

		/* Check if process is registered owner of any HWTs. */
		ctx = hwt_lookup_by_owner_p(td->td_proc, ptr_get->pid);
		if (ctx == NULL)
			return (ENXIO);

		if (ctx != thr->ctx)
			return (ENXIO);

		hwt_backend_read(thr, &curpage, &curpage_offset);

		error = copyout(&curpage, ptr_get->curpage, sizeof(int));
		if (error)
			return (error);
		error = copyout(&curpage_offset, ptr_get->curpage_offset,
		    sizeof(vm_offset_t));
		if (error)
			return (error);

		break;
	default:
		break;
	}

	return (0);
}

static struct cdevsw hwt_thread_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_open		= hwt_open,
	.d_mmap_single	= hwt_mmap_single,
	.d_ioctl	= hwt_thread_ioctl,
};

static int
hwt_create_cdev(struct hwt_thread *thr)
{
	struct make_dev_args args;
	struct hwt_context *ctx;
	int error;

	ctx = thr->ctx;

	printf("%s: pid %d tid %d\n", __func__, ctx->pid, thr->tid);

	make_dev_args_init(&args);
	args.mda_devsw = &hwt_thread_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = thr;

	error = make_dev_s(&args, &thr->cdev, "hwt_%d_%d", ctx->pid, thr->tid);
	if (error != 0)
		return (error);

	return (0);
}

static int
hwt_thread_alloc_buffers(struct hwt_thread *thr)
{
	int error;

	thr->pages = malloc(sizeof(struct vm_page *) * thr->npages, M_HWT,
	    M_WAITOK | M_ZERO);

	error = hwt_thread_alloc_pages(thr);
	if (error) {
		printf("%s: could not alloc pages\n", __func__);
		return (error);
	}

	return (0);
}

static void
hwt_thread_destroy_buffers(struct hwt_thread *thr)
{
	vm_page_t m;
	int i;

	VM_OBJECT_WLOCK(thr->obj);
	for (i = 0; i < thr->npages; i++) {
		m = thr->pages[i];
		if (m == NULL)
			break;

		vm_page_busy_acquire(m, 0);
		cdev_pager_free_page(thr->obj, m);
		m->flags &= ~PG_FICTITIOUS;
		vm_page_unwire_noq(m);
		vm_page_free(m);

	}
	vm_pager_deallocate(thr->obj);
	VM_OBJECT_WUNLOCK(thr->obj);

	free(thr->pages, M_HWT);
}

static struct hwt_context *
hwt_alloc(void)
{
	struct hwt_context *ctx;

	ctx = malloc(sizeof(struct hwt_context), M_HWT, M_WAITOK | M_ZERO);
	LIST_INIT(&ctx->records);
	mtx_init(&ctx->mtx_records, "hwt records", NULL, MTX_DEF);

	LIST_INIT(&ctx->threads);
	mtx_init(&ctx->mtx_threads, "hwt threads", NULL, MTX_SPIN);

	return (ctx);
}

/*
 * To use by hwt_switch_in/out() and hwt_record() only.
 */
struct hwt_context *
hwt_lookup_contexthash(struct proc *p)
{
	struct hwt_contexthash *hch;
	struct hwt_context *ctx;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_FOREACH(ctx, hch, next_hch) {
		if (ctx->proc == p) {
			mtx_unlock_spin(&hwt_contexthash_mtx);
			return (ctx);
		}
	}
	mtx_unlock_spin(&hwt_contexthash_mtx);

	panic("ctx not found");
}

/*
 * To use by hwt_switch_in/out() only.
 */
static struct hwt_thread *
hwt_lookup_thread(struct hwt_context *ctx, struct thread *td)
{
	struct hwt_thread *thr, *thr1;

	mtx_lock_spin(&ctx->mtx_threads);
	LIST_FOREACH_SAFE(thr, &ctx->threads, next, thr1) {
		if (thr->tid == td->td_tid) {
			mtx_unlock_spin(&ctx->mtx_threads);
			return (thr);
		}
	}
	mtx_unlock_spin(&ctx->mtx_threads);

	panic("thread not found");
}

static void
hwt_insert_contexthash(struct hwt_context *ctx)
{
	struct hwt_contexthash *hch;
	int hindex;

	PROC_LOCK_ASSERT(ctx->proc, MA_OWNED);

	hindex = HWT_HASH_PTR(ctx->proc, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_INSERT_HEAD(hch, ctx, next_hch);
	mtx_unlock_spin(&hwt_contexthash_mtx);
}

static int
hwt_send_records(struct hwt_record_get *record_get, struct hwt_context *ctx)
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
	    M_HWT, M_WAITOK | M_ZERO);

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
			free(entry->fullpath, M_HWT);
		}
		LIST_REMOVE(entry, next);

		free(entry, M_HWT);

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

	free(user_entry, M_HWT);

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
hwt_thread_alloc(struct hwt_thread **thr0, size_t bufsize)
{
	struct hwt_thread *thr;
	int error;

	thr = malloc(sizeof(struct hwt_thread), M_HWT, M_WAITOK | M_ZERO);
	thr->npages = bufsize / PAGE_SIZE;

	error = hwt_thread_alloc_buffers(thr);
	if (error)
		return (error);

	*thr0 = thr;

	return (0);
}

static void
hwt_thread_free(struct hwt_thread *thr)
{

	hwt_thread_destroy_buffers(thr);

	free(thr, M_HWT);
}

int
hwt_thread_create(struct hwt_context *ctx, struct thread *td)
{
	struct hwt_thread *thr;
	int error;

	error = hwt_thread_alloc(&thr, ctx->bufsize);
	if (error)
		return (error);

	thr->ctx = ctx;
	thr->tid = td->td_tid;

	error = hwt_create_cdev(thr);
	if (error) {
		printf("%s: could not create cdev, error %d\n",
		    __func__, error);
		return (error);
	}

	mtx_lock_spin(&ctx->mtx_threads);
	LIST_INSERT_HEAD(&ctx->threads, thr, next);
	mtx_unlock_spin(&ctx->mtx_threads);

	return (0);
}

static int
hwt_ioctl_alloc(struct thread *td, struct hwt_alloc *halloc)
{
	char backend_name[HWT_BACKEND_MAXNAMELEN];
	struct hwt_backend *backend;
	struct hwt_ownerhash *hoh;
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct hwt_owner *ho;
	struct proc *p;
	int hindex;
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

	backend = hwt_lookup_backend(backend_name);
	if (backend == NULL)
		return (ENXIO);

	/* First get the owner. */
	ho = hwt_lookup_ownerhash(td->td_proc);
	if (ho) {
		/* Check if the owner have this pid configured already. */
		ctx = hwt_lookup_by_owner(ho, halloc->pid);
		if (ctx)
			return (EEXIST);
	} else {
		/* Create a new owner. */
		ho = malloc(sizeof(struct hwt_owner), M_HWT,
		    M_WAITOK | M_ZERO);
		ho->p = td->td_proc;
		LIST_INIT(&ho->hwts);
		mtx_init(&ho->mtx, "hwts", NULL, MTX_DEF);

		hindex = HWT_HASH_PTR(ho->p, hwt_ownerhashmask);
		hoh = &hwt_ownerhash[hindex];

		mtx_lock_spin(&hwt_ownerhash_mtx);
		LIST_INSERT_HEAD(hoh, ho, next);
		mtx_unlock_spin(&hwt_ownerhash_mtx);
	}

	/* Allocate a new HWT context. */
	ctx = hwt_alloc();
	ctx->bufsize = halloc->bufsize;
	ctx->pid = halloc->pid;
	ctx->hwt_backend = backend;
	ctx->hwt_owner = ho;

	/* Allocate first thread and buffers. */
	error = hwt_thread_alloc(&thr, ctx->bufsize);
	if (error) {
		free(ctx, M_HWT);
		return (error);
	}

	/* Since we done with malloc, now get the victim proc. */
	p = pfind(halloc->pid);
	if (p == NULL) {
		hwt_thread_free(thr);
		free(ctx, M_HWT);
		return (ENXIO);
	}

	error = hwt_priv_check(td->td_proc, p);
	if (error) {
		hwt_thread_free(thr);
		free(ctx, M_HWT);
		PROC_UNLOCK(p);
		return (error);
	}

	thr->ctx = ctx;
	thr->tid = FIRST_THREAD_IN_PROC(p)->td_tid;

	mtx_lock_spin(&ctx->mtx_threads);
	LIST_INSERT_HEAD(&ctx->threads, thr, next);
	mtx_unlock_spin(&ctx->mtx_threads);

	p->p_flag2 |= P2_HWT;

	mtx_lock(&ho->mtx);
	LIST_INSERT_HEAD(&ho->hwts, ctx, next_hwts);
	mtx_unlock(&ho->mtx);
	PROC_UNLOCK(p);

	error = hwt_create_cdev(thr);
	if (error) {
		/* TODO: deallocate resources. */
		return (error);
	}

	/* Pass thread ID to user for mmap. */

	struct hwt_record_entry *entry;
	entry = malloc(sizeof(struct hwt_record_entry), M_HWT,
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

		ctx = hwt_lookup_by_owner_p(td->td_proc, s->pid);
		if (ctx == NULL)
			return (ENXIO);

		mtx_lock_spin(&ctx->mtx_threads);
		thr = LIST_FIRST(&ctx->threads);
		mtx_unlock_spin(&ctx->mtx_threads);

		KASSERT(thr != NULL, ("thr is NULL"));

		/* Pass first thread as needed by Coresight, not Intel PT. */
		error = hwt_backend_init(thr);
		if (error)
			return (error);

		p = pfind(s->pid);
		if (p == NULL) {
			/* TODO: deinit backend. */
			return (ENXIO);
		}

		ctx->proc = p;

		hwt_insert_contexthash(ctx);
		PROC_UNLOCK(p);

		return (0);

	case HWT_IOC_RECORD_GET:
		rget = (struct hwt_record_get *)addr;

		/* Check if process is registered owner of any HWTs. */
		ctx = hwt_lookup_by_owner_p(td->td_proc, rget->pid);
		if (ctx == NULL)
			return (ENXIO);

		error = hwt_send_records(rget, ctx);
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

	ctx = hwt_lookup_contexthash(p);
	thr = hwt_lookup_thread(ctx, td);

	dprintf("%s: thr %p on cpu_id %d\n", __func__, thr, cpu_id);

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

	ctx = hwt_lookup_contexthash(p);
	thr = hwt_lookup_thread(ctx, td);

	dprintf("%s: thr %p on cpu_id %d\n", __func__, thr, cpu_id);

	hwt_backend_disable(thr, cpu_id);
}

static struct cdevsw hwt_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_mmap_single	= NULL,
	.d_ioctl	= hwt_ioctl
};

static void
hwt_stop_proc_hwts(struct hwt_contexthash *hch, struct proc *p)
{
	struct hwt_context *ctx, *ctx1;

	printf("%s: stopping hwt proc\n", __func__);

	PROC_LOCK(p);
	p->p_flag2 &= ~P2_HWT;

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_FOREACH_SAFE(ctx, hch, next_hch, ctx1) {
		if (ctx->proc == p) {
			printf("%s: stopping proc hwt\n", __func__);

			LIST_REMOVE(ctx, next_hch);
			hwt_backend_deinit(ctx);

			ctx->proc = NULL;
		}
	}
	mtx_unlock_spin(&hwt_contexthash_mtx);
	PROC_UNLOCK(p);
}

static void
hwt_stop_owner_hwts(struct hwt_contexthash *hch, struct hwt_owner *ho)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;

	printf("%s: stopping hwt owner\n", __func__);

	while (1) {
		mtx_lock(&ho->mtx);
		ctx = LIST_FIRST(&ho->hwts);
		if (ctx)
			LIST_REMOVE(ctx, next_hwts);
		mtx_unlock(&ho->mtx);

		if (ctx == NULL)
			break;

		p = pfind(ctx->pid);
		if (p != NULL) {
			printf("stopping hwt pid %d\n", ctx->pid);

			if (ctx->proc) {
				/* Remove it from contexthash now. */
				mtx_lock_spin(&hwt_contexthash_mtx);
				LIST_REMOVE(ctx, next_hch);

				ctx->proc = NULL;
				mtx_unlock_spin(&hwt_contexthash_mtx);
			}

			/* Stop it now on every CPU. */
			hwt_backend_deinit(ctx);

			PROC_UNLOCK(p);
			printf("pid %d stopped\n", ctx->pid);
		}

		printf("%s: remove threads\n", __func__);

		while (1) {
			mtx_lock_spin(&ctx->mtx_threads);
			thr = LIST_FIRST(&ctx->threads);
			if (thr)
				LIST_REMOVE(thr, next);
			mtx_unlock_spin(&ctx->mtx_threads);

			if (thr == NULL)
				break;

			hwt_thread_destroy_buffers(thr);
			destroy_dev_sched(thr->cdev);
			free(thr, M_HWT);
		}

		free(ctx, M_HWT);
	}

	/* Destroy hwt owner. */
	mtx_lock_spin(&hwt_ownerhash_mtx);
	LIST_REMOVE(ho, next);
	mtx_unlock_spin(&hwt_ownerhash_mtx);

	free(ho, M_HWT);
}

static void
hwt_process_exit(void *arg __unused, struct proc *p)
{
	struct hwt_contexthash *hch;
	struct hwt_owner *ho;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	ho = hwt_lookup_ownerhash(p);
	if (ho) {
		/* Stop HWTs associated with exiting owner. */
		hwt_stop_owner_hwts(hch, ho);
	} else if (p->p_flag2 & P2_HWT) {
		/* Stop HWTs associated with exiting proc. */
		hwt_stop_proc_hwts(hch, p);
	}
}

static int
hwt_load(void)
{
	struct make_dev_args args;
	int error;

	LIST_INIT(&hwt_backends);

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

	hwt_contexthash = hashinit(HWT_PROCHASH_SIZE, M_HWT,
	    &hwt_contexthashmask);
        mtx_init(&hwt_contexthash_mtx, "hwt-proc-hash", "hwt-proc", MTX_SPIN);

	hwt_ownerhash = hashinit(HWT_OWNERHASH_SIZE, M_HWT, &hwt_ownerhashmask);
        mtx_init(&hwt_ownerhash_mtx, "hwt-owner-hash", "hwt-owner", MTX_SPIN);

	mtx_init(&hwt_backend_mtx, "hwt backend", NULL, MTX_SPIN);

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
