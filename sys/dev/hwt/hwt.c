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

#define	HWT_DEBUG
//#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	HWT_PROCHASH_SIZE	1024
#define	HWT_OWNERHASH_SIZE	1024

/*
 * Hash function.  Discard the lower 2 bits of the pointer since
 * these are always zero for our uses.  The hash multiplier is
 * round((2^LONG_BIT) * ((sqrt(5)-1)/2)).
 */

#define	_HWT_HM	11400714819323198486u	/* hash multiplier */
#define	HWT_HASH_PTR(P, M)	((((unsigned long) (P) >> 2) * _HWT_HM) & (M))

static eventhandler_tag hwt_exit_tag;

static struct mtx hwt_contexthash_mtx;
static u_long hwt_contexthashmask;
static LIST_HEAD(hwt_contexthash, hwt_context)	*hwt_contexthash;

static struct mtx hwt_ownerhash_mtx;
static u_long hwt_ownerhashmask;
static LIST_HEAD(hwt_ownerhash, hwt_owner)	*hwt_ownerhash;

static struct hwt_softc hwt_sc;
static struct hwt_backend *hwt_backend;

static void
hwt_event_init(struct hwt_context *hwt)
{

	printf("%s: cpu %d\n", __func__, hwt->cpu_id);

	hwt_backend->ops->hwt_event_init(hwt);
}

static int
hwt_event_start(struct hwt_context *hwt)
{

	printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_start(hwt);

	return (0);
}

static int
hwt_event_stop(struct hwt_context *hwt)
{

	printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_stop(hwt);

	return (0);
}

static int
hwt_event_enable(struct hwt_context *hwt)
{

	//printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_enable(hwt);

	return (0);
}

static int
hwt_event_disable(struct hwt_context *hwt)
{

	//printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_disable(hwt);

	return (0);
}

static int
hwt_event_dump(struct hwt_context *hwt)
{

	//printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_dump(hwt);

	return (0);
}

int
hwt_register(struct hwt_backend *backend)
{

	hwt_backend = backend;

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
hwt_alloc_pages(struct hwt_context *hwt)
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

	hwt->obj = cdev_pager_allocate(hwt, OBJT_MGTDEVICE, &hwt_pager_ops,
	    hwt->npages * PAGE_SIZE, PROT_READ, 0, curthread->td_ucred);

	VM_OBJECT_WLOCK(hwt->obj);
	for (i = 0; i < hwt->npages; i++) {
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

			VM_OBJECT_WUNLOCK(hwt->obj);
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
		hwt->pages[i] = m;

		vm_page_insert(m, hwt->obj, i);
	}

	VM_OBJECT_WUNLOCK(hwt->obj);

	return (0);
}

static int
hwt_open(struct cdev *cdev, int oflags, int devtype, struct thread *td)
{

	printf("%s\n", __func__);

	return (0);
}

static int
hwt_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct hwt_context *hwt;

	hwt = cdev->si_drv1;

	if (nprot != PROT_READ || *offset != 0)
		return (ENXIO);

	*objp = hwt->obj;

	return (0);
}

static struct cdevsw hwt_context_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_open		= hwt_open,
	.d_mmap_single	= hwt_mmap_single,
	.d_ioctl	= NULL,
};

static int
hwt_create_cdev(struct hwt_context *hwt)
{
	struct make_dev_args args;
	int error;

	dprintf("%s\n", __func__);

	make_dev_args_init(&args);
	args.mda_devsw = &hwt_context_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = hwt;

	error = make_dev_s(&args, &hwt->cdev, "hwt_%d%d", hwt->cpu_id, hwt->pid);
	if (error != 0)
		return (error);

	return (0);
}

static int
hwt_alloc_buffers(struct hwt_softc *sc, struct hwt_context *hwt)
{
	int error;

	hwt->npages = (16 * 1024 * 1024) / 4096;
	hwt->pages = malloc(sizeof(struct vm_page *) * hwt->npages, M_HWT,
	    M_WAITOK | M_ZERO);

	error = hwt_alloc_pages(hwt);
	if (error) {
		printf("%s: could not alloc pages\n", __func__);
		return (error);
	}

	return (0);
}

static void
hwt_destroy_buffers(struct hwt_context *hwt)
{
	vm_page_t m;
	int i;

	VM_OBJECT_WLOCK(hwt->obj);
	for (i = 0; i < hwt->npages; i++) {
		m = hwt->pages[i];
		if (m == NULL)
			break;

		vm_page_busy_acquire(m, 0);
		cdev_pager_free_page(hwt->obj, m);
		m->flags &= ~PG_FICTITIOUS;
		vm_page_unwire_noq(m);
		vm_page_free(m);

	}
	vm_pager_deallocate(hwt->obj);
	VM_OBJECT_WUNLOCK(hwt->obj);

	free(hwt->pages, M_HWT);
}

static struct hwt_context *
hwt_alloc(struct hwt_softc *sc, struct thread *td)
{
	struct hwt_context *hwt;
	int error;

	hwt = malloc(sizeof(struct hwt_context), M_HWT, M_WAITOK | M_ZERO);
	LIST_INIT(&hwt->records);

	error = hwt_alloc_buffers(sc, hwt);
	if (error) {
		printf("%s: can't allocate hwt\n", __func__);
		return (NULL);
	}

	return (hwt);
}

struct hwt_context *
hwt_lookup_contexthash(struct proc *p, int cpu_id)
{
	struct hwt_contexthash *hch;
	struct hwt_context *ctx;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_FOREACH(ctx, hch, next) {
		if (ctx->p == p && ctx->cpu_id == cpu_id) {
			mtx_unlock_spin(&hwt_contexthash_mtx);
			return (ctx);
		}
	}
	mtx_unlock_spin(&hwt_contexthash_mtx);

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
hwt_lookup_by_owner(struct hwt_owner *ho, int cpu_id, pid_t pid)
{
	struct hwt_context *ctx;

	mtx_lock(&ho->mtx);
	LIST_FOREACH(ctx, &ho->hwts, next1) {
		if (ctx->pid == pid && ctx->cpu_id == cpu_id) {
			mtx_unlock(&ho->mtx);
			return (ctx);
		}
	}
	mtx_unlock(&ho->mtx);

	return (NULL);
}

static struct hwt_context *
hwt_lookup_by_owner_p(struct proc *owner_p, int cpu_id, pid_t pid)
{
	struct hwt_context *ctx;
	struct hwt_owner *ho;

	ho = hwt_lookup_ownerhash(owner_p);
	if (ho == NULL)
		return (NULL);

	ctx = hwt_lookup_by_owner(ho, cpu_id, pid);

	return (ctx);
}

static void
hwt_insert_ctxhash(struct hwt_context *ctx)
{
	struct hwt_contexthash *hch;
	int hindex;

	hindex = HWT_HASH_PTR(ctx->p, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_INSERT_HEAD(hch, ctx, next);
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
	    M_DEVBUF, M_WAITOK);

	i = 0;

	mtx_lock_spin(&ctx->mtx);
	LIST_FOREACH_SAFE(entry, &ctx->records, next, entry1) {
		user_entry[i].addr = entry->addr;
		user_entry[i].size = entry->size;
		strncpy(user_entry[i].fullpath, entry->fullpath,
		    MAXPATHLEN);
		LIST_REMOVE(entry, next);

		i += 1;

		/* TODO: deallocate entry. */

		if (i == nitems_req)
			break;
	}
	mtx_unlock_spin(&ctx->mtx);

	if (i == 0)
		return (ENOENT);

	error = copyout(user_entry, record_get->records,
	    sizeof(struct hwt_record_user_entry) * i);
	if (error)
		return (error);

	error = copyout(&i, record_get->nentries, sizeof(int));

	free(user_entry, M_DEVBUF);

	return (error);
}

static int
hwt_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwt_softc *sc;
	struct hwt_start *s;
	struct hwt_alloc *halloc;
	struct hwt_record_get *rget;
	struct proc *p;
	struct hwt_context *hwt __unused;
	struct hwt_owner *ho;
	struct hwt_ownerhash *hoh;
	int hindex;
	int error;
	int len;

	error = 0;

	sc = dev->si_drv1;

	len = IOCPARM_LEN(cmd);

	dprintf("%s: cmd %lx, addr %lx, len %d\n", __func__, cmd,
	    (uint64_t)addr, len);

	switch (cmd) {
	/* Allocate HWT context. */
	case HWT_IOC_ALLOC:
		halloc = (struct hwt_alloc *)addr;

		/* TODO: check cpu_id field for sanity. */

		/* First get the owner. */
		ho = hwt_lookup_ownerhash(td->td_proc);
		if (ho) {
			hwt = hwt_lookup_by_owner(ho, halloc->cpu_id, halloc->pid);
			if (hwt)
				return (EEXIST);
		} else {
			ho = malloc(sizeof(struct hwt_owner), M_HWT,
			    M_WAITOK | M_ZERO);
			ho->p = td->td_proc;
			LIST_INIT(&ho->hwts);
			mtx_init(&ho->mtx, "hwts", NULL, MTX_DEF);

			mtx_lock_spin(&hwt_ownerhash_mtx);
			hindex = HWT_HASH_PTR(ho->p, hwt_ownerhashmask);
			hoh = &hwt_ownerhash[hindex];
			LIST_INSERT_HEAD(hoh, ho, next);
			mtx_unlock_spin(&hwt_ownerhash_mtx);
		}

		/* Allocate a new HWT. */
		hwt = hwt_alloc(sc, td);
		if (hwt == NULL) {
			/* TODO: remove ho if it was created. */
			return (ENOMEM);
		}

		hwt->cpu_id = halloc->cpu_id;
		hwt->pid = halloc->pid;
		hwt->p = NULL;
		hwt->hwt_owner = ho;

		error = hwt_create_cdev(hwt);
		if (error) {
			printf("%s: could not create cdev\n", __func__);
			return (error);
		}

		/* Since we done with malloc, now get the victim proc. */
		p = pfind(halloc->pid);
		if (p == NULL) {
			/* TODO: deallocate resources. */
			return (ENXIO);
		}

		hwt->p = p;

		mtx_lock(&ho->mtx);
		LIST_INSERT_HEAD(&ho->hwts, hwt, next1);
		mtx_unlock(&ho->mtx);

		hwt_insert_ctxhash(hwt);

		p->p_flag2 |= P2_HWT;
		PROC_UNLOCK(p);
		break;
	case HWT_IOC_START:
		s = (struct hwt_start *)addr;

		dprintf("%s: start, cpu_id %d pid %d\n", __func__, s->cpu_id, s->pid);

		/* Check if process is registered owner of any HWTs. */
		hwt = hwt_lookup_by_owner_p(td->td_proc, s->cpu_id, s->pid);
		if (hwt == NULL)
			return (ENXIO);

		hwt_event_init(hwt);
		hwt_event_start(hwt);

		hwt->started = 1;

		break;
	case HWT_IOC_RECORD_GET:
		rget = (struct hwt_record_get *)addr;

		/* Check if process is registered owner of any HWTs. */
		hwt = hwt_lookup_by_owner_p(td->td_proc, rget->cpu_id, rget->pid);
		if (hwt == NULL)
			return (ENXIO);

		error = hwt_send_records(rget, hwt);
	default:
		break;
	};

	return (error);
}

void
hwt_switch_in(struct thread *td)
{
	struct hwt_context *ctx;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu_id = PCPU_GET(cpuid);

	dprintf("%s\n", __func__);

	ctx = hwt_lookup_contexthash(p, cpu_id);
	if (!ctx)
		panic("no ctx");

	dprintf("%s: ctx %p on cpu_id %d\n", __func__, ctx, cpu_id);

	if (ctx->started)
		hwt_event_enable(ctx);
}

void
hwt_switch_out(struct thread *td)
{
	struct hwt_context *ctx;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_lookup_contexthash(p, cpu_id);

	dprintf("%s: ctx %p from cpu_id %d\n", __func__, ctx, cpu_id);

	if (ctx->started) {
		hwt_event_disable(ctx);
		hwt_event_dump(ctx);
	}
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

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_FOREACH_SAFE(ctx, hch, next, ctx1) {
		if (ctx->p == p) {
			printf("%s: stopping proc hwts on cpu %d\n", __func__,
			    ctx->cpu_id);
			ctx->started = 0;
			hwt_event_disable(ctx);
			hwt_event_dump(ctx);
			hwt_event_stop(ctx);

			LIST_REMOVE(ctx, next);
			ctx->p = NULL;
			ctx->exited = 1;
		}
	}
	mtx_unlock_spin(&hwt_contexthash_mtx);
}

static void
hwt_stop_owner_hwts(struct hwt_contexthash *hch, struct hwt_owner *ho)
{
	struct hwt_context *ctx, *ctx1;

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_FOREACH_SAFE(ctx, hch, next, ctx1) {
		if (ctx->hwt_owner == ho) {
			printf("%s: stopping owner hwts on cpu %d\n", __func__,
			    ctx->cpu_id);
			ctx->started = 0;
			hwt_event_disable(ctx);
			hwt_event_dump(ctx);
			hwt_event_stop(ctx);
			LIST_REMOVE(ctx, next);
		}
	}
	mtx_unlock_spin(&hwt_contexthash_mtx);

	printf("%s: stopping hwt owner\n", __func__);

	mtx_lock(&ho->mtx);
	LIST_FOREACH_SAFE(ctx, &ho->hwts, next1, ctx1) {
		LIST_REMOVE(ctx, next1);
		dprintf("stopping hwt cpu_id %d pid %d\n",
		    ctx->cpu_id, ctx->pid);
		hwt_destroy_buffers(ctx);
		destroy_dev_sched(ctx->cdev);
		free(ctx, M_HWT);
	}
	mtx_unlock(&ho->mtx);

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
		/*
		 * Stop HWTs associated with exiting owner.
		 * Detach associated procs.
		 */
		hwt_stop_owner_hwts(hch, ho);
	} else {
		/* Stop HWTs associated with exiting proc. */
		hwt_stop_proc_hwts(hch, p);
	}
}

static int
hwt_load(void)
{
	struct make_dev_args args;
	struct hwt_softc *sc;
	int error;

	sc = &hwt_sc;

	dprintf("%s\n", __func__);

	mtx_init(&sc->mtx, "HWT driver", NULL, MTX_DEF);

	TAILQ_INIT(&sc->hwt_backends);

	make_dev_args_init(&args);
	args.mda_devsw = &hwt_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = sc;

	error = make_dev_s(&args, &sc->hwt_cdev, "hwt");
	if (error != 0)
		return (error);

	hwt_contexthash = hashinit(HWT_PROCHASH_SIZE, M_HWT, &hwt_contexthashmask);
        mtx_init(&hwt_contexthash_mtx, "hwt-proc-hash", "hwt-proc", MTX_SPIN);

	hwt_ownerhash = hashinit(HWT_OWNERHASH_SIZE, M_HWT, &hwt_ownerhashmask);
        mtx_init(&hwt_ownerhash_mtx, "hwt-owner-hash", "hwt-owner", MTX_SPIN);

	hwt_exit_tag = EVENTHANDLER_REGISTER(process_exit, hwt_process_exit,
	    NULL, EVENTHANDLER_PRI_ANY);

	return (0);
}

static int
hwt_unload(void)
{
	struct hwt_softc *sc;

	dprintf("%s\n", __func__);

	sc = &hwt_sc;

	destroy_dev(sc->hwt_cdev);
	mtx_destroy(&sc->mtx);

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

DECLARE_MODULE(hwt, hwt_mod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_VERSION(hwt, 1);
