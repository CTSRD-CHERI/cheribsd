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

/* Hardware Trace (HWT) module. */

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

static eventhandler_tag hwt_exit_tag;

struct mtx hwt_prochash_mtx;
static u_long hwt_prochashmask;
static LIST_HEAD(hwt_prochash, hwt_proc)	*hwt_prochash;

struct mtx hwt_ownerhash_mtx;
static u_long hwt_ownerhashmask;
static LIST_HEAD(hwt_ownerhash, hwt_owner)	*hwt_ownerhash;

/*
 * Hash function.  Discard the lower 2 bits of the pointer since
 * these are always zero for our uses.  The hash multiplier is
 * round((2^LONG_BIT) * ((sqrt(5)-1)/2)).
 */

#define	_HWT_HM	11400714819323198486u	/* hash multiplier */
#define	HWT_HASH_PTR(P, M)	((((unsigned long) (P) >> 2) * _HWT_HM) & (M))

struct hwt_softc hwt_sc;

static struct hwt_backend *hwt_backend;

static int
hwt_event_init(struct hwt *hwt)
{

	printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_init(hwt);

	return (0);
}

static int
hwt_event_start(struct hwt *hwt)
{

	printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_start(hwt);

	return (0);
}

static int
hwt_event_enable(struct hwt *hwt)
{

	//printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_enable(hwt);

	return (0);
}

static int
hwt_event_disable(struct hwt *hwt)
{

	//printf("%s\n", __func__);

	hwt_backend->ops->hwt_event_disable(hwt);

	return (0);
}

static int
hwt_event_dump(struct hwt *hwt)
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
hwt_alloc_pages(struct hwt *hwt)
{
	vm_paddr_t low, high, boundary;
	vm_memattr_t memattr;
	vm_pointer_t va;
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
	memattr = VM_MEMATTR_WRITE_COMBINING;

	hwt->obj = vm_pager_allocate(OBJT_PHYS, 0, hwt->npages * PAGE_SIZE,
	    PROT_READ, 0, curthread->td_ucred);

	VM_OBJECT_WLOCK(hwt->obj);

	for (i = 0; i < hwt->npages; i++) {
		tries = 0;
retry:
		m = vm_page_alloc_contig(hwt->obj, i, pflags, 1, low, high,
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

		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);

		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);
		m->valid = VM_PAGE_BITS_ALL;
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;

		hwt->pages[i] = m;
	}

	VM_OBJECT_WUNLOCK(hwt->obj);

	return (0);
}

static int
hwt_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct hwt *hwt;

	hwt = cdev->si_drv1;

	if (nprot != PROT_READ || *offset != 0)
		return (ENXIO);

	*objp = hwt->obj;

	return (0);
}

static struct cdevsw hwt_context_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_mmap_single	= hwt_mmap_single,
	.d_ioctl	= NULL,
};

static int
hwt_create_cdev(struct hwt *hwt)
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

	error = make_dev_s(&args, &hwt->cdev, "hwt_ctx_%d", hwt->hwt_id);
	if (error != 0)
		return (error);

	return (0);
}

static int
hwt_alloc_buffers(struct hwt_softc *sc, struct hwt *hwt)
{
	int error;

	hwt->npages = 4096 * 8;
	hwt->pages = malloc(sizeof(struct vm_page *) * hwt->npages, M_HWT,
	    M_WAITOK | M_ZERO);

	error = hwt_alloc_pages(hwt);
	if (error) {
		printf("%s: could not alloc pages\n", __func__);
		return (error);
	}

#if 0
	struct sglist *sg;
	vm_page_t *m;
	int i;

	sg = sglist_alloc(hwt->npages, M_WAITOK);
	if (sg == NULL) {
		printf("%s: could not allocate sg\n", __func__);
		return (ENOMEM);
	}

	for (i = 0; i < hwt->npages; i++) {
		m = &hwt->pages[i];
		//printf("page %d maxseg %d\n", i, sg->sg_maxseg);
		error = sglist_append_vmpages(sg, m, 0, PAGE_SIZE);
		if (error != 0) {
			printf("%s: cant add pages, error %d\n",
			    __func__, error);
			return (error);
		}
	}

printf("%s: pages added to sg\n", __func__);
#endif

	return (0);
}

static void
hwt_destroy_buffers(struct hwt *hwt)
{
	vm_page_t m;
	int i;

	VM_OBJECT_WLOCK(hwt->obj);
	for (i = 0; i < hwt->npages; i++) {
		m = hwt->pages[i];
		if (m == NULL)
			break;

		vm_page_busy_acquire(m, 0);
		m->oflags |= VPO_UNMANAGED;
		m->flags &= ~PG_FICTITIOUS;
		vm_page_unwire_noq(m);
		vm_page_free(m);
	}
	vm_pager_deallocate(hwt->obj);
	VM_OBJECT_WUNLOCK(hwt->obj);

	free(hwt->pages, M_HWT);
}

static struct hwt *
hwt_alloc(struct hwt_softc *sc, struct thread *td)
{
	struct hwt *hwt;
	int error;

	hwt = malloc(sizeof(struct hwt), M_HWT, M_WAITOK | M_ZERO);

	error = hwt_alloc_buffers(sc, hwt);
	if (error) {
		printf("%s: can't allocate hwt\n", __func__);
		return (NULL);
	}

	return (hwt);
}

static struct hwt_proc *
hwt_lookup_proc_by_cpu(struct proc *p, int cpu)
{
	struct hwt_prochash *hph;
	struct hwt_proc *hp;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_prochashmask);
	hph = &hwt_prochash[hindex];

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_FOREACH(hp, hph, next) {
		if (hp->p == p && hp->cpu_id == cpu) {
			mtx_unlock_spin(&hwt_prochash_mtx);
			return (hp);
		}
	}
	mtx_unlock_spin(&hwt_prochash_mtx);

	return (NULL);
}

static struct hwt_proc *
hwt_lookup_proc_by_hwt(struct proc *p, struct hwt *hwt)
{
	struct hwt_prochash *hph;
	struct hwt_proc *hp;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_prochashmask);
	hph = &hwt_prochash[hindex];

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_FOREACH(hp, hph, next) {
		if (hp->p == p && hp->hwt == hwt) {
			mtx_unlock_spin(&hwt_prochash_mtx);
			return (hp);
		}
	}
	mtx_unlock_spin(&hwt_prochash_mtx);

	return (NULL);
}

static struct hwt_owner *
hwt_lookup_owner(struct proc *p)
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

static struct hwt *
hwt_lookup_by_id(struct hwt_owner *ho, int hwt_id)
{
	struct hwt *hwt;

	mtx_lock(&ho->mtx);
	LIST_FOREACH(hwt, &ho->hwts, next) {
		if (hwt->hwt_id == hwt_id) {
			mtx_unlock(&ho->mtx);
			return (hwt);
		}
	}
	mtx_unlock(&ho->mtx);

	return (NULL);
}

static void
hwt_insert_prochash(struct hwt_proc *hp)
{
	struct hwt_prochash *hph;
	int hindex;

	hindex = HWT_HASH_PTR(hp->p, hwt_prochashmask);
	hph = &hwt_prochash[hindex];

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_INSERT_HEAD(hph, hp, next);
	mtx_unlock_spin(&hwt_prochash_mtx);
}

static int
hwt_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwt_softc *sc;
	struct hwt_attach *a;
	struct hwt_start *s;
	struct proc *p;
	int error;
	struct hwt_proc *hp, *hpnew;
	struct hwt *hwt __unused;
	struct hwt_owner *ho;
	struct hwt_ownerhash *hoh;
	int hindex;

	int len;

	error = 0;

	sc = dev->si_drv1;

	len = IOCPARM_LEN(cmd);

	dprintf("%s: cmd %lx, addr %lx, len %d\n", __func__, cmd,
	    (uint64_t)addr, len);

	struct hwt_alloc *halloc;

	switch (cmd) {
	case HWT_IOC_ALLOC:

		halloc = (struct hwt_alloc *)addr;

		hwt = hwt_alloc(sc, td);
		if (hwt == NULL)
			return (ENOMEM);

		p = td->td_proc;

		ho = hwt_lookup_owner(p);
		if (ho == NULL) {
			ho = malloc(sizeof(struct hwt_owner), M_HWT,
			    M_WAITOK | M_ZERO);
			ho->p = p;
			LIST_INIT(&ho->hwts);
			mtx_init(&ho->mtx, "hwts", NULL, MTX_DEF);

			mtx_lock_spin(&hwt_ownerhash_mtx);
			hindex = HWT_HASH_PTR(ho->p, hwt_ownerhashmask);
			hoh = &hwt_ownerhash[hindex];
			LIST_INSERT_HEAD(hoh, ho, next);
			mtx_unlock_spin(&hwt_ownerhash_mtx);
		}

		hwt->cpu_id = halloc->cpu_id;
		hwt->hwt_id = 110 + hwt->cpu_id;
		hwt->hwt_owner = ho;

		mtx_lock(&ho->mtx);
		LIST_INSERT_HEAD(&ho->hwts, hwt, next);
		mtx_unlock(&ho->mtx);

		error = hwt_create_cdev(hwt);
		if (error) {
			printf("%s: could not create cdev\n", __func__);
			/* TODO */
			return (error);
		}

		error = copyout(&hwt->hwt_id, halloc->hwt_id,
		    sizeof(hwt->hwt_id));

		break;

	case HWT_IOC_ATTACH:
		a = (void *)addr;

		dprintf("%s: attach, pid %d, hwt_id %d\n", __func__, a->pid,
		    a->hwt_id);

		/* Check if process is registered owner of any HWTs. */
		ho = hwt_lookup_owner(td->td_proc);
		if (ho == NULL) {
			/* No HWTs allocated. So nothing attach to. */
			return (ENXIO);
		}

		/* Now find HWT we want to attach to. */
		hwt = hwt_lookup_by_id(ho, a->hwt_id);
		if (hwt == NULL) {
			/* No HWT with such id. */
			return (ENXIO);
		}

		hpnew = malloc(sizeof(struct hwt_proc), M_HWT,
		    M_WAITOK | M_ZERO);

		p = pfind(a->pid);
		if (p == NULL)
			break;

		dprintf("%s: proc %p\n", __func__, p);

		hp = hwt_lookup_proc_by_hwt(p, hwt);
		if (hp) {
			/* Already attached. */
			free(hpnew, M_HWT);
			PROC_UNLOCK(p);
			break;
		}

		p->p_flag2 |= P2_HWT;
		hpnew->p = p;
		hpnew->hwt_owner = ho;
		hpnew->hwt = hwt;
		hpnew->cpu_id = hwt->cpu_id;
		hwt_insert_prochash(hpnew);

		PROC_UNLOCK(p);
		break;
	case HWT_IOC_START:
		s = (struct hwt_start *)addr;

		dprintf("%s: start, hwt_id %d\n", __func__, s->hwt_id);

		/* Check if process is registered owner of any HWTs. */
		ho = hwt_lookup_owner(td->td_proc);
		if (ho == NULL) {
			/* No HWTs allocated. So nothing to attach to. */
			return (ENXIO);
		}

		/* Now find HWT we want to activate. */
		hwt = hwt_lookup_by_id(ho, s->hwt_id);
		if (hwt == NULL) {
			/* No HWT with such id. */
			return (ENXIO);
		}

		printf("%s: initing hwt %p\n", __func__, hwt);
		hwt_event_init(hwt);

		printf("%s: starting hwt %p\n", __func__, hwt);
		hwt_event_start(hwt);

		hwt->started = 1;

		break;
	default:
		break;
	};

	return (error);
}

void
hwt_switch_in(struct thread *td)
{
	struct hwt_proc *hp;
	struct proc *p;
	int cpu;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu = PCPU_GET(cpuid);

	hp = hwt_lookup_proc_by_cpu(p, cpu);

	//dprintf("%s: hp %p\n", __func__, hp);

	if (hp->hwt->started)
		hwt_event_enable(hp->hwt);
}

void
hwt_switch_out(struct thread *td)
{
	struct hwt_proc *hp;
	struct proc *p;
	int cpu;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	cpu = PCPU_GET(cpuid);

	hp = hwt_lookup_proc_by_cpu(p, cpu);

	//dprintf("%s: hp %p\n", __func__, hp);

	if (hp->hwt->started) {
		hwt_event_disable(hp->hwt);
		hwt_event_dump(hp->hwt);
	}
}

static struct cdevsw hwt_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_mmap_single	= NULL,
	.d_ioctl	= hwt_ioctl
};

static void
hwt_stop_proc_hwts(struct hwt_prochash *hph, struct proc *p)
{
	struct hwt_proc *hp, *hp1;
	struct hwt *hwt;

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_FOREACH_SAFE(hp, hph, next, hp1) {
		if (hp->p == p) {
			printf("%s: stopping hwt on cpu %d\n", __func__,
			    hp->cpu_id);
			hwt = hp->hwt;
			hwt->started = 0;
			hwt_event_disable(hwt);
			hwt_event_dump(hwt);
			LIST_REMOVE(hp, next);
		}
	}
	mtx_unlock_spin(&hwt_prochash_mtx);
}

static void
hwt_stop_owner_hwts(struct hwt_prochash *hph, struct hwt_owner *ho)
{
	struct hwt_proc *hp, *hp1;
	struct hwt *hwt_tmp;
	struct hwt *hwt;

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_FOREACH_SAFE(hp, hph, next, hp1) {
		if (hp->hwt_owner == ho) {
			printf("%s: stopping hwt on cpu %d\n", __func__,
			    hp->cpu_id);
			hwt = hp->hwt;
			hwt->started = 0;
			hwt_event_disable(hwt);
			hwt_event_dump(hwt);
			LIST_REMOVE(hp, next);
		}
	}
	mtx_unlock_spin(&hwt_prochash_mtx);

	printf("%s: stopping hwt owner\n", __func__);

	mtx_lock(&ho->mtx);
	LIST_FOREACH_SAFE(hwt, &ho->hwts, next, hwt_tmp) {
		LIST_REMOVE(hwt, next);
printf("stopping hwt %d\n", hwt->hwt_id);
		hwt_destroy_buffers(hwt);
		destroy_dev_sched(hwt->cdev);
		free(hwt, M_HWT);
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
	struct hwt_prochash *hph;
	struct hwt_owner *ho;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_prochashmask);
	hph = &hwt_prochash[hindex];

	ho = hwt_lookup_owner(p);
	if (ho == NULL) {
		/* Stop HWTs associated with exiting proc. */
		hwt_stop_proc_hwts(hph, p);
	} else {
		/*
		 * Stop HWTs associated with exiting owner.
		 * Detach associated procs.
		 */
		hwt_stop_owner_hwts(hph, ho);
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

	hwt_prochash = hashinit(HWT_PROCHASH_SIZE, M_HWT, &hwt_prochashmask);
        mtx_init(&hwt_prochash_mtx, "hwt-proc-hash", "hwt-proc", MTX_SPIN);

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
