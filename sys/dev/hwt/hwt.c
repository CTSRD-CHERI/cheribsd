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
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
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

struct hwt_proc {
	struct proc		*p;
	struct hwt		*hwt;
	struct hwt_owner	*hwt_owner;
	LIST_ENTRY(hwt_proc)	next;
};

struct hwt {
	vm_page_t		*pages;
	int			npages;
	int			hwt_id;
	struct hwt_owner	*hwt_owner;
	LIST_ENTRY(hwt)		next;
};

struct hwt_owner {
	struct proc		*p;
	LIST_HEAD(, hwt)	hwts; /* Owned HWTs. */
	LIST_ENTRY(hwt_owner)	next;
};

#define	HWT_PROCHASH_SIZE	1024
#define	HWT_OWNERHASH_SIZE	1024

struct mtx hwt_prochash_mtx;
static u_long hwt_prochashmask;
static LIST_HEAD(hwt_prochash, hwt_proc)	*hwt_prochash;

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

int
hwt_register(void)
{

	return (0);
}

static int
hwt_alloc_pages(vm_page_t *pages, int npages)
{
	vm_paddr_t low, high, boundary;
	vm_memattr_t memattr;
	int alignment;
	vm_pointer_t va;
	int pflags;
	vm_page_t m;
	int tries;
	int i;

	alignment = PAGE_SIZE;
	low = 0;
	high = -1UL;
	boundary = 0;
	pflags = VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY | VM_ALLOC_WIRED |
	    VM_ALLOC_ZERO;
	memattr = VM_MEMATTR_WRITE_COMBINING;

	for (i = 0; i < npages; i++) {
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

		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);

		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);
		m->valid = VM_PAGE_BITS_ALL;
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;

		pages[i] = m;
        }

	return (0);
}

static int
hwt_alloc_buffers(struct hwt_softc *sc, struct hwt *hwt)
{
	vm_page_t *m;
	struct sglist *sg;
	int error;
	int i;

	hwt->npages = 1024;
	hwt->pages = malloc(sizeof(struct vm_page *) * hwt->npages, M_HWT,
	    M_WAITOK | M_ZERO);

	error = hwt_alloc_pages(hwt->pages, hwt->npages);
	if (error) {
		printf("%s: could not alloc pages\n", __func__);
		return (error);
	}

	sg = sglist_alloc(hwt->npages, M_WAITOK);

	for (i = 0; i < hwt->npages; i++) {
		m = &hwt->pages[i];
		error = sglist_append_vmpages(sg, m, 0, PAGE_SIZE);
		if (error != 0) {
			printf("%s: cant add pages\n", __func__);
			return (error);
		}
	}

printf("%s: pages added to sg\n", __func__);

	return (0);
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
hwt_lookup_proc(struct proc *p)
{
	struct hwt_prochash *hph;
	struct hwt_proc *hp;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_prochashmask);
	hph = &hwt_prochash[hindex];

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_FOREACH(hp, hph, next) {
		if (hp->p == p) {
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

	mtx_lock_spin(&hwt_prochash_mtx);
	LIST_FOREACH(ho, hoh, next) {
		if (ho->p == p) {
			mtx_unlock_spin(&hwt_prochash_mtx);
			return (ho);
		}
	}
	mtx_unlock_spin(&hwt_prochash_mtx);

	return (NULL);
}

static struct hwt *
hwt_lookup_by_id(struct hwt_owner *ho, int hwt_id)
{
	struct hwt *hwt;

	LIST_FOREACH(hwt, &ho->hwts, next) {
		if (hwt->hwt_id == hwt_id) {
			return (hwt);
		}
	}

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
			hindex = HWT_HASH_PTR(ho->p, hwt_ownerhashmask);
			hoh = &hwt_ownerhash[hindex];
			LIST_INSERT_HEAD(hoh, ho, next);
		}

		LIST_INSERT_HEAD(&ho->hwts, hwt, next);

		hwt->hwt_id = 111;
		hwt->hwt_owner = ho;
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

		hp = hwt_lookup_proc(p);
		if (hp) {
			/* Already attached. */
			free(hpnew, M_HWT);
			break;
		}

		p->p_flag2 |= P2_HWT;
		hpnew->p = p;
		hpnew->hwt_owner = ho;
		hpnew->hwt = hwt;
		hwt_insert_prochash(hpnew);

		//struct coresight_event event;

		PROC_UNLOCK(p);
		break;
	case HWT_IOC_START:
		//coresight_init_event();
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

	p = td->td_proc;

	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	hp = hwt_lookup_proc(p);

	dprintf("%s: hp %p\n", __func__, hp);
}

void
hwt_switch_out(struct thread *td)
{
	struct hwt_proc *hp;
	struct proc *p;

	p = td->td_proc;

	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	hp = hwt_lookup_proc(p);

	dprintf("%s: hp %p\n", __func__, hp);
}

static int
hwt_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{

	return (0);
}

static struct cdevsw hwt_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwt",
	.d_mmap_single	= hwt_mmap_single,
	.d_ioctl	= hwt_ioctl
};

static int
hwt_load(void)
{
	struct make_dev_args args;
	struct hwt_softc *sc;
	int error;

	sc = &hwt_sc;

	dprintf("%s\n", __func__);

	mtx_init(&sc->mtx, "HWT driver", NULL, MTX_DEF);

	TAILQ_INIT(&sc->hwt_devices);

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
        mtx_init(&hwt_prochash_mtx, "hwt-proc-hash", "hwt-leaf", MTX_SPIN);

	hwt_ownerhash = hashinit(HWT_OWNERHASH_SIZE, M_HWT, &hwt_ownerhashmask);

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
