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

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_owner.h>
#include <dev/hwt/hwt_ownerhash.h>
#include <dev/hwt/hwt_backend.h>

#define	HWT_THREAD_DEBUG
#undef	HWT_THREAD_DEBUG

#ifdef	HWT_THREAD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static MALLOC_DEFINE(M_HWT_THREAD, "hwt_thread", "Hardware Trace");

static int
hwt_thread_fault(vm_object_t vm_obj, vm_ooffset_t offset,
    int prot, vm_page_t *mres)
{

	return (0);
}

static int
hwt_thread_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
    vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	*color = 0;

	return (0);
}

static void
hwt_thread_dtor(void *handle)
{

}

static struct cdev_pager_ops hwt_thread_pager_ops = {
	.cdev_pg_fault = hwt_thread_fault,
	.cdev_pg_ctor = hwt_thread_ctor,
	.cdev_pg_dtor = hwt_thread_dtor
}; 

struct hwt_thread *
hwt_thread_first(struct hwt_context *ctx)
{
	struct hwt_thread *thr;

	HWT_CTX_ASSERT_LOCKED(ctx);

	thr = LIST_FIRST(&ctx->threads);

	KASSERT(thr != NULL, ("thr is NULL"));

	return (thr);
}

static int
hwt_thread_alloc_pages(struct hwt_thread *thr)
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
	memattr = VM_MEMATTR_DEVICE;

	thr->obj = cdev_pager_allocate(thr, OBJT_MGTDEVICE,
	    &hwt_thread_pager_ops, thr->npages * PAGE_SIZE, PROT_READ, 0,
	    curthread->td_ucred);

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
		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);
#endif

		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);

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
hwt_thread_open(struct cdev *cdev, int oflags, int devtype, struct thread *td)
{

	dprintf("%s\n", __func__);

	return (0);
}

static int
hwt_thread_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{
	struct hwt_thread *thr;

	thr = cdev->si_drv1;

	if (nprot != PROT_READ || *offset != 0)
		return (ENXIO);

	*objp = thr->obj;

	return (0);
}

static int
hwt_thread_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwt_bufptr_get *ptr_get;
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct hwt_owner *ho;
	vm_offset_t curpage_offset;
	int curpage;
	int error;

	thr = dev->si_drv1;

	switch (cmd) {
	case HWT_IOC_BUFPTR_GET:
		ptr_get = (struct hwt_bufptr_get *)addr;

		/* Check if process is registered owner of any HWTs. */
		ho = hwt_ownerhash_lookup(td->td_proc);
		if (ho == NULL)
			return (ENXIO);

		ctx = hwt_owner_lookup_ctx(ho, ptr_get->pid);
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
	.d_open		= hwt_thread_open,
	.d_mmap_single	= hwt_thread_mmap_single,
	.d_ioctl	= hwt_thread_ioctl,
};

int
hwt_thread_create_cdev(struct hwt_thread *thr, pid_t pid)
{
	struct make_dev_args args;
	int error;

	printf("%s: pid %d tid %d\n", __func__, pid, thr->tid);

	make_dev_args_init(&args);
	args.mda_devsw = &hwt_thread_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = thr;

	error = make_dev_s(&args, &thr->cdev, "hwt_%d_%d", pid, thr->tid);
	if (error != 0)
		return (error);

	return (0);
}

static int
hwt_thread_alloc_buffers(struct hwt_thread *thr)
{
	int error;

	thr->pages = malloc(sizeof(struct vm_page *) * thr->npages,
	    M_HWT_THREAD, M_WAITOK | M_ZERO);

	error = hwt_thread_alloc_pages(thr);
	if (error) {
		printf("%s: could not alloc pages\n", __func__);
		return (error);
	}

	return (0);
}

void
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

	free(thr->pages, M_HWT_THREAD);
}

/*
 * To use by hwt_switch_in/out() only.
 */
struct hwt_thread *
hwt_thread_lookup(struct hwt_context *ctx, struct thread *td)
{
	struct hwt_thread *thr, *thr1;

	HWT_CTX_ASSERT_LOCKED(ctx);

	LIST_FOREACH_SAFE(thr, &ctx->threads, next, thr1) {
		if (thr->tid == td->td_tid) {
			return (thr);
		}
	}

	panic("thread not found");
}

int
hwt_thread_alloc(struct hwt_thread **thr0, size_t bufsize)
{
	struct hwt_thread *thr;
	int error;

	thr = malloc(sizeof(struct hwt_thread), M_HWT_THREAD,
	    M_WAITOK | M_ZERO);
	thr->npages = bufsize / PAGE_SIZE;

	error = hwt_thread_alloc_buffers(thr);
	if (error)
		return (error);

	*thr0 = thr;

	return (0);
}

void
hwt_thread_free(struct hwt_thread *thr)
{

	hwt_thread_destroy_buffers(thr);

	free(thr, M_HWT_THREAD);
}

void
hwt_thread_insert(struct hwt_context *ctx, struct hwt_thread *thr)
{

	HWT_CTX_ASSERT_LOCKED(ctx);

	LIST_INSERT_HEAD(&ctx->threads, thr, next);
}
