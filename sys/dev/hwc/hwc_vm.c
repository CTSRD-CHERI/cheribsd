/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023-2025 Ruslan Bukin <br@bsdpad.com>
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
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/hwc.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>

#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_contexthash.h>
#include <dev/hwc/hwc_owner.h>
#include <dev/hwc/hwc_ownerhash.h>
#include <dev/hwc/hwc_backend.h>
#include <dev/hwc/hwc_vm.h>

#define	HWC_THREAD_DEBUG
#undef	HWC_THREAD_DEBUG

#ifdef	HWC_THREAD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static MALLOC_DEFINE(M_HWC_VM, "hwc_vm", "Hardware Counters");

static int
hwc_vm_open(struct cdev *cdev, int oflags, int devtype, struct thread *td)
{

	dprintf("%s\n", __func__);

	return (0);
}

static int
hwc_vm_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct hwc_configure *hc;
	struct hwc_start *hstart;
	struct hwc_stop *hstop;
	struct hwc_context *ctx;
	struct hwc_vm *vm;
	struct hwc_owner *ho;
	int error;

	vm = dev->si_drv1;
	KASSERT(vm != NULL, ("si_drv1 is NULL"));

	ctx = vm->ctx;

	/* Ensure process is registered owner of this HWC. */
	ho = hwc_ownerhash_lookup(td->td_proc);
	if (ho == NULL)
		return (ENXIO);

	if (ctx->hwc_owner != ho)
		return (EPERM);

	switch (cmd) {
	case HWC_IOC_START:
		dprintf("%s: start tracing\n", __func__);

		HWC_CTX_LOCK(ctx);
		if (ctx->state == CTX_STATE_RUNNING) {
			/* Already running ? */
			HWC_CTX_UNLOCK(ctx);
			return (ENXIO);
		}
		ctx->state = CTX_STATE_RUNNING;
		HWC_CTX_UNLOCK(ctx);

		hstart = (struct hwc_start *)addr;
		error = hwc_backend_start(ctx, hstart);
		if (error)
			return (error);
		break;
	case HWC_IOC_STOP:
		hstop = (struct hwc_stop *)addr;
		error = hwc_backend_stop(ctx, hstop);
		if (error)
			return (error);
		ctx->state = CTX_STATE_STOPPED;
		break;
	case HWC_IOC_CONFIGURE:
		hc = (struct hwc_configure *)addr;
		hwc_backend_configure(ctx, hc);
		break;
	default:
		break;
	}

	return (0);
}

static struct cdevsw hwc_vm_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwc",
	.d_open		= hwc_vm_open,
	.d_mmap_single	= NULL,
	.d_ioctl	= hwc_vm_ioctl,
};

static int
hwc_vm_create_cdev(struct hwc_vm *vm, char *path)
{
	struct make_dev_args args;
	int error;

	dprintf("%s: path %s\n", __func__, path);

	make_dev_args_init(&args);
	args.mda_devsw = &hwc_vm_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = vm;

	error = make_dev_s(&args, &vm->cdev, "%s", path);
	if (error != 0)
		return (error);

	return (0);
}

void
hwc_vm_free(struct hwc_vm *vm)
{

	dprintf("%s\n", __func__);

	if (vm->cdev)
		destroy_dev_sched(vm->cdev);
	free(vm, M_HWC_VM);
}

int
hwc_vm_alloc(size_t bufsize, int kva_req, char *path, struct hwc_vm **vm0)
{
	struct hwc_vm *vm;
	int error;

	vm = malloc(sizeof(struct hwc_vm), M_HWC_VM, M_WAITOK | M_ZERO);

	error = hwc_vm_create_cdev(vm, path);
	if (error) {
		hwc_vm_free(vm);
		return (error);
	}

	*vm0 = vm;

	return (0);
}
