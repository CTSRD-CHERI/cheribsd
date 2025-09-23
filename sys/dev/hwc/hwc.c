/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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

/* Hardware Counting Framework */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_contexthash.h>
#if 0
#include <dev/hwc/hwc_thread.h>
#endif
#include <dev/hwc/hwc_owner.h>
#include <dev/hwc/hwc_ownerhash.h>
#include <dev/hwc/hwc_backend.h>
#if 0
#include <dev/hwc/hwc_record.h>
#endif
#include <dev/hwc/hwc_ioctl.h>
#include <dev/hwc/hwc_hook.h>

#define	HWC_DEBUG
#undef	HWC_DEBUG

#ifdef	HWC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static eventhandler_tag hwc_exit_tag;
static struct cdev *hwc_cdev;
static struct cdevsw hwc_cdevsw = {
	.d_version	= D_VERSION,
	.d_name		= "hwc",
	.d_mmap_single	= NULL,
	.d_ioctl	= hwc_ioctl
};

static void
hwc_process_exit(void *arg __unused, struct proc *p)
{
	struct hwc_owner *ho;

	/* Stop HWCs associated with exiting owner, if any. */
	ho = hwc_ownerhash_lookup(p);
	if (ho)
		hwc_owner_shutdown(ho);
}

static int
hwc_load(void)
{
	struct make_dev_args args;
	int error;

	make_dev_args_init(&args);
	args.mda_devsw = &hwc_cdevsw;
	args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	args.mda_si_drv1 = NULL;

	hwc_backend_load();
	hwc_ctx_load();
	hwc_contexthash_load();
	hwc_ownerhash_load();
#if 0
	hwc_record_load();
#endif

	error = make_dev_s(&args, &hwc_cdev, "hwc");
	if (error != 0)
		return (error);

	hwc_exit_tag = EVENTHANDLER_REGISTER(process_exit, hwc_process_exit,
	    NULL, EVENTHANDLER_PRI_ANY);

	hwc_hook_load();

	return (0);
}

static int
hwc_unload(void)
{

	hwc_hook_unload();
	EVENTHANDLER_DEREGISTER(process_exit, hwc_exit_tag);
	destroy_dev(hwc_cdev);
#if 0
	hwc_record_unload();
	hwc_ownerhash_unload();
	hwc_contexthash_unload();
	hwc_ctx_unload();
	hwc_backend_unload();
#endif

	return (0);
}

static int
hwc_modevent(module_t mod, int type, void *data)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		error = hwc_load();
		break;
	case MOD_UNLOAD:
		error = hwc_unload();
		break;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t hwc_mod = {
	"hwc",
	hwc_modevent,
	NULL
};

DECLARE_MODULE(hwc, hwc_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(hwc, 1);
