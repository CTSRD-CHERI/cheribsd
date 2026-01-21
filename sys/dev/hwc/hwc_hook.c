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

/* Hardware Counting (HWC) framework. */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/refcount.h>
#include <sys/hwc.h>

#include <dev/hwc/hwc_hook.h>
#if 0
#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_contexthash.h>
#include <dev/hwc/hwc_config.h>
#include <dev/hwc/hwc_thread.h>
#include <dev/hwc/hwc_owner.h>
#include <dev/hwc/hwc_backend.h>
#include <dev/hwc/hwc_vm.h>
#endif

#define	HWC_DEBUG
#undef	HWC_DEBUG

#ifdef	HWC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static void
hwc_switch_in(struct thread *td)
{
#if 0
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		hwc_ctx_put(ctx);
		return;
	}

	thr = hwc_thread_lookup(ctx, td);
	if (thr == NULL) {
		hwc_ctx_put(ctx);
		return;
	}

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwc_backend_configure(ctx, cpu_id, thr->thread_id);
	hwc_backend_enable(ctx, cpu_id);

	hwc_ctx_put(ctx);
#endif
}

static void
hwc_switch_out(struct thread *td)
{
#if 0
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		hwc_ctx_put(ctx);
		return;
	}
	thr = hwc_thread_lookup(ctx, td);
	if (thr == NULL) {
		hwc_ctx_put(ctx);
		return;
	}

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwc_backend_disable(ctx, cpu_id);

	hwc_ctx_put(ctx);
#endif
}

static void
hwc_hook_handler(struct thread *td, int func, void *arg)
{
	struct proc *p;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWC) == 0)
		return;

	switch (func) {
	case HWC_SWITCH_IN:
		hwc_switch_in(td);
		break;
	case HWC_SWITCH_OUT:
		hwc_switch_out(td);
		break;
	};
}

void
hwc_hook_load(void)
{

	hwc_hook = hwc_hook_handler;
}

void
hwc_hook_unload(void)
{

	hwc_hook = NULL;
}
