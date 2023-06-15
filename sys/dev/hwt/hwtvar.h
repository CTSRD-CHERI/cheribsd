/*-
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
 *
 * $FreeBSD$
 */

#ifndef _DEV_HWT_HWTVAR_H_
#define _DEV_HWT_HWTVAR_H_

#ifndef LOCORE
static MALLOC_DEFINE(M_HWT, "hwt", "Hardware Trace");

#define	HWT_LOCK(sc)			mtx_lock(&(sc)->mtx)
#define	HWT_UNLOCK(sc)			mtx_unlock(&(sc)->mtx)
#define	HWT_ASSERT_LOCKED(sc)		mtx_assert(&(sc)->mtx, MA_OWNED)

struct hwt_thread {
	vm_page_t			*pages;
	int				npages;
	lwpid_t				tid;
	vm_object_t			obj;
	struct cdev			*cdev;
	struct hwt_context		*ctx;
	LIST_ENTRY(hwt_thread)		next;
};

struct hwt_context {
	LIST_HEAD(, hwt_thread)		threads;
	struct mtx			mtx_threads; /* Protects threads. */
	size_t				bufsize; /* Applied to each hwt_thread*/

	LIST_HEAD(, hwt_record_entry)	records;
	struct mtx			mtx; /* Protects records. */

	LIST_ENTRY(hwt_context)		next_hch; /* Entry in contexthash. */
	LIST_ENTRY(hwt_context)		next_hwts; /* Entry in ho->hwts. */

	struct proc			*p; /* Could be NULL if exited. */
	pid_t				pid;

	struct hwt_owner		*hwt_owner;
	struct hwt_backend		*hwt_backend;
};

struct hwt_owner {
	struct proc			*p;
	struct mtx			mtx; /* Protects hwts. */
	LIST_HEAD(, hwt_context)	hwts; /* Owned HWTs. */
	LIST_ENTRY(hwt_owner)		next; /* Entry in hwt owner hash. */
};

struct hwt_backend_ops {
	void (*hwt_event_init)(struct hwt_thread *, int cpu_id);
	void (*hwt_event_start)(struct hwt_thread *, int cpu_id);
	void (*hwt_event_stop)(struct hwt_thread *, int cpu_id);
	void (*hwt_event_enable)(struct hwt_thread *, int cpu_id);
	void (*hwt_event_disable)(struct hwt_thread *, int cpu_id);
	void (*hwt_event_dump)(struct hwt_thread *, int cpu_id);
	int (*hwt_event_read)(struct hwt_thread *, int cpu_id,
	    int *curpage, vm_offset_t *curpage_offset);
};

struct hwt_backend {
	const char			*name;
	struct hwt_backend_ops		*ops;
	LIST_ENTRY(hwt_backend)		next;
};

int hwt_register(struct hwt_backend *);

struct hwt_context * hwt_lookup_contexthash(struct proc *p);

#endif /* !LOCORE */
#endif /* !_DEV_HWT_HWTVAR_H_ */
