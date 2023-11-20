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

#ifndef _DEV_HWT_HWT_BACKEND_H_
#define _DEV_HWT_HWT_BACKEND_H_

struct hwt_backend_ops {
	int (*hwt_backend_init)(struct hwt_context *);
	void (*hwt_backend_deinit)(struct hwt_context *);
	int (*hwt_backend_configure)(struct hwt_context *, int cpu_id,
	    int thread_id);
	void (*hwt_backend_enable)(struct hwt_context *, int cpu_id);
	void (*hwt_backend_disable)(struct hwt_context *, int cpu_id);
	int (*hwt_backend_read)(int cpu_id, int *curpage,
	    vm_offset_t *curpage_offset);

	/* Debugging only. */
	void (*hwt_backend_dump)(int cpu_id);
};

struct hwt_backend {
	const char			*name;
	struct hwt_backend_ops		*ops;
};

int hwt_backend_init(struct hwt_context *ctx);
void hwt_backend_deinit(struct hwt_context *ctx);
int hwt_backend_configure(struct hwt_context *ctx, int cpu_id, int thread_id);
void hwt_backend_enable(struct hwt_context *ctx, int cpu_id);
void hwt_backend_disable(struct hwt_context *ctx, int cpu_id);
void hwt_backend_dump(struct hwt_context *ctx, int cpu_id);
int hwt_backend_read(struct hwt_context *ctx, int cpu_id, int *curpage,
    vm_offset_t *curpage_offset);
int hwt_backend_register(struct hwt_backend *);
int hwt_backend_unregister(struct hwt_backend *);
struct hwt_backend * hwt_backend_lookup(const char *name);

void hwt_backend_load(void);
void hwt_backend_unload(void);

#define	HWT_BACKEND_LOCK()		mtx_lock(&hwt_backend_mtx)
#define	HWT_BACKEND_UNLOCK()		mtx_unlock(&hwt_backend_mtx)

#endif /* !_DEV_HWT_HWT_BACKEND_H_ */

