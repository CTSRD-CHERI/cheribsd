/*-
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

#ifndef _DEV_HWT_HWT_BACKEND_H_
#define _DEV_HWT_HWT_BACKEND_H_

struct hwc_vm;
struct hwc_configure;
struct hwc_start;
struct hwc_stop;

struct hwc_backend_ops {
	int (*hwc_backend_init)(struct hwc_context *);
	int (*hwc_backend_deinit)(struct hwc_context *);
	int (*hwc_backend_configure)(struct hwc_context *,
	    struct hwc_configure *hc);
	int (*hwc_backend_svc_buf)(struct hwc_context *, void *data,
	    size_t data_size, int data_version);
	void (*hwc_backend_enable)(struct hwc_context *, int cpu_id);
	void (*hwc_backend_disable)(struct hwc_context *, int cpu_id);
	int (*hwc_backend_read)(struct hwc_vm *, int *ident,
	    vm_offset_t *offset, uint64_t *data);
	int (*hwc_backend_stop)(struct hwc_context *, struct hwc_stop *);
	int (*hwc_backend_start)(struct hwc_context *, struct hwc_start *);
	/* For backends that are tied to local CPU registers */
	int (*hwc_backend_enable_smp)(struct hwc_context *);
	int (*hwc_backend_disable_smp)(struct hwc_context *);
	/* Allocation and initialization of backend-specific thread data. */
	int (*hwc_backend_thread_alloc)(struct hwc_thread *);
	void (*hwc_backend_thread_free)(struct hwc_thread *);
	/* Debugging only. */
	void (*hwc_backend_dump)(int cpu_id);
};

struct hwc_backend {
	const char			*name;
	struct hwc_backend_ops		*ops;
	/* buffers require kernel virtual addresses */
	bool				kva_req;
};

int hwc_backend_init(struct hwc_context *ctx);
void hwc_backend_deinit(struct hwc_context *ctx);
int hwc_backend_configure(struct hwc_context *ctx, struct hwc_configure *hc);
void hwc_backend_enable(struct hwc_context *ctx, int cpu_id);
void hwc_backend_disable(struct hwc_context *ctx, int cpu_id);
void hwc_backend_enable_smp(struct hwc_context *ctx);
void hwc_backend_disable_smp(struct hwc_context *ctx);
void hwc_backend_dump(struct hwc_context *ctx, int cpu_id);
int hwc_backend_read(struct hwc_context *ctx, struct hwc_vm *vm, int *ident,
    vm_offset_t *offset, uint64_t *data);
int hwc_backend_register(struct hwc_backend *);
int hwc_backend_unregister(struct hwc_backend *);
int hwc_backend_stop(struct hwc_context *, struct hwc_stop *);
int hwc_backend_start(struct hwc_context *, struct hwc_start *);
int hwc_backend_svc_buf(struct hwc_context *ctx, void *data, size_t data_size,
    int data_version);
struct hwc_backend * hwc_backend_lookup(const char *name);
int hwc_backend_thread_alloc(struct hwc_context *ctx, struct hwc_thread *);
void hwc_backend_thread_free(struct hwc_thread *);

void hwc_backend_load(void);
void hwc_backend_unload(void);

#define	HWT_BACKEND_LOCK()		mtx_lock(&hwc_backend_mtx)
#define	HWT_BACKEND_UNLOCK()		mtx_unlock(&hwc_backend_mtx)

#endif /* !_DEV_HWT_HWT_BACKEND_H_ */

