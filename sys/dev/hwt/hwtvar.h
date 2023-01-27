/*-
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
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

struct hwt_info {
	int test;
};

struct hwt_device {
	const char *name;
};

struct hwt_softc {
	struct cdev			*hwt_cdev;
	struct mtx			mtx;

	/*
	 * List of CPU trace devices registered in HWT.
	 * Protected by sc->mtx.
	 */
	TAILQ_HEAD(hwt_device_list, hwt_device)	hwt_devices;
};

int hwt_register(void);

#endif /* !LOCORE */

#endif /* !_DEV_HWT_HWTVAR_H_ */
