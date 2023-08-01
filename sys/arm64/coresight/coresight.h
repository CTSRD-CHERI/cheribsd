/*-
 * Copyright (c) 2018-2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#ifndef	_ARM64_CORESIGHT_CORESIGHT_H_
#define	_ARM64_CORESIGHT_CORESIGHT_H_

#include "opt_acpi.h"
#include "opt_platform.h"

#include <sys/bus.h>
#include <sys/malloc.h>

#ifdef FDT
#include <dev/ofw/openfirm.h>
#endif

#ifdef DEV_ACPI
#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#endif

#include <dev/hwt/hwt_thread.h>

#define	CORESIGHT_ITCTRL	0xf00
#define	CORESIGHT_CLAIMSET	0xfa0
#define	CORESIGHT_CLAIMCLR	0xfa4
#define	CORESIGHT_LAR		0xfb0
#define	 CORESIGHT_UNLOCK	0xc5acce55
#define	CORESIGHT_LSR		0xfb4
#define	CORESIGHT_AUTHSTATUS	0xfb8
#define	CORESIGHT_DEVID		0xfc8
#define	CORESIGHT_DEVTYPE	0xfcc

enum cs_dev_type {
	CORESIGHT_ETMV4,
	CORESIGHT_TMC_ETF,
	CORESIGHT_TMC_ETR,
	CORESIGHT_DYNAMIC_REPLICATOR,
	CORESIGHT_FUNNEL,
	CORESIGHT_CPU_DEBUG,
};

enum cs_bus_type {
	CORESIGHT_BUS_ACPI,
	CORESIGHT_BUS_FDT,
};

struct coresight_device {
	TAILQ_ENTRY(coresight_device) link;
	device_t dev;
	enum cs_dev_type dev_type;
	struct coresight_platform_data *pdata;
};

struct endpoint {
	TAILQ_ENTRY(endpoint) link;
#ifdef FDT
	phandle_t my_node;
	phandle_t their_node;
	phandle_t dev_node;
#endif
#ifdef DEV_ACPI
	ACPI_HANDLE their_handle;
	ACPI_HANDLE my_handle;
#endif
	boolean_t input;
	int reg;
	struct coresight_device *cs_dev;
	TAILQ_ENTRY(endpoint) endplink;
};

struct coresight_platform_data {
	int cpu;
	int in_ports;
	int out_ports;
	struct mtx mtx_lock;
	TAILQ_HEAD(endpoint_list, endpoint) endpoints;
	enum cs_bus_type bus_type;
};

struct coresight_desc {
	struct coresight_platform_data *pdata;
	device_t dev;
	enum cs_dev_type dev_type;
};

TAILQ_HEAD(coresight_device_list, coresight_device);

#define	ETM_N_COMPRATOR		16

struct etm_state {
	uint32_t trace_id;
};

struct etr_state {
	uint32_t low;
	uint32_t high;
	uint32_t bufsize;
	vm_page_t *pages;
	int npages;
	int curpage;
	vm_offset_t curpage_offset;

	vm_page_t *pt_dir;
	int npt;
};

struct coresight_pipeline {
	TAILQ_HEAD(endplistname, endpoint) endplist;

	uint64_t addr[ETM_N_COMPRATOR];
	uint32_t naddr;
	uint8_t excp_level;
	enum cs_dev_type src;
	enum cs_dev_type sink;

	struct etr_state etr;
	struct etm_state etm;
};

struct etm_config {
	uint64_t addr[ETM_N_COMPRATOR];
	uint32_t naddr;
	uint8_t excp_level;
};

MALLOC_DECLARE(M_CORESIGHT);

struct coresight_platform_data *coresight_fdt_get_platform_data(device_t dev);
void coresight_fdt_release_platform_data(struct coresight_platform_data *pdata);

struct coresight_platform_data *coresight_acpi_get_platform_data(device_t dev);
struct endpoint *
    coresight_get_output_endpoint(struct coresight_platform_data *pdata);
struct coresight_device *
    coresight_get_output_device(struct coresight_device *cs_dev,
    struct endpoint *endp, struct endpoint **);
int coresight_register(struct coresight_desc *desc);

int coresight_init_pipeline(struct coresight_pipeline *pipeline, int cpu);
void coresight_deinit_pipeline(struct coresight_pipeline *pipeline);

int coresight_setup(struct coresight_pipeline *pipeline);
int coresight_configure(struct coresight_pipeline *pipeline,
    struct hwt_context *ctx);
void coresight_deconfigure(struct coresight_pipeline *pipeline);

int coresight_start(struct coresight_pipeline *pipeline);
void coresight_stop(struct coresight_pipeline *pipeline);

void coresight_enable(struct coresight_pipeline *pipeline);
void coresight_disable(struct coresight_pipeline *pipeline);

int coresight_read(struct coresight_pipeline *pipeline);
void coresight_dump(struct coresight_pipeline *pipeline);

int coresight_unregister(device_t dev);

#endif /* !_ARM64_CORESIGHT_CORESIGHT_H_ */
