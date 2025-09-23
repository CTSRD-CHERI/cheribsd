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

/* RISC-V PMU. */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cpuset.h>
#include <sys/hwc.h>
#include <sys/wait.h>
#include <sys/sysctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <ucl.h>

#include <machine/riscvreg.h>
#include <machine/encoding.h>
#include <machine/sbi.h>

#include "hwc.h"
#include "hwc_pmu.h"

#include <libxo/xo.h>

#define	HWC_DEBUG
#undef	HWC_DEBUG

#ifdef	HWC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct counter {
	int event_id;
	bool enabled;
	char *name;
};

#define	RISCV_NCOUNTERS	32

static struct counter counters[RISCV_NCOUNTERS];

static uint64_t
csr_read_num(int csr_num)
{
#define switchcase_csr_read(__csr_num, __val)		{\
	case __csr_num:					\
		__val = csr_read(__csr_num);		\
		break; }
#define switchcase_csr_read_2(__csr_num, __val)		{\
	switchcase_csr_read(__csr_num + 0, __val)	\
	switchcase_csr_read(__csr_num + 1, __val)}
#define switchcase_csr_read_4(__csr_num, __val)		{\
	switchcase_csr_read_2(__csr_num + 0, __val)	\
	switchcase_csr_read_2(__csr_num + 2, __val)}
#define switchcase_csr_read_8(__csr_num, __val)		{\
	switchcase_csr_read_4(__csr_num + 0, __val)	\
	switchcase_csr_read_4(__csr_num + 4, __val)}
#define switchcase_csr_read_16(__csr_num, __val)	{\
	switchcase_csr_read_8(__csr_num + 0, __val)	\
	switchcase_csr_read_8(__csr_num + 8, __val)}
#define switchcase_csr_read_32(__csr_num, __val)	{\
	switchcase_csr_read_16(__csr_num + 0, __val)	\
	switchcase_csr_read_16(__csr_num + 16, __val)}

	unsigned long ret = 0;

	switch (csr_num) {
	switchcase_csr_read_32(CSR_CYCLE, ret)
	switchcase_csr_read_32(CSR_CYCLEH, ret)
	default :
		break;
	}

	return ret;
#undef switchcase_csr_read_32
#undef switchcase_csr_read_16
#undef switchcase_csr_read_8
#undef switchcase_csr_read_4
#undef switchcase_csr_read_2
#undef switchcase_csr_read
}

static int
pmu_request_configure(struct hwc_context *tc, int mhpm_id, int event_id)
{
	struct hwc_configure hc;
	int error;

	/* Map event_id to a counter mhpm_id. */
	hc.counter_id = mhpm_id;
	hc.event_id = event_id;
	hc.flags = SBI_PMU_CFG_FLAG_CLEAR_VALUE;
	hc.flags |= SBI_PMU_CFG_FLAG_SET_SINH; /* S-mode Inhibit */
	hc.flags |= SBI_PMU_CFG_FLAG_SET_MINH; /* M-mode Inhibit */
	//hc.flags |= SBI_PMU_CFG_FLAG_SET_UINH; /* U-mode Inhibit */
	hc.flags |= SBI_PMU_CFG_FLAG_SET_VUINH; /* VU-mode Inhibit */
	hc.flags |= SBI_PMU_CFG_FLAG_SET_VSINH; /* VS-mode Inhibit */

	error = ioctl(tc->ctx_fd, HWC_IOC_CONFIGURE, &hc);
	if (error)
		return (error);

	return (0);
}

static int
pmu_parse_counter(struct hwc_context *tc __unused, const ucl_object_t *top)
{
	const ucl_object_t *obj;
	ucl_object_iter_t it = NULL;
	const char *k;
	int event_id;
	int mhpm_id;
	const char *name;
	bool enabled __unused;

	while ((obj = ucl_iterate_object (top, &it, true))) {
		k = ucl_object_key(obj);
		if (strcmp(k, "id") == 0)
			mhpm_id = ucl_object_toint(obj);
		if (strcmp(k, "event_id") == 0)
			event_id = ucl_object_toint(obj);
		if (strcmp(k, "name") == 0)
			name = ucl_object_tostring(obj);
		if (strcmp(k, "enabled") == 0)
			enabled = ucl_object_toboolean(obj);
	}

	counters[mhpm_id].event_id = event_id;
	counters[mhpm_id].name = strdup(name);
	counters[mhpm_id].enabled = enabled;

	return (0);
}

static int
pmu_parse_counters(struct hwc_context *tc, const ucl_object_t *top)
{
	ucl_object_iter_t it_obj = NULL;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *obj;
	const ucl_object_t *cur;
	const char *k;
	int error;

	while ((obj = ucl_iterate_object (top, &it, true))) {
		k = ucl_object_key(obj);
		if (strcmp(k, "mhpmcounter") != 0)
			continue;
		while ((cur = ucl_iterate_object (obj, &it_obj, false))) {
			error = pmu_parse_counter(tc, cur);
			if (error)
				return (error);
		}
	}

	return (0);
}

static int __unused
pmu_stop_one(struct hwc_context *tc, int i)
{
	struct hwc_stop hs;
	int error;

	hs.counter_mask = (1 << i);
	hs.flags = 0;

	error = ioctl(tc->ctx_fd, HWC_IOC_STOP, &hs);
	if (error) {
		printf("%s: could not stop counter (mask) 0x%x, error %d\n",
		    __func__, hs.counter_mask, error);
		return (error);
	}

	return (0);
}

static int
pmu_stop_all(struct hwc_context *tc, int flags)
{
	struct hwc_stop hs;
	int error;
	int i;

	hs.counter_mask = 0;
	hs.flags = flags;

	for (i = 0; i < RISCV_NCOUNTERS; i++)
		if (counters[i].enabled == true)
			hs.counter_mask |= (1 << i);

	error = ioctl(tc->ctx_fd, HWC_IOC_STOP, &hs);
	if (error)
		return (error);

	return (0);
}

static int __unused
pmu_start_all(struct hwc_context *tc)
{
	struct hwc_start hs;
	int error;
	int i;

	hs.counter_mask = 0;
	hs.flags = SBI_PMU_START_FLAG_SET_INIT_VALUE;
	hs.data = 0;

	for (i = 0; i < RISCV_NCOUNTERS; i++)
		if (counters[i].enabled == true)
			hs.counter_mask |= (1 << i);

	error = ioctl(tc->ctx_fd, HWC_IOC_START, &hs);
	if (error) {
		printf("%s: could not start counters (mask) 0x%x, error %d\n",
		    __func__, hs.counter_mask, error);
		return (error);
	}

	return (0);
}

static int
pmu_parse_config(struct hwc_context *tc)
{
	struct ucl_parser *parser;
	const ucl_object_t *obj;
	ucl_object_t *top;
	ucl_object_iter_t it = NULL;
	const char *k;
	int error;
	bool ret;

	parser = ucl_parser_new(0);

	ret = ucl_parser_add_file(parser, tc->config_file);
	if (ret == false) {
		printf("can't read file\n");
		return (-1);
	}

	top = ucl_parser_get_object(parser);

	while ((obj = ucl_iterate_object(top, &it, true))) {
		k = ucl_object_key(obj);
		if (strcmp(k, "mhpmcounters") == 0) {
			error = pmu_parse_counters(tc, obj);
			if (error)
				return (error);
		}
	}

	return (0);
}

static int
pmu_configure(struct hwc_context *tc)
{
	struct counter *c;
	int error;
	int i;

	error = pmu_parse_config(tc);
	if (error)
		return (error);

	/* Stop and reset any previous mappings. */
	pmu_stop_all(tc, SBI_PMU_STOP_FLAG_RESET);

	for (i = 0; i < RISCV_NCOUNTERS; i++) {
		c = &counters[i];
		if (c->enabled == true) {
			error = pmu_request_configure(tc, i, c->event_id);
			if (error) {
				printf("%s: cound not configure ctr id %d\n",
				    __func__, i);
				return (error);
			}
		}
	}

	error = pmu_start_all(tc);

	return (error);
}

static int
pmu_init(struct hwc_context *tc __unused)
{

	dprintf("%s\n", __func__);

	bzero(counters, sizeof(struct counter) * RISCV_NCOUNTERS);

	return (0);
}

static void
pmu_run_once(struct hwc_context *tc __unused)
{

}

static void
pmu_ucl_insert_entry(ucl_object_t *root, struct counter *c, int i)
{
	ucl_object_t *result;
	uint64_t val;

	val = csr_read_num(CSR_HPMCOUNTER3 - 3 + i);

	result = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(result, ucl_object_fromstring(c->name),
	    "name", 0, false);
	ucl_object_insert_key(result, ucl_object_fromint(val), "count", 0,
	    false);

	ucl_object_insert_key(root, result, "counters", 0, false);
}

static int
pmu_dump(struct hwc_context *tc)
{
	unsigned char *json_str;
	struct counter *c;
	ucl_object_t *root;
	FILE *fp;
	int i;

	if (tc->output_file == NULL)
		return (0);

	fp = fopen(tc->output_file, "w");
	if (!fp) {
		perror("fopen");
		return (-1);
	}

	root = ucl_object_typed_new(UCL_OBJECT);

	for (i = 0; i < RISCV_NCOUNTERS; i++) {
		c = &counters[i];
		if (c->enabled == true)
			pmu_ucl_insert_entry(root, c, i);
	}

	json_str = ucl_object_emit(root, UCL_EMIT_JSON_COMPACT);
	if (json_str) {
		fputs((const char *)json_str, fp);
		free(json_str);
	}

	fclose(fp);

	ucl_object_unref(root);

	return (0);
}

static void
pmu_print(struct hwc_context *tc __unused)
{
	struct counter *c;
	int i;

	/* Print out standard counters. */
	printf(" time == %ld\n", csr_read(time));
	printf(" cycle == %ld\n", csr_read(cycle));
	printf(" instructions == %ld\n", csr_read(instret));

	for (i = 0; i < RISCV_NCOUNTERS; i++) {
		c = &counters[i];
		if (c->enabled == true)
			printf(" %s == %ld\n", c->name,
			    csr_read_num(CSR_HPMCOUNTER3 - 3 + i));
	}
}

static int
pmu_shutdown(struct hwc_context *tc)
{

	pmu_stop_all(tc, 0);
	pmu_print(tc);
	pmu_dump(tc);

	return (0);
}

struct hwc_methods pmu_methods = {
	.init = pmu_init,
	.shutdown = pmu_shutdown,
	.configure = pmu_configure,
	.run_once = pmu_run_once,
};
