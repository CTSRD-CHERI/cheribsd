/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Ruslan Bukin <br@bsdpad.com>
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

#ifndef	_ARM64_SCMI_SCMI_PERF_H_
#define	_ARM64_SCMI_SCMI_PERF_H_

/*
 * SCMI Perf Protocol
 */

#define	SCMI_PERFORMANCE_DOMAIN_ATTRIBUTES	0x3
#define	SCMI_PERFORMANCE_DESCRIBE_LEVELS	0x4
#define	SCMI_PERFORMANCE_LEVEL_SET		0x7
#define	SCMI_PERFORMANCE_LEVEL_GET		0x8

struct scmi_perf_level_get_in {
	uint32_t domain_id;
};

struct scmi_perf_level_get_out {
	int32_t status;
	uint32_t performance_level;
};

struct scmi_perf_level_set_in {
	uint32_t domain_id;
	uint32_t performance_level;
};

struct scmi_perf_level_set_out {
	int32_t status;
};

struct scmi_perf_describe_levels_in {
	uint32_t domain_id;
	uint32_t level_index;
};

struct scmi_perf_level_out {
	uint32_t perf_level_value;
	uint32_t power_cost;
	uint32_t attributes;
};

struct scmi_perf_describe_levels_out {
	int32_t status;
	uint32_t num_levels;
#define	NUM_LEVEL_REM_S	16
#define	NUM_LEVEL_REM_M	(0xffff << NUM_LEVEL_REM_S)
#define	NUM_LEVELS_S	0
#define	NUM_LEVELS_M	(0xfff << NUM_LEVELS_S)
	struct scmi_perf_level_out levels[];
};

struct scmi_perf_protocol_attrs_out {
	int32_t status;
	uint32_t attributes;
	uint32_t statistics_address_low;
	uint32_t statistics_address_high;
	uint32_t statistics_len;
};

struct scmi_perf_domain_attrs_in {
	uint32_t domain_id;
};

struct scmi_perf_domain_attrs_out {
	int32_t status;
	uint32_t attributes;
	uint32_t rate_limit;
	uint32_t sustained_freq;
	uint32_t sustained_perf_level;
	uint8_t name[16];
};

/* SCMI Perf Driver */

struct scmi_perf_level {
	int			id;
	uint32_t		rate;
};

struct scmi_perf_domain {
	int			id;
	struct scmi_perf_level	*levels;
	int			level_count;
};

#endif /* !_ARM64_SCMI_SCMI_PERF_H_ */
