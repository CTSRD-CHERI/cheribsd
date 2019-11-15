/*-
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018-2019
 *	Netflix Inc.
 *      All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * __FBSDID("$FreeBSD$");
 *
 */
/**
 * Author: Randall Stewart <rrs@netflix.com>
 */
#ifndef __tcp_ratelimit_h__
#define __tcp_ratelimit_h__

struct m_snd_tag;

/* Flags on an individual rate */
#define HDWRPACE_INITED 	0x0001
#define HDWRPACE_TAGPRESENT	0x0002
#define HDWRPACE_IFPDEPARTED	0x0004
struct tcp_hwrate_limit_table {
	const struct tcp_rate_set *ptbl;	/* Pointer to parent table */
	struct m_snd_tag *tag;	/* Send tag if needed (chelsio) */
	uint64_t rate;		/* Rate we get in Bytes per second (Bps) */
	uint32_t time_between;	/* Time-Gap between packets at this rate */
	uint32_t flags;
};

/* Rateset flags */
#define RS_IS_DEFF      0x0001	/* Its a lagg, do a double lookup */
#define RS_IS_INTF      0x0002	/* Its a plain interface */
#define RS_NO_PRE       0x0004	/* The interfacd has set rates */
#define RS_INT_TBL      0x0010	/*
				 * The table is the internal version
				 * which has special setup requirements.
				 */
#define RS_IS_DEAD      0x0020	/* The RS is dead list */
#define RS_FUNERAL_SCHD 0x0040  /* Is a epoch call scheduled to bury this guy?*/
#define RS_INTF_NO_SUP  0x0100 	/* The interface does not support the ratelimiting */

struct tcp_rate_set {
	struct sysctl_ctx_list sysctl_ctx;
	CK_LIST_ENTRY(tcp_rate_set) next;
	struct ifnet *rs_ifp;
	struct tcp_hwrate_limit_table *rs_rlt;
	uint64_t rs_flows_using;
	uint64_t rs_flow_limit;
	uint32_t rs_if_dunit;
	int rs_rate_cnt;
	int rs_min_seg;
	int rs_highest_valid;
	int rs_lowest_valid;
	int rs_disable;
	int rs_flags;
	struct epoch_context rs_epoch_ctx;
};

CK_LIST_HEAD(head_tcp_rate_set, tcp_rate_set);

/* Request flags */
#define RS_PACING_EXACT_MATCH	0x0001	/* Need an exact match for rate */
#define RS_PACING_GT		0x0002	/* Greater than requested */
#define RS_PACING_GEQ		0x0004	/* Greater than or equal too */
#define RS_PACING_LT		0x0008	/* Less than requested rate */
#define RS_PACING_SUB_OK	0x0010	/* If a rate can't be found get the
					 * next best rate (highest or lowest). */
#ifdef _KERNEL
#ifdef RATELIMIT
#define DETAILED_RATELIMIT_SYSCTL 1	/*
					 * Undefine this if you don't want
					 * detailed rates to appear in
					 * net.inet.tcp.rl.
					 * With the defintion each rate
					 * shows up in your sysctl tree
					 * this can be big.
					 */

const struct tcp_hwrate_limit_table *
tcp_set_pacing_rate(struct tcpcb *tp, struct ifnet *ifp,
    uint64_t bytes_per_sec, int flags, int *error);

const struct tcp_hwrate_limit_table *
tcp_chg_pacing_rate(const struct tcp_hwrate_limit_table *crte,
    struct tcpcb *tp, struct ifnet *ifp,
    uint64_t bytes_per_sec, int flags, int *error);
void
tcp_rel_pacing_rate(const struct tcp_hwrate_limit_table *crte,
    struct tcpcb *tp);
#else
static inline const struct tcp_hwrate_limit_table *
tcp_set_pacing_rate(struct tcpcb *tp, struct ifnet *ifp,
    uint64_t bytes_per_sec, int flags, int *error)
{
	if (error)
		*error = EOPNOTSUPP;
	return (NULL);
}

static inline const struct tcp_hwrate_limit_table *
tcp_chg_pacing_rate(const struct tcp_hwrate_limit_table *crte,
    struct tcpcb *tp, struct ifnet *ifp,
    uint64_t bytes_per_sec, int flags, int *error)
{
	if (error)
		*error = EOPNOTSUPP;
	return (NULL);
}

static inline void
tcp_rel_pacing_rate(const struct tcp_hwrate_limit_table *crte,
    struct tcpcb *tp)
{
	return;
}

#endif
#endif
#endif
