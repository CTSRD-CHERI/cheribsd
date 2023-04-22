/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2023 Alexander V. Chernikov <melifaro@FreeBSD.org>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef	_NETLINK_NETLINK_SNL_ROUTE_PARSERS_H_
#define	_NETLINK_NETLINK_SNL_ROUTE_PARSERS_H_

#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route.h>

/* TODO: this file should be generated automatically */

/* RTM_<NEW|DEL|GET>ROUTE message parser */

struct rta_mpath_nh {
	struct sockaddr	*gw;
	uint32_t	ifindex;
	uint8_t		rtnh_flags;
	uint8_t		rtnh_weight;
	uint32_t	rtax_mtu;
	uint32_t	rta_rtflags;
};

#define	_IN(_field)	offsetof(struct rtnexthop, _field)
#define	_OUT(_field)	offsetof(struct rta_mpath_nh, _field)
static const struct snl_attr_parser _nla_p_mp_nh_metrics[] = {
	{ .type = NL_RTAX_MTU, .off = _OUT(rtax_mtu), .cb = snl_attr_get_uint32 },
};
SNL_DECLARE_ATTR_PARSER(_metrics_mp_nh_parser, _nla_p_mp_nh_metrics);

static const struct snl_attr_parser _nla_p_mp_nh[] = {
	{ .type = NL_RTA_GATEWAY, .off = _OUT(gw), .cb = snl_attr_get_ip },
	{ .type = NL_RTA_METRICS, .arg = &_metrics_mp_nh_parser, .cb = snl_attr_get_nested },
	{ .type = NL_RTA_RTFLAGS, .off = _OUT(rta_rtflags), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_VIA, .off = _OUT(gw), .cb = snl_attr_get_ipvia },
};

static const struct snl_field_parser _fp_p_mp_nh[] = {
	{ .off_in = _IN(rtnh_flags), .off_out = _OUT(rtnh_flags), .cb = snl_field_get_uint8 },
	{ .off_in = _IN(rtnh_hops), .off_out = _OUT(rtnh_weight), .cb = snl_field_get_uint8 },
	{ .off_in = _IN(rtnh_ifindex), .off_out = _OUT(ifindex), .cb = snl_field_get_uint32 },
};
#undef _IN
#undef _OUT
SNL_DECLARE_PARSER(_mpath_nh_parser, struct rtnexthop, _fp_p_mp_nh, _nla_p_mp_nh);

struct rta_mpath {
	int num_nhops;
	struct rta_mpath_nh nhops[0];
};

static bool
nlattr_get_multipath(struct snl_state *ss, struct nlattr *nla, const void *arg __unused,
    void *target)
{
	int data_len = nla->nla_len - sizeof(struct nlattr);
	struct rtnexthop *rtnh;

	int max_nhops = data_len / sizeof(struct rtnexthop);
	size_t sz = (max_nhops + 2) * sizeof(struct rta_mpath_nh);

	struct rta_mpath *mp = snl_allocz(ss, sz);
	mp->num_nhops = 0;

	for (rtnh = (struct rtnexthop *)(void *)(nla + 1); data_len > 0; ) {
		struct rta_mpath_nh *mpnh = &mp->nhops[mp->num_nhops++];

		if (!snl_parse_header(ss, rtnh, rtnh->rtnh_len, &_mpath_nh_parser, mpnh))
			return (false);

		int len = NL_ITEM_ALIGN(rtnh->rtnh_len);
		data_len -= len;
		rtnh = (struct rtnexthop *)(void *)((char *)rtnh + len);
	}
	if (data_len != 0 || mp->num_nhops == 0) {
		return (false);
	}

	*((struct rta_mpath **)target) = mp;
	return (true);
}

struct snl_parsed_route {
	struct sockaddr		*rta_dst;
	struct sockaddr		*rta_gw;
	struct nlattr		*rta_metrics;
	struct rta_mpath	*rta_multipath;
	uint32_t		rta_expires;
	uint32_t		rta_oif;
	uint32_t		rta_expire;
	uint32_t		rta_table;
	uint32_t		rta_knh_id;
	uint32_t		rta_nh_id;
	uint32_t		rta_rtflags;
	uint32_t		rtax_mtu;
	uint32_t		rtax_weight;
	uint8_t			rtm_family;
	uint8_t			rtm_type;
	uint8_t			rtm_protocol;
	uint8_t			rtm_dst_len;
};

#define	_IN(_field)	offsetof(struct rtmsg, _field)
#define	_OUT(_field)	offsetof(struct snl_parsed_route, _field)
static const struct snl_attr_parser _nla_p_rtmetrics[] = {
	{ .type = NL_RTAX_MTU, .off = _OUT(rtax_mtu), .cb = snl_attr_get_uint32 },
};
SNL_DECLARE_ATTR_PARSER(_metrics_parser, _nla_p_rtmetrics);

static const struct snl_attr_parser _nla_p_route[] = {
	{ .type = NL_RTA_DST, .off = _OUT(rta_dst), .cb = snl_attr_get_ip },
	{ .type = NL_RTA_OIF, .off = _OUT(rta_oif), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_GATEWAY, .off = _OUT(rta_gw), .cb = snl_attr_get_ip },
	{ .type = NL_RTA_METRICS, .arg = &_metrics_parser, .cb = snl_attr_get_nested },
	{ .type = NL_RTA_MULTIPATH, .off = _OUT(rta_multipath), .cb = nlattr_get_multipath },
	{ .type = NL_RTA_KNH_ID, .off = _OUT(rta_knh_id), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_WEIGHT, .off = _OUT(rtax_weight), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_RTFLAGS, .off = _OUT(rta_rtflags), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_TABLE, .off = _OUT(rta_table), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_VIA, .off = _OUT(rta_gw), .cb = snl_attr_get_ipvia },
	{ .type = NL_RTA_EXPIRES, .off = _OUT(rta_expire), .cb = snl_attr_get_uint32 },
	{ .type = NL_RTA_NH_ID, .off = _OUT(rta_nh_id), .cb = snl_attr_get_uint32 },
};

static const struct snl_field_parser _fp_p_route[] = {
	{.off_in = _IN(rtm_family), .off_out = _OUT(rtm_family), .cb = snl_field_get_uint8 },
	{.off_in = _IN(rtm_type), .off_out = _OUT(rtm_type), .cb = snl_field_get_uint8 },
	{.off_in = _IN(rtm_protocol), .off_out = _OUT(rtm_protocol), .cb = snl_field_get_uint8 },
	{.off_in = _IN(rtm_dst_len), .off_out = _OUT(rtm_dst_len), .cb = snl_field_get_uint8 },
};
#undef _IN
#undef _OUT
SNL_DECLARE_PARSER(snl_rtm_route_parser, struct rtmsg, _fp_p_route, _nla_p_route);

/* RTM_<NEW|DEL|GET>LINK message parser */
struct snl_parsed_link {
	uint32_t			ifi_index;
	uint32_t			ifi_flags;
	uint32_t			ifi_change;
	uint16_t			ifi_type;
	uint8_t				ifla_operstate;
	uint8_t				ifla_carrier;
	uint32_t			ifla_mtu;
	char				*ifla_ifname;
	struct nlattr			*ifla_address;
	struct nlattr			*ifla_broadcast;
	char				*ifla_ifalias;
	uint32_t			ifla_promiscuity;
	struct rtnl_link_stats64	*ifla_stats64;
};

#define	_IN(_field)	offsetof(struct ifinfomsg, _field)
#define	_OUT(_field)	offsetof(struct snl_parsed_link, _field)
static const struct snl_attr_parser _nla_p_link[] = {
	{ .type = IFLA_ADDRESS, .off = _OUT(ifla_address), .cb = snl_attr_get_nla },
	{ .type = IFLA_BROADCAST, .off = _OUT(ifla_broadcast), .cb = snl_attr_get_nla },
	{ .type = IFLA_IFNAME, .off = _OUT(ifla_ifname), .cb = snl_attr_get_string },
	{ .type = IFLA_MTU, .off = _OUT(ifla_mtu), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_OPERSTATE, .off = _OUT(ifla_operstate), .cb = snl_attr_get_uint8 },
	{ .type = IFLA_IFALIAS, .off = _OUT(ifla_ifalias), .cb = snl_attr_get_string },
	{ .type = IFLA_STATS64, .off = _OUT(ifla_stats64), .cb = snl_attr_copy_struct },
	{ .type = IFLA_PROMISCUITY, .off = _OUT(ifla_promiscuity), .cb = snl_attr_get_uint32 },
	{ .type = IFLA_CARRIER, .off = _OUT(ifla_carrier), .cb = snl_attr_get_uint8 },
};
static const struct snl_field_parser _fp_p_link[] = {
	{.off_in = _IN(ifi_index), .off_out = _OUT(ifi_index), .cb = snl_field_get_uint32 },
	{.off_in = _IN(ifi_flags), .off_out = _OUT(ifi_flags), .cb = snl_field_get_uint32 },
	{.off_in = _IN(ifi_change), .off_out = _OUT(ifi_change), .cb = snl_field_get_uint32 },
	{.off_in = _IN(ifi_type), .off_out = _OUT(ifi_type), .cb = snl_field_get_uint16 },
};
#undef _IN
#undef _OUT
SNL_DECLARE_PARSER(snl_rtm_link_parser, struct ifinfomsg, _fp_p_link, _nla_p_link);

struct snl_parsed_link_simple {
	uint32_t		ifi_index;
	uint32_t		ifla_mtu;
	uint16_t		ifi_type;
	char			*ifla_ifname;
};

#define	_IN(_field)	offsetof(struct ifinfomsg, _field)
#define	_OUT(_field)	offsetof(struct snl_parsed_link_simple, _field)
static struct snl_attr_parser _nla_p_link_s[] = {
	{ .type = IFLA_IFNAME, .off = _OUT(ifla_ifname), .cb = snl_attr_get_string },
	{ .type = IFLA_MTU, .off = _OUT(ifla_mtu), .cb = snl_attr_get_uint32 },
};
static struct snl_field_parser _fp_p_link_s[] = {
	{.off_in = _IN(ifi_index), .off_out = _OUT(ifi_index), .cb = snl_field_get_uint32 },
	{.off_in = _IN(ifi_type), .off_out = _OUT(ifi_type), .cb = snl_field_get_uint16 },
};
#undef _IN
#undef _OUT
SNL_DECLARE_PARSER(snl_rtm_link_parser_simple, struct ifinfomsg, _fp_p_link_s, _nla_p_link_s);

static const struct snl_hdr_parser *snl_all_route_parsers[] = {
	&_metrics_mp_nh_parser, &_mpath_nh_parser, &_metrics_parser, &snl_rtm_route_parser,
	&snl_rtm_link_parser, &snl_rtm_link_parser_simple,
};

#endif
