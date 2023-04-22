/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Alexander V. Chernikov <melifaro@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#include "opt_inet.h"
#include "opt_inet6.h"
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/socketvar.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_vlan_var.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/route/route_ctl.h>
#include <netlink/netlink.h>
#include <netlink/netlink_ctl.h>
#include <netlink/netlink_route.h>
#include <netlink/route/route_var.h>

#include <netinet6/scope6_var.h> /* scope deembedding */

#define	DEBUG_MOD_NAME	nl_iface_drivers
#define	DEBUG_MAX_LEVEL	LOG_DEBUG3
#include <netlink/netlink_debug.h>
_DECLARE_DEBUG(LOG_DEBUG);

/*
 * Generic modification interface handler.
 * Responsible for changing network stack interface attributes
 * such as state, mtu or description.
 */
static int
modify_generic(struct ifnet *ifp, struct nl_parsed_link *lattrs,
    const struct nlattr_bmask *bm, struct nlpcb *nlp, struct nl_pstate *npt)
{
	int error;

	if (lattrs->ifla_ifalias != NULL) {
		if (nlp_has_priv(nlp, PRIV_NET_SETIFDESCR)) {
			int len = strlen(lattrs->ifla_ifalias) + 1;
			char *buf = if_allocdescr(len, M_WAITOK);

			memcpy(buf, lattrs->ifla_ifalias, len);
			if_setdescr(ifp, buf);
			getmicrotime(&ifp->if_lastchange);
		} else {
			nlmsg_report_err_msg(npt, "Not enough privileges to set descr");
			return (EPERM);
		}
	}

	if ((lattrs->ifi_change & IFF_UP) && (lattrs->ifi_flags & IFF_UP) == 0) {
		/* Request to down the interface */
		if_down(ifp);
	}

	if (lattrs->ifla_mtu > 0) {
		if (nlp_has_priv(nlp, PRIV_NET_SETIFMTU)) {
			struct ifreq ifr = { .ifr_mtu = lattrs->ifla_mtu };
			error = ifhwioctl(SIOCSIFMTU, ifp, (char *)&ifr, curthread);
		} else {
			nlmsg_report_err_msg(npt, "Not enough privileges to set mtu");
			return (EPERM);
		}
	}

	if (lattrs->ifi_change & IFF_PROMISC) {
		error = ifpromisc(ifp, lattrs->ifi_flags & IFF_PROMISC);
		if (error != 0) {
			nlmsg_report_err_msg(npt, "unable to set promisc");
			return (error);
		}
	}

	return (0);
}

/*
 * Saves the resulting ifindex and ifname to report them
 *  to userland along with the operation result.
 * NLA format:
 * NLMSGERR_ATTR_COOKIE(nested)
 *  IFLA_NEW_IFINDEX(u32)
 *  IFLA_IFNAME(string)
 */
static void
store_cookie(struct nl_pstate *npt, struct ifnet *ifp)
{
	int ifname_len = strlen(if_name(ifp));
	uint32_t ifindex = (uint32_t)ifp->if_index;

	int nla_len = sizeof(struct nlattr) * 3 +
		sizeof(ifindex) + NL_ITEM_ALIGN(ifname_len + 1);
	struct nlattr *nla_cookie = npt_alloc(npt, nla_len);

	/* Nested TLV */
	nla_cookie->nla_len = nla_len;
	nla_cookie->nla_type = NLMSGERR_ATTR_COOKIE;

	struct nlattr *nla = nla_cookie + 1;
	nla->nla_len = sizeof(struct nlattr) + sizeof(ifindex);
	nla->nla_type = IFLA_NEW_IFINDEX;
	memcpy(NLA_DATA(nla), &ifindex, sizeof(ifindex));

	nla = NLA_NEXT(nla);
	nla->nla_len = sizeof(struct nlattr) + ifname_len + 1;
	nla->nla_type = IFLA_IFNAME;
	strlcpy(NLA_DATA(nla), if_name(ifp), ifname_len + 1);

	nlmsg_report_cookie(npt, nla_cookie);
}

static int
create_generic_ifd(struct nl_parsed_link *lattrs, const struct nlattr_bmask *bm,
    struct ifc_data *ifd, struct nlpcb *nlp, struct nl_pstate *npt)
{
	int error = 0;

	struct ifnet *ifp = NULL;
	error = ifc_create_ifp(lattrs->ifla_ifname, ifd, &ifp);

	NLP_LOG(LOG_DEBUG2, nlp, "clone for %s returned %d", lattrs->ifla_ifname, error);

	if (error == 0) {
		struct epoch_tracker et;

		NET_EPOCH_ENTER(et);
		bool success = if_try_ref(ifp);
		NET_EPOCH_EXIT(et);
		if (!success)
			return (EINVAL);
		error = modify_generic(ifp, lattrs, bm, nlp, npt);
		if (error == 0)
			store_cookie(npt, ifp);
		if_rele(ifp);
	}

	return (error);
}
/*
 * Generic creation interface handler.
 * Responsible for creating interfaces w/o parameters and setting
 * misc attributes such as state, mtu or description.
 */
static int
create_generic(struct nl_parsed_link *lattrs, const struct nlattr_bmask *bm,
    struct nlpcb *nlp, struct nl_pstate *npt)
{
	struct ifc_data ifd = {};

	return (create_generic_ifd(lattrs, bm, &ifd, nlp, npt));
}

struct nl_cloner generic_cloner = {
	.name = "_default_",
	.create_f = create_generic,
	.modify_f = modify_generic,
};

/*
 *
 * {len=76, type=RTM_NEWLINK, flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, seq=1662892737, pid=0},
 *  {ifi_family=AF_UNSPEC, ifi_type=ARPHRD_NETROM, ifi_index=0, ifi_flags=0, ifi_change=0},
 *   [
 *    {{nla_len=8, nla_type=IFLA_LINK}, 2},
 *    {{nla_len=12, nla_type=IFLA_IFNAME}, "xvlan22"},
 *    {{nla_len=24, nla_type=IFLA_LINKINFO},
 *     [
 *      {{nla_len=8, nla_type=IFLA_INFO_KIND}, "vlan"...},
 *      {{nla_len=12, nla_type=IFLA_INFO_DATA}, "\x06\x00\x01\x00\x16\x00\x00\x00"}]}]}, iov_len=76}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 76
 */

struct nl_parsed_vlan {
	uint16_t vlan_id;
	uint16_t vlan_proto;
	struct ifla_vlan_flags vlan_flags;
};

#define	_OUT(_field)	offsetof(struct nl_parsed_vlan, _field)
static const struct nlattr_parser nla_p_vlan[] = {
	{ .type = IFLA_VLAN_ID, .off = _OUT(vlan_id), .cb = nlattr_get_uint16 },
	{ .type = IFLA_VLAN_FLAGS, .off = _OUT(vlan_flags), .cb = nlattr_get_nla },
	{ .type = IFLA_VLAN_PROTOCOL, .off = _OUT(vlan_proto), .cb = nlattr_get_uint16 },
};
#undef _OUT
NL_DECLARE_ATTR_PARSER(vlan_parser, nla_p_vlan);

static int
create_vlan(struct nl_parsed_link *lattrs, const struct nlattr_bmask *bm,
    struct nlpcb *nlp, struct nl_pstate *npt)
{
	struct epoch_tracker et;
        struct ifnet *ifp;
	int error;

	/*
	 * lattrs.ifla_ifname is the new interface name
	 * lattrs.ifi_index contains parent interface index
	 * lattrs.ifla_idata contains un-parsed vlan data
	 */

	struct nl_parsed_vlan attrs = {
		.vlan_id = 0xFEFE,
		.vlan_proto = ETHERTYPE_VLAN
	};
	NLP_LOG(LOG_DEBUG3, nlp, "nested: %p len %d", lattrs->ifla_idata, lattrs->ifla_idata->nla_len);

	if (lattrs->ifla_idata == NULL) {
		NLMSG_REPORT_ERR_MSG(npt, "vlan id is required, guessing not supported");
		return (ENOTSUP);
	}

	error = nl_parse_nested(lattrs->ifla_idata, &vlan_parser, npt, &attrs);
	if (error != 0)
		return (error);
	if (attrs.vlan_id > 4095) {
		NLMSG_REPORT_ERR_MSG(npt, "Invalid VID: %d", attrs.vlan_id);
		return (EINVAL);
	}
	if (attrs.vlan_proto != ETHERTYPE_VLAN && attrs.vlan_proto != ETHERTYPE_QINQ) {
		NLMSG_REPORT_ERR_MSG(npt, "Unsupported ethertype: 0x%04X", attrs.vlan_proto);
		return (ENOTSUP);
	}

	NET_EPOCH_ENTER(et);
	ifp = ifnet_byindex_ref(lattrs->ifi_index);
	NET_EPOCH_EXIT(et);
	if (ifp == NULL) {
		NLP_LOG(LOG_DEBUG, nlp, "unable to find parent interface %u",
		    lattrs->ifi_index);
		return (ENOENT);
	}

	struct vlanreq params = {
		.vlr_tag = attrs.vlan_id,
		.vlr_proto = attrs.vlan_proto,
	};
	strlcpy(params.vlr_parent, if_name(ifp), sizeof(params.vlr_parent));
	struct ifc_data ifd = { .flags = IFC_F_SYSSPACE, .params = &params };

	error = create_generic_ifd(lattrs, bm, &ifd, nlp, npt);

	if_rele(ifp);
	return (error);
}

static int
dump_vlan(struct ifnet *ifp, struct nl_writer *nw)
{
	return (0);
}

static struct nl_cloner vlan_cloner = {
	.name = "vlan",
	.create_f = create_vlan,
	.modify_f = modify_generic,
	.dump_f = dump_vlan,

};

static const struct nlhdr_parser *all_parsers[] = { &vlan_parser };

void
rtnl_iface_drivers_register(void)
{
	rtnl_iface_add_cloner(&vlan_cloner);
	NL_VERIFY_PARSERS(all_parsers);
}


