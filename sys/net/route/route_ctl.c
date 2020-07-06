/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Alexander V. Chernikov
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
#include "opt_mpath.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/rmlock.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/vnet.h>
#include <net/route.h>
#include <net/route/route_ctl.h>
#include <net/route/route_var.h>
#include <net/route/nhop_utils.h>
#include <net/route/nhop.h>
#include <net/route/nhop_var.h>
#include <net/route/shared.h>
#include <netinet/in.h>

#ifdef RADIX_MPATH
#include <net/radix_mpath.h>
#endif

#include <vm/uma.h>


/*
 * This file contains control plane routing tables functions.
 *
 * All functions assumes they are called in net epoch.
 */

struct rib_subscription {
	CK_STAILQ_ENTRY(rib_subscription)	next;
	rib_subscription_cb_t			*func;
	void					*arg;
	enum rib_subscription_type		type;
	struct epoch_context			epoch_ctx;
};

static void rib_notify(struct rib_head *rnh, enum rib_subscription_type type,
    struct rib_cmd_info *rc);

static void rt_notifydelete(struct rtentry *rt, struct rt_addrinfo *info);
static void destroy_subscription_epoch(epoch_context_t ctx);

static struct rib_head *
get_rnh(uint32_t fibnum, const struct rt_addrinfo *info)
{
	struct rib_head *rnh;
	struct sockaddr *dst;

	KASSERT((fibnum < rt_numfibs), ("rib_add_route: bad fibnum"));

	dst = info->rti_info[RTAX_DST];
	rnh = rt_tables_get_rnh(fibnum, dst->sa_family);

	return (rnh);
}

/*
 * Adds route defined by @info into the kernel table specified by @fibnum and
 * sa_family in @info->rti_info[RTAX_DST].
 *
 * Returns 0 on success and fills in operation metadata into @rc.
 */
int
rib_add_route(uint32_t fibnum, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	struct rib_head *rnh;

	NET_EPOCH_ASSERT();

	rnh = get_rnh(fibnum, info);
	if (rnh == NULL)
		return (EAFNOSUPPORT);

	/*
	 * Check consistency between RTF_HOST flag and netmask
	 * existence.
	 */
	if (info->rti_flags & RTF_HOST)
		info->rti_info[RTAX_NETMASK] = NULL;
	else if (info->rti_info[RTAX_NETMASK] == NULL)
		return (EINVAL);

	bzero(rc, sizeof(struct rib_cmd_info));
	rc->rc_cmd = RTM_ADD;

	return (add_route(rnh, info, rc));
}

int
add_route(struct rib_head *rnh, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	struct sockaddr *dst, *ndst, *gateway, *netmask;
	struct rtentry *rt, *rt_old;
	struct nhop_object *nh;
	struct radix_node *rn;
	struct ifaddr *ifa;
	int error, flags;
	struct epoch_tracker et;

	dst = info->rti_info[RTAX_DST];
	gateway = info->rti_info[RTAX_GATEWAY];
	netmask = info->rti_info[RTAX_NETMASK];
	flags = info->rti_flags;

	if ((flags & RTF_GATEWAY) && !gateway)
		return (EINVAL);
	if (dst && gateway && (dst->sa_family != gateway->sa_family) && 
	    (gateway->sa_family != AF_UNSPEC) && (gateway->sa_family != AF_LINK))
		return (EINVAL);

	if (dst->sa_len > sizeof(((struct rtentry *)NULL)->rt_dstb))
		return (EINVAL);

	if (info->rti_ifa == NULL) {
		error = rt_getifa_fib(info, rnh->rib_fibnum);
		if (error)
			return (error);
	} else {
		ifa_ref(info->rti_ifa);
	}

	NET_EPOCH_ENTER(et);
	error = nhop_create_from_info(rnh, info, &nh);
	NET_EPOCH_EXIT(et);
	if (error != 0) {
		ifa_free(info->rti_ifa);
		return (error);
	}

	rt = uma_zalloc(V_rtzone, M_NOWAIT);
	if (rt == NULL) {
		ifa_free(info->rti_ifa);
		nhop_free(nh);
		return (ENOBUFS);
	}
	rt->rt_flags = RTF_UP | flags;
	rt->rt_nhop = nh;

	/* Fill in dst */
	memcpy(&rt->rt_dst, dst, dst->sa_len);
	rt_key(rt) = &rt->rt_dst;

	/*
	 * point to the (possibly newly malloc'd) dest address.
	 */
	ndst = (struct sockaddr *)rt_key(rt);

	/*
	 * make sure it contains the value we want (masked if needed).
	 */
	if (netmask) {
		rt_maskedcopy(dst, ndst, netmask);
	} else
		bcopy(dst, ndst, dst->sa_len);

	/*
	 * We use the ifa reference returned by rt_getifa_fib().
	 * This moved from below so that rnh->rnh_addaddr() can
	 * examine the ifa and  ifa->ifa_ifp if it so desires.
	 */
	ifa = info->rti_ifa;
	rt->rt_weight = 1;

	rt_setmetrics(info, rt);
	rt_old = NULL;

	RIB_WLOCK(rnh);
	RT_LOCK(rt);
#ifdef RADIX_MPATH
	/* do not permit exactly the same dst/mask/gw pair */
	if (rt_mpath_capable(rnh) &&
		rt_mpath_conflict(rnh, rt, netmask)) {
		RIB_WUNLOCK(rnh);

		nhop_free(nh);
		uma_zfree(V_rtzone, rt);
		return (EEXIST);
	}
#endif

	rn = rnh->rnh_addaddr(ndst, netmask, &rnh->head, rt->rt_nodes);

	if (rn != NULL) {
		/* Most common usecase */
		if (rt->rt_expire > 0)
			tmproutes_update(rnh, rt);

		/* Finalize notification */
		rnh->rnh_gen++;

		rc->rc_rt = RNTORT(rn);
		rc->rc_nh_new = nh;

		rib_notify(rnh, RIB_NOTIFY_IMMEDIATE, rc);
	} else if ((info->rti_flags & RTF_PINNED) != 0) {

		/*
		 * Force removal and re-try addition
		 * TODO: better multipath&pinned support
		 */
		struct sockaddr *info_dst = info->rti_info[RTAX_DST];
		info->rti_info[RTAX_DST] = ndst;
		/* Do not delete existing PINNED(interface) routes */
		info->rti_flags &= ~RTF_PINNED;
		rt_old = rt_unlinkrte(rnh, info, &error);
		info->rti_flags |= RTF_PINNED;
		info->rti_info[RTAX_DST] = info_dst;
		if (rt_old != NULL) {
			rn = rnh->rnh_addaddr(ndst, netmask, &rnh->head,
			    rt->rt_nodes);

			/* Finalize notification */
			rnh->rnh_gen++;

			if (rn != NULL) {
				rc->rc_cmd = RTM_CHANGE;
				rc->rc_rt = RNTORT(rn);
				rc->rc_nh_old = rt_old->rt_nhop;
				rc->rc_nh_new = nh;
			} else {
				rc->rc_cmd = RTM_DELETE;
				rc->rc_rt = RNTORT(rn);
				rc->rc_nh_old = rt_old->rt_nhop;
				rc->rc_nh_new = nh;
			}
			rib_notify(rnh, RIB_NOTIFY_IMMEDIATE, rc);
		}
	}
	RIB_WUNLOCK(rnh);

	if ((rn != NULL) || (rt_old != NULL))
		rib_notify(rnh, RIB_NOTIFY_DELAYED, rc);

	if (rt_old != NULL) {
		rt_notifydelete(rt_old, info);
		rtfree(rt_old);
	}

	/*
	 * If it still failed to go into the tree,
	 * then un-make it (this should be a function)
	 */
	if (rn == NULL) {
		nhop_free(nh);
		uma_zfree(V_rtzone, rt);
		return (EEXIST);
	}

	/*
	 * If this protocol has something to add to this then
	 * allow it to do that as well.
	 */
	if (ifa->ifa_rtrequest)
		ifa->ifa_rtrequest(RTM_ADD, rt, rt->rt_nhop, info);

	RT_UNLOCK(rt);

	return (0);
}


/*
 * Removes route defined by @info from the kernel table specified by @fibnum and
 * sa_family in @info->rti_info[RTAX_DST].
 *
 * Returns 0 on success and fills in operation metadata into @rc.
 */
int
rib_del_route(uint32_t fibnum, struct rt_addrinfo *info, struct rib_cmd_info *rc)
{
	struct rib_head *rnh;

	NET_EPOCH_ASSERT();

	rnh = get_rnh(fibnum, info);
	if (rnh == NULL)
		return (EAFNOSUPPORT);

	bzero(rc, sizeof(struct rib_cmd_info));
	rc->rc_cmd = RTM_DELETE;

	return (del_route(rnh, info, rc));
}

/*
 * Conditionally unlinks rtentry matching data inside @info from @rnh.
 * Returns unlinked, locked and referenced @rtentry on success,
 * Returns NULL and sets @perror to:
 * ESRCH - if prefix was not found,
 * EADDRINUSE - if trying to delete PINNED route without appropriate flag.
 * ENOENT - if supplied filter function returned 0 (not matched).
 */
struct rtentry *
rt_unlinkrte(struct rib_head *rnh, struct rt_addrinfo *info, int *perror)
{
	struct sockaddr *dst, *netmask;
	struct rtentry *rt;
	struct radix_node *rn;

	dst = info->rti_info[RTAX_DST];
	netmask = info->rti_info[RTAX_NETMASK];

	rt = (struct rtentry *)rnh->rnh_lookup(dst, netmask, &rnh->head);
	if (rt == NULL) {
		*perror = ESRCH;
		return (NULL);
	}

	if ((info->rti_flags & RTF_PINNED) == 0) {
		/* Check if target route can be deleted */
		if (rt->rt_flags & RTF_PINNED) {
			*perror = EADDRINUSE;
			return (NULL);
		}
	}

	if (info->rti_filter != NULL) {
		if (info->rti_filter(rt, rt->rt_nhop, info->rti_filterdata)==0){
			/* Not matched */
			*perror = ENOENT;
			return (NULL);
		}

		/*
		 * Filter function requested rte deletion.
		 * Ease the caller work by filling in remaining info
		 * from that particular entry.
		 */
		info->rti_info[RTAX_GATEWAY] = &rt->rt_nhop->gw_sa;
	}

	/*
	 * Remove the item from the tree and return it.
	 * Complain if it is not there and do no more processing.
	 */
	*perror = ESRCH;
#ifdef RADIX_MPATH
	if (rt_mpath_capable(rnh))
		rn = rt_mpath_unlink(rnh, info, rt, perror);
	else
#endif
	rn = rnh->rnh_deladdr(dst, netmask, &rnh->head);
	if (rn == NULL)
		return (NULL);

	if (rn->rn_flags & (RNF_ACTIVE | RNF_ROOT))
		panic ("rtrequest delete");

	rt = RNTORT(rn);
	RT_LOCK(rt);
	rt->rt_flags &= ~RTF_UP;

	*perror = 0;

	return (rt);
}

int
del_route(struct rib_head *rnh, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	struct sockaddr *dst, *netmask;
	struct sockaddr_storage mdst;
	struct rtentry *rt;
	int error;

	dst = info->rti_info[RTAX_DST];
	netmask = info->rti_info[RTAX_NETMASK];

	if (netmask) {
		if (dst->sa_len > sizeof(mdst))
			return (EINVAL);
		rt_maskedcopy(dst, (struct sockaddr *)&mdst, netmask);
		dst = (struct sockaddr *)&mdst;
	}

	RIB_WLOCK(rnh);
	rt = rt_unlinkrte(rnh, info, &error);
	if (rt != NULL) {
		/* Finalize notification */
		rnh->rnh_gen++;
		rc->rc_rt = rt;
		rc->rc_nh_old = rt->rt_nhop;
		rib_notify(rnh, RIB_NOTIFY_IMMEDIATE, rc);
	}
	RIB_WUNLOCK(rnh);
	if (error != 0)
		return (error);

	rib_notify(rnh, RIB_NOTIFY_DELAYED, rc);
	rt_notifydelete(rt, info);

	/*
	 * If the caller wants it, then it can have it,
	 * the entry will be deleted after the end of the current epoch.
	 */
	rtfree(rt);

	return (0);
}

int
rib_change_route(uint32_t fibnum, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	struct rib_head *rnh;

	NET_EPOCH_ASSERT();

	rnh = get_rnh(fibnum, info);
	if (rnh == NULL)
		return (EAFNOSUPPORT);

	bzero(rc, sizeof(struct rib_cmd_info));
	rc->rc_cmd = RTM_CHANGE;

	return (change_route(rnh, info, rc));
}

static int
change_route_one(struct rib_head *rnh, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	RIB_RLOCK_TRACKER;
	struct rtentry *rt = NULL;
	int error = 0;
	int free_ifa = 0;
	struct nhop_object *nh, *nh_orig;

	RIB_RLOCK(rnh);
	rt = (struct rtentry *)rnh->rnh_lookup(info->rti_info[RTAX_DST],
	    info->rti_info[RTAX_NETMASK], &rnh->head);

	if (rt == NULL) {
		RIB_RUNLOCK(rnh);
		return (ESRCH);
	}

#ifdef RADIX_MPATH
	/*
	 * If we got multipath routes,
	 * we require users to specify a matching RTAX_GATEWAY.
	 */
	if (rt_mpath_capable(rnh)) {
		rt = rt_mpath_matchgate(rt, info->rti_info[RTAX_GATEWAY]);
		if (rt == NULL) {
			RIB_RUNLOCK(rnh);
			return (ESRCH);
		}
	}
#endif
	nh_orig = rt->rt_nhop;

	RIB_RUNLOCK(rnh);

	rt = NULL;
	nh = NULL;

	/*
	 * New gateway could require new ifaddr, ifp;
	 * flags may also be different; ifp may be specified
	 * by ll sockaddr when protocol address is ambiguous
	 */
	if (((nh_orig->nh_flags & NHF_GATEWAY) &&
	    info->rti_info[RTAX_GATEWAY] != NULL) ||
	    info->rti_info[RTAX_IFP] != NULL ||
	    (info->rti_info[RTAX_IFA] != NULL &&
	     !sa_equal(info->rti_info[RTAX_IFA], nh_orig->nh_ifa->ifa_addr))) {
		error = rt_getifa_fib(info, rnh->rib_fibnum);
		if (info->rti_ifa != NULL)
			free_ifa = 1;

		if (error != 0) {
			if (free_ifa) {
				ifa_free(info->rti_ifa);
				info->rti_ifa = NULL;
			}

			return (error);
		}
	}

	error = nhop_create_from_nhop(rnh, nh_orig, info, &nh);
	if (free_ifa) {
		ifa_free(info->rti_ifa);
		info->rti_ifa = NULL;
	}
	if (error != 0)
		return (error);

	RIB_WLOCK(rnh);

	/* Lookup rtentry once again and check if nexthop is still the same */
	rt = (struct rtentry *)rnh->rnh_lookup(info->rti_info[RTAX_DST],
	    info->rti_info[RTAX_NETMASK], &rnh->head);

	if (rt == NULL) {
		RIB_WUNLOCK(rnh);
		nhop_free(nh);
		return (ESRCH);
	}

	if (rt->rt_nhop != nh_orig) {
		RIB_WUNLOCK(rnh);
		nhop_free(nh);
		return (EAGAIN);
	}

	/* Proceed with the update */
	RT_LOCK(rt);

	/* Provide notification to the protocols.*/
	if ((nh_orig->nh_ifa != nh->nh_ifa) && nh_orig->nh_ifa->ifa_rtrequest)
		nh_orig->nh_ifa->ifa_rtrequest(RTM_DELETE, rt, nh_orig, info);

	rt->rt_nhop = nh;
	rt_setmetrics(info, rt);

	if ((nh_orig->nh_ifa != nh->nh_ifa) && nh_orig->nh_ifa->ifa_rtrequest)
		nh_orig->nh_ifa->ifa_rtrequest(RTM_DELETE, rt, nh_orig, info);

	/* Finalize notification */
	rc->rc_rt = rt;
	rc->rc_nh_old = nh_orig;
	rc->rc_nh_new = rt->rt_nhop;

	RT_UNLOCK(rt);

	/* Update generation id to reflect rtable change */
	rnh->rnh_gen++;
	rib_notify(rnh, RIB_NOTIFY_IMMEDIATE, rc);

	RIB_WUNLOCK(rnh);

	rib_notify(rnh, RIB_NOTIFY_DELAYED, rc);

	nhop_free(nh_orig);

	return (0);
}

int
change_route(struct rib_head *rnh, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	int error;

	/* Check if updated gateway exists */
	if ((info->rti_flags & RTF_GATEWAY) &&
	    (info->rti_info[RTAX_GATEWAY] == NULL))
		return (EINVAL);

	/*
	 * route change is done in multiple steps, with dropping and
	 * reacquiring lock. In the situations with multiple processes
	 * changes the same route in can lead to the case when route
	 * is changed between the steps. Address it by retrying the operation
	 * multiple times before failing.
	 */
	for (int i = 0; i < RIB_MAX_RETRIES; i++) {
		error = change_route_one(rnh, info, rc);
		if (error != EAGAIN)
			break;
	}

	return (error);
}

/*
 * Performs modification of routing table specificed by @action.
 * Table is specified by @fibnum and sa_family in @info->rti_info[RTAX_DST].
 * Needs to be run in network epoch.
 *
 * Returns 0 on success and fills in @rc with action result.
 */
int
rib_action(uint32_t fibnum, int action, struct rt_addrinfo *info,
    struct rib_cmd_info *rc)
{
	int error;

	switch (action) {
	case RTM_ADD:
		error = rib_add_route(fibnum, info, rc);
		break;
	case RTM_DELETE:
		error = rib_del_route(fibnum, info, rc);
		break;
	case RTM_CHANGE:
		error = rib_change_route(fibnum, info, rc);
		break;
	default:
		error = ENOTSUP;
	}

	return (error);
}


static void
rt_notifydelete(struct rtentry *rt, struct rt_addrinfo *info)
{
	struct ifaddr *ifa;

	/*
	 * give the protocol a chance to keep things in sync.
	 */
	ifa = rt->rt_nhop->nh_ifa;
	if (ifa != NULL && ifa->ifa_rtrequest != NULL)
		ifa->ifa_rtrequest(RTM_DELETE, rt, rt->rt_nhop, info);
}

struct rt_delinfo
{
	struct rt_addrinfo info;
	struct rib_head *rnh;
	struct rtentry *head;
	struct rib_cmd_info rc;
};

/*
 * Conditionally unlinks @rn from radix tree based
 * on info data passed in @arg.
 */
static int
rt_checkdelroute(struct radix_node *rn, void *arg)
{
	struct rt_delinfo *di;
	struct rt_addrinfo *info;
	struct rtentry *rt;
	int error;

	di = (struct rt_delinfo *)arg;
	rt = (struct rtentry *)rn;
	info = &di->info;
	error = 0;

	info->rti_info[RTAX_DST] = rt_key(rt);
	info->rti_info[RTAX_NETMASK] = rt_mask(rt);
	info->rti_info[RTAX_GATEWAY] = &rt->rt_nhop->gw_sa;

	rt = rt_unlinkrte(di->rnh, info, &error);
	if (rt == NULL) {
		/* Either not allowed or not matched. Skip entry */
		return (0);
	}

	/* Entry was unlinked. Notify subscribers */
	di->rnh->rnh_gen++;
	di->rc.rc_rt = rt;
	di->rc.rc_nh_old = rt->rt_nhop;
	rib_notify(di->rnh, RIB_NOTIFY_IMMEDIATE, &di->rc);

	/* Add to the list and return */
	rt->rt_chain = di->head;
	di->head = rt;

	return (0);
}

/*
 * Iterates over a routing table specified by @fibnum and @family and
 *  deletes elements marked by @filter_f.
 * @fibnum: rtable id
 * @family: AF_ address family
 * @filter_f: function returning non-zero value for items to delete
 * @arg: data to pass to the @filter_f function
 * @report: true if rtsock notification is needed.
 */
void
rib_walk_del(u_int fibnum, int family, rt_filter_f_t *filter_f, void *arg, bool report)
{
	struct rib_head *rnh;
	struct rt_delinfo di;
	struct rtentry *rt;
	struct epoch_tracker et;

	rnh = rt_tables_get_rnh(fibnum, family);
	if (rnh == NULL)
		return;

	bzero(&di, sizeof(di));
	di.info.rti_filter = filter_f;
	di.info.rti_filterdata = arg;
	di.rnh = rnh;
	di.rc.rc_cmd = RTM_DELETE;

	NET_EPOCH_ENTER(et);

	RIB_WLOCK(rnh);
	rnh->rnh_walktree(&rnh->head, rt_checkdelroute, &di);
	RIB_WUNLOCK(rnh);

	/* We might have something to reclaim. */
	while (di.head != NULL) {
		rt = di.head;
		di.head = rt->rt_chain;
		rt->rt_chain = NULL;

		di.rc.rc_rt = rt;
		di.rc.rc_nh_old = rt->rt_nhop;
		rib_notify(rnh, RIB_NOTIFY_DELAYED, &di.rc);

		/* TODO std rt -> rt_addrinfo export */
		di.info.rti_info[RTAX_DST] = rt_key(rt);
		di.info.rti_info[RTAX_NETMASK] = rt_mask(rt);

		rt_notifydelete(rt, &di.info);

		if (report)
			rt_routemsg(RTM_DELETE, rt, rt->rt_nhop->nh_ifp, 0,
			    fibnum);
		rtfree(rt);
	}

	NET_EPOCH_EXIT(et);
}

static void
rib_notify(struct rib_head *rnh, enum rib_subscription_type type,
    struct rib_cmd_info *rc)
{
	struct rib_subscription *rs;

	CK_STAILQ_FOREACH(rs, &rnh->rnh_subscribers, next) {
		if (rs->type == type)
			rs->func(rnh, rc, rs->arg);
	}
}

/*
 * Subscribe for the changes in the routing table specified by @fibnum and
 *  @family.
 * Needs to be run in network epoch.
 *
 * Returns pointer to the subscription structure on success.
 */
struct rib_subscription *
rib_subscribe(uint32_t fibnum, int family, rib_subscription_cb_t *f, void *arg,
    enum rib_subscription_type type, int waitok)
{
	struct rib_head *rnh;
	struct rib_subscription *rs;
	int flags = M_ZERO | (waitok ? M_WAITOK : 0);

	NET_EPOCH_ASSERT();
	KASSERT((fibnum < rt_numfibs), ("%s: bad fibnum", __func__));
	rnh = rt_tables_get_rnh(fibnum, family);

	rs = malloc(sizeof(struct rib_subscription), M_RTABLE, flags);
	if (rs == NULL)
		return (NULL);

	rs->func = f;
	rs->arg = arg;
	rs->type = type;

	RIB_WLOCK(rnh);
	CK_STAILQ_INSERT_TAIL(&rnh->rnh_subscribers, rs, next);
	RIB_WUNLOCK(rnh);

	return (rs);
}

/*
 * Remove rtable subscription @rs from the table specified by @fibnum
 *  and @family.
 * Needs to be run in network epoch.
 *
 * Returns 0 on success.
 */
int
rib_unsibscribe(uint32_t fibnum, int family, struct rib_subscription *rs)
{
	struct rib_head *rnh;

	NET_EPOCH_ASSERT();
	KASSERT((fibnum < rt_numfibs), ("%s: bad fibnum", __func__));
	rnh = rt_tables_get_rnh(fibnum, family);

	if (rnh == NULL)
		return (ENOENT);

	RIB_WLOCK(rnh);
	CK_STAILQ_REMOVE(&rnh->rnh_subscribers, rs, rib_subscription, next);
	RIB_WUNLOCK(rnh);

	epoch_call(net_epoch_preempt, destroy_subscription_epoch,
	    &rs->epoch_ctx);

	return (0);
}

/*
 * Epoch callback indicating subscription is safe to destroy
 */
static void
destroy_subscription_epoch(epoch_context_t ctx)
{
	struct rib_subscription *rs;

	rs = __containerof(ctx, struct rib_subscription, epoch_ctx);

	free(rs, M_RTABLE);
}
