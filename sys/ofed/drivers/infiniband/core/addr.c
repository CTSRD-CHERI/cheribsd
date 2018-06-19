/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 * Copyright (c) 1999-2005, Mellanox Technologies, Inc. All rights reserved.
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/mutex.h>
#include <linux/inetdevice.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <net/route.h>
#include <net/netevent.h>
#include <rdma/ib_addr.h>
#include <netinet/if_ether.h>
#include <netinet6/scope6_var.h>


MODULE_AUTHOR("Sean Hefty");
MODULE_DESCRIPTION("IB Address Translation");
MODULE_LICENSE("Dual BSD/GPL");

struct addr_req {
	struct list_head list;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	struct rdma_dev_addr *addr;
	struct rdma_addr_client *client;
	void *context;
	void (*callback)(int status, struct sockaddr *src_addr,
			 struct rdma_dev_addr *addr, void *context);
	unsigned long timeout;
	int status;
};

static void process_req(struct work_struct *work);

static DEFINE_MUTEX(lock);
static LIST_HEAD(req_list);
static struct delayed_work work;
static struct workqueue_struct *addr_wq;

static struct rdma_addr_client self;
void rdma_addr_register_client(struct rdma_addr_client *client)
{
	atomic_set(&client->refcount, 1);
	init_completion(&client->comp);
}
EXPORT_SYMBOL(rdma_addr_register_client);

static inline void put_client(struct rdma_addr_client *client)
{
	if (atomic_dec_and_test(&client->refcount))
		complete(&client->comp);
}

void rdma_addr_unregister_client(struct rdma_addr_client *client)
{
	put_client(client);
	wait_for_completion(&client->comp);
}
EXPORT_SYMBOL(rdma_addr_unregister_client);

int rdma_copy_addr(struct rdma_dev_addr *dev_addr, struct ifnet *dev,
		     const unsigned char *dst_dev_addr)
{
	if (dev->if_type == IFT_INFINIBAND)
		dev_addr->dev_type = ARPHRD_INFINIBAND;
	else if (dev->if_type == IFT_ETHER)
		dev_addr->dev_type = ARPHRD_ETHER;
	else
		dev_addr->dev_type = 0;
	memcpy(dev_addr->src_dev_addr, IF_LLADDR(dev), dev->if_addrlen);
	memcpy(dev_addr->broadcast, __DECONST(char *, dev->if_broadcastaddr),
	    dev->if_addrlen);
	if (dst_dev_addr)
		memcpy(dev_addr->dst_dev_addr, dst_dev_addr, dev->if_addrlen);
	dev_addr->bound_dev_if = dev->if_index;
	return 0;
}
EXPORT_SYMBOL(rdma_copy_addr);

int rdma_translate_ip(struct sockaddr *addr, struct rdma_dev_addr *dev_addr,
		      u16 *vlan_id)
{
	struct net_device *dev;
	int ret = -EADDRNOTAVAIL;

	if (dev_addr->bound_dev_if) {
		dev = dev_get_by_index(&init_net, dev_addr->bound_dev_if);
		if (!dev)
			return -ENODEV;
		ret = rdma_copy_addr(dev_addr, dev, NULL);
		dev_put(dev);
		return ret;
	}

	switch (addr->sa_family) {
	case AF_INET:
		dev = ip_dev_find(&init_net,
			((struct sockaddr_in *) addr)->sin_addr.s_addr);

		if (!dev)
			return ret;

		ret = rdma_copy_addr(dev_addr, dev, NULL);
		if (vlan_id)
			*vlan_id = rdma_vlan_dev_vlan_id(dev);
		dev_put(dev);
		break;

#if defined(INET6)
	case AF_INET6:
		dev = ip6_dev_find(&init_net,
			((const struct sockaddr_in6 *)addr)->sin6_addr);

		if (!dev)
			return ret;

		ret = rdma_copy_addr(dev_addr, dev, NULL);
		if (vlan_id)
			*vlan_id = rdma_vlan_dev_vlan_id(dev);
		dev_put(dev);
		break;
#endif
	default:
		break;
	}
	return ret;
}
EXPORT_SYMBOL(rdma_translate_ip);

static void set_timeout(unsigned long time)
{
	int delay;	/* under FreeBSD ticks are 32-bit */

	delay = time - jiffies;
	if (delay <= 0)
		delay = 1;

	mod_delayed_work(addr_wq, &work, delay);
}

static void queue_req(struct addr_req *req)
{
	struct addr_req *temp_req;

	mutex_lock(&lock);
	list_for_each_entry_reverse(temp_req, &req_list, list) {
		if (time_after_eq(req->timeout, temp_req->timeout))
			break;
	}

	list_add(&req->list, &temp_req->list);

	if (req_list.next == &req->list)
		set_timeout(req->timeout);
	mutex_unlock(&lock);
}

static int addr_resolve(struct sockaddr *src_in,
			struct sockaddr *dst_in,
			struct rdma_dev_addr *addr)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ifaddr *ifa;
	struct ifnet *ifp;
	struct rtentry *rte;
#if defined(INET6)
	struct sockaddr_in6 dstv6_tmp;
#endif
	u_char edst[MAX_ADDR_LEN];
	int multi;
	int bcast;
	int is_gw = 0;
	int error = 0;

	CURVNET_SET_QUIET(&init_net);

	/*
	 * Determine whether the address is unicast, multicast, or broadcast
	 * and whether the source interface is valid.
	 */
	multi = 0;
	bcast = 0;
	sin = NULL;
	sin6 = NULL;
	ifp = NULL;
	rte = NULL;
	ifa = NULL;
	memset(edst, 0, sizeof(edst));

	switch (dst_in->sa_family) {
#ifdef INET
	case AF_INET:
		sin = (struct sockaddr_in *)dst_in;
		if (sin->sin_addr.s_addr == INADDR_BROADCAST)
			bcast = 1;
		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			multi = 1;
		sin = (struct sockaddr_in *)src_in;
		if (sin->sin_addr.s_addr != INADDR_ANY) {
			ifp = ip_dev_find(&init_net, sin->sin_addr.s_addr);
			if (ifp == NULL) {
				error = ENETUNREACH;
				goto done;
			}
			if (bcast || multi)
				goto mcast;
		}
		break;
#endif
#ifdef INET6
	case AF_INET6:
		/* Make destination socket address writeable */
		dstv6_tmp = *(struct sockaddr_in6 *)dst_in;
		dst_in = (struct sockaddr *)&dstv6_tmp;
		sin6 = (struct sockaddr_in6 *)dst_in;
		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			multi = 1;
		/*
		 * Make sure the scope ID gets embedded, else rtalloc1() will
		 * resolve to the loopback interface.
		 */
		sin6->sin6_scope_id = addr->bound_dev_if;
		sa6_embedscope(sin6, 0);

		sin6 = (struct sockaddr_in6 *)src_in;
		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			ifp = ip6_dev_find(&init_net, sin6->sin6_addr);
			if (ifp == NULL) {
				error = ENETUNREACH;
				goto done;
			}
			if (bcast || multi)
				goto mcast;
		}
		break;
#endif
	default:
		error = EINVAL;
		goto done;
	}
	/*
	 * Make sure the route exists and has a valid link.
	 */
	rte = rtalloc1(dst_in, 1, 0);
	if (rte == NULL || rte->rt_ifp == NULL ||
	    RT_LINK_IS_UP(rte->rt_ifp) == 0 ||
	    rte->rt_ifp == V_loif) {
		if (rte != NULL) {
			RTFREE_LOCKED(rte);
			rte = NULL;
		}
		error = EHOSTUNREACH;
		goto done;
	}
	if (rte->rt_flags & RTF_GATEWAY)
		is_gw = 1;
	/*
	 * If it's not multicast or broadcast and the route doesn't match the
	 * requested interface return unreachable.  Otherwise fetch the
	 * correct interface pointer and unlock the route.
	 */
	if (multi || bcast) {
		/* rt_ifa holds the route answer source address */
		ifa = rte->rt_ifa;

		if (ifp == NULL) {
			ifp = rte->rt_ifp;
			dev_hold(ifp);
		}
		RTFREE_LOCKED(rte);
		rte = NULL;
	} else if (ifp != NULL && ifp != rte->rt_ifp) {
		RTFREE_LOCKED(rte);
		rte = NULL;
		error = ENETUNREACH;
		goto done;
	} else {
		/* rt_ifa holds the route answer source address */
		ifa = rte->rt_ifa;

		if (ifp == NULL) {
			ifp = rte->rt_ifp;
			dev_hold(ifp);
		}
		RT_UNLOCK(rte);
	}
#if defined(INET) || defined(INET6)
mcast:
#endif
	if (bcast) {
		memcpy(edst, ifp->if_broadcastaddr, ifp->if_addrlen);
		goto done;
	} else if (multi) {
		struct sockaddr *llsa;
		struct sockaddr_dl sdl;

		sdl.sdl_len = sizeof(sdl);
		llsa = (struct sockaddr *)&sdl;

		if (ifp->if_resolvemulti == NULL) {
			error = EOPNOTSUPP;
			goto done;
		}
		error = ifp->if_resolvemulti(ifp, &llsa, dst_in);
		if (error == 0) {
			memcpy(edst, LLADDR((struct sockaddr_dl *)llsa),
			    ifp->if_addrlen);
		}
		goto done;
	}
	/*
	 * Resolve the link local address.
	 */
	switch (dst_in->sa_family) {
#ifdef INET
	case AF_INET:
		error = arpresolve(ifp, is_gw, NULL,
		    is_gw ? rte->rt_gateway : dst_in, edst, NULL, NULL);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		error = nd6_resolve(ifp, is_gw, NULL,
		    is_gw ? rte->rt_gateway : dst_in, edst, NULL, NULL);
		break;
#endif
	default:
		KASSERT(0, ("rdma_addr_resolve: Unreachable"));
		error = EINVAL;
		break;
	}
done:
	if (error == 0)
		error = -rdma_copy_addr(addr, ifp, edst);
	if (error == 0)
		memcpy(src_in, ifa->ifa_addr, ip_addr_size(ifa->ifa_addr));
	if (error == EWOULDBLOCK)
		error = ENODATA;
	if (rte != NULL)
		RTFREE(rte);
	if (ifp != NULL)
		dev_put(ifp);

	CURVNET_RESTORE();
	return -error;
}

static void process_req(struct work_struct *work)
{
	struct addr_req *req, *temp_req;
	struct sockaddr *src_in, *dst_in;
	struct list_head done_list;

	INIT_LIST_HEAD(&done_list);

	mutex_lock(&lock);
	list_for_each_entry_safe(req, temp_req, &req_list, list) {
		if (req->status == -ENODATA) {
			src_in = (struct sockaddr *) &req->src_addr;
			dst_in = (struct sockaddr *) &req->dst_addr;
			req->status = addr_resolve(src_in, dst_in, req->addr);
			if (req->status && time_after_eq(jiffies, req->timeout))
				req->status = -ETIMEDOUT;
			else if (req->status == -ENODATA)
				continue;
		}
		list_move_tail(&req->list, &done_list);
	}

	if (!list_empty(&req_list)) {
		req = list_entry(req_list.next, struct addr_req, list);
		set_timeout(req->timeout);
	}
	mutex_unlock(&lock);

	list_for_each_entry_safe(req, temp_req, &done_list, list) {
		list_del(&req->list);
		req->callback(req->status, (struct sockaddr *) &req->src_addr,
			req->addr, req->context);
		put_client(req->client);
		kfree(req);
	}
}

int rdma_resolve_ip(struct rdma_addr_client *client,
		    struct sockaddr *src_addr, struct sockaddr *dst_addr,
		    struct rdma_dev_addr *addr, int timeout_ms,
		    void (*callback)(int status, struct sockaddr *src_addr,
				     struct rdma_dev_addr *addr, void *context),
		    void *context)
{
	struct sockaddr *src_in, *dst_in;
	struct addr_req *req;
	int ret = 0;

	req = kzalloc(sizeof *req, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	src_in = (struct sockaddr *) &req->src_addr;
	dst_in = (struct sockaddr *) &req->dst_addr;

	if (src_addr) {
		if (src_addr->sa_family != dst_addr->sa_family) {
			ret = -EINVAL;
			goto err;
		}

		memcpy(src_in, src_addr, ip_addr_size(src_addr));
	} else {
		src_in->sa_family = dst_addr->sa_family;
	}

	memcpy(dst_in, dst_addr, ip_addr_size(dst_addr));
	req->addr = addr;
	req->callback = callback;
	req->context = context;
	req->client = client;
	atomic_inc(&client->refcount);

	req->status = addr_resolve(src_in, dst_in, addr);
	switch (req->status) {
	case 0:
		req->timeout = jiffies;
		queue_req(req);
		break;
	case -ENODATA:
		req->timeout = msecs_to_jiffies(timeout_ms) + jiffies;
		queue_req(req);
		break;
	default:
		ret = req->status;
		atomic_dec(&client->refcount);
		goto err;
	}
	return ret;
err:
	kfree(req);
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_ip);

void rdma_addr_cancel(struct rdma_dev_addr *addr)
{
	struct addr_req *req, *temp_req;

	mutex_lock(&lock);
	list_for_each_entry_safe(req, temp_req, &req_list, list) {
		if (req->addr == addr) {
			req->status = -ECANCELED;
			req->timeout = jiffies;
			list_move(&req->list, &req_list);
			set_timeout(req->timeout);
			break;
		}
	}
	mutex_unlock(&lock);
}
EXPORT_SYMBOL(rdma_addr_cancel);

struct resolve_cb_context {
	struct rdma_dev_addr *addr;
	struct completion comp;
};

static void resolve_cb(int status, struct sockaddr *src_addr,
	     struct rdma_dev_addr *addr, void *context)
{
	memcpy(((struct resolve_cb_context *)context)->addr, addr, sizeof(struct
				rdma_dev_addr));
	complete(&((struct resolve_cb_context *)context)->comp);
}

int rdma_addr_find_dmac_by_grh(union ib_gid *sgid, union ib_gid *dgid, u8 *dmac,
			       u16 *vlan_id, int *if_index)
{
	int ret = 0;
	struct rdma_dev_addr dev_addr;
	struct resolve_cb_context ctx;
	struct net_device *dev;

	union {
		struct sockaddr     _sockaddr;
		struct sockaddr_in  _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} sgid_addr, dgid_addr;

	ret = rdma_gid2ip(&sgid_addr._sockaddr, sgid);
	if (ret)
		return ret;

	ret = rdma_gid2ip(&dgid_addr._sockaddr, dgid);
	if (ret)
		return ret;

	memset(&dev_addr, 0, sizeof(dev_addr));
	if (if_index)
		dev_addr.bound_dev_if = *if_index;

	ctx.addr = &dev_addr;
	init_completion(&ctx.comp);
	ret = rdma_resolve_ip(&self, &sgid_addr._sockaddr, &dgid_addr._sockaddr,
			&dev_addr, 1000, resolve_cb, &ctx);
	if (ret)
		return ret;

	wait_for_completion(&ctx.comp);

	memcpy(dmac, dev_addr.dst_dev_addr, ETH_ALEN);
	dev = dev_get_by_index(&init_net, dev_addr.bound_dev_if);
	if (!dev)
		return -ENODEV;
	if (vlan_id)
		*vlan_id = rdma_vlan_dev_vlan_id(dev);
	dev_put(dev);
	return ret;
}
EXPORT_SYMBOL(rdma_addr_find_dmac_by_grh);

int rdma_addr_find_smac_by_sgid(union ib_gid *sgid, u8 *smac, u16 *vlan_id)
{
	int ret = 0;
	struct rdma_dev_addr dev_addr;
	union {
		struct sockaddr     _sockaddr;
		struct sockaddr_in  _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} gid_addr;

	ret = rdma_gid2ip(&gid_addr._sockaddr, sgid);
	if (ret)
		return ret;
	memset(&dev_addr, 0, sizeof(dev_addr));
	ret = rdma_translate_ip(&gid_addr._sockaddr, &dev_addr, vlan_id);
	if (ret)
		return ret;

	memcpy(smac, dev_addr.src_dev_addr, ETH_ALEN);
	return ret;
}
EXPORT_SYMBOL(rdma_addr_find_smac_by_sgid);

static int netevent_callback(struct notifier_block *self, unsigned long event,
	void *ctx)
{
	if (event == NETEVENT_NEIGH_UPDATE) {
			set_timeout(jiffies);
		}
	return 0;
}

static struct notifier_block nb = {
	.notifier_call = netevent_callback
};

static int __init addr_init(void)
{
	INIT_DELAYED_WORK(&work, process_req);
	addr_wq = create_singlethread_workqueue("ib_addr");
	if (!addr_wq)
		return -ENOMEM;

	register_netevent_notifier(&nb);
	rdma_addr_register_client(&self);
	return 0;
}

static void __exit addr_cleanup(void)
{
	rdma_addr_unregister_client(&self);
	unregister_netevent_notifier(&nb);
	destroy_workqueue(addr_wq);
}

module_init(addr_init);
module_exit(addr_cleanup);
