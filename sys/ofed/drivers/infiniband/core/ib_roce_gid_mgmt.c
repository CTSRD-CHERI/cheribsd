/*
 * Copyright (c) 2015-2017, Mellanox Technologies inc.  All rights reserved.
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

#include "core_priv.h"

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/rcupdate.h>

#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>

#include <netinet6/scope6_var.h>

static struct workqueue_struct *roce_gid_mgmt_wq;

enum gid_op_type {
	GID_DEL = 0,
	GID_ADD
};

struct roce_netdev_event_work {
	struct work_struct work;
	struct net_device *ndev;
};

struct roce_rescan_work {
	struct work_struct	work;
	struct ib_device	*ib_dev;
};

static const struct {
	bool (*is_supported)(const struct ib_device *device, u8 port_num);
	enum ib_gid_type gid_type;
} PORT_CAP_TO_GID_TYPE[] = {
	{rdma_protocol_roce_eth_encap, IB_GID_TYPE_ROCE},
	{rdma_protocol_roce_udp_encap, IB_GID_TYPE_ROCE_UDP_ENCAP},
};

#define CAP_TO_GID_TABLE_SIZE	ARRAY_SIZE(PORT_CAP_TO_GID_TYPE)

unsigned long roce_gid_type_mask_support(struct ib_device *ib_dev, u8 port)
{
	int i;
	unsigned int ret_flags = 0;

	if (!rdma_protocol_roce(ib_dev, port))
		return 1UL << IB_GID_TYPE_IB;

	for (i = 0; i < CAP_TO_GID_TABLE_SIZE; i++)
		if (PORT_CAP_TO_GID_TYPE[i].is_supported(ib_dev, port))
			ret_flags |= 1UL << PORT_CAP_TO_GID_TYPE[i].gid_type;

	return ret_flags;
}
EXPORT_SYMBOL(roce_gid_type_mask_support);

static void update_gid(enum gid_op_type gid_op, struct ib_device *ib_dev,
    u8 port, union ib_gid *gid, struct net_device *ndev)
{
	int i;
	unsigned long gid_type_mask = roce_gid_type_mask_support(ib_dev, port);
	struct ib_gid_attr gid_attr;

	memset(&gid_attr, 0, sizeof(gid_attr));
	gid_attr.ndev = ndev;

	for (i = 0; i != IB_GID_TYPE_SIZE; i++) {
		if ((1UL << i) & gid_type_mask) {
			gid_attr.gid_type = i;
			switch (gid_op) {
			case GID_ADD:
				ib_cache_gid_add(ib_dev, port,
						 gid, &gid_attr);
				break;
			case GID_DEL:
				ib_cache_gid_del(ib_dev, port,
						 gid, &gid_attr);
				break;
			}
		}
	}
}

static int
roce_gid_match_netdev(struct ib_device *ib_dev, u8 port,
    struct net_device *idev, void *cookie)
{
	struct net_device *ndev = (struct net_device *)cookie;
	if (idev == NULL)
		return (0);
	return (ndev == idev);
}

static int
roce_gid_match_all(struct ib_device *ib_dev, u8 port,
    struct net_device *idev, void *cookie)
{
	if (idev == NULL)
		return (0);
	return (1);
}

static int
roce_gid_enum_netdev_default(struct ib_device *ib_dev,
    u8 port, struct net_device *idev)
{
	unsigned long gid_type_mask;

	gid_type_mask = roce_gid_type_mask_support(ib_dev, port);

	ib_cache_gid_set_default_gid(ib_dev, port, idev, gid_type_mask,
				     IB_CACHE_GID_DEFAULT_MODE_SET);

	return (hweight_long(gid_type_mask));
}

#define ETH_IPOIB_DRV_NAME	"ib"

static inline int
is_eth_ipoib_intf(struct net_device *dev)
{
	if (strcmp(dev->if_dname, ETH_IPOIB_DRV_NAME))
		return 0;
	return 1;
}

static void
roce_gid_update_addr_callback(struct ib_device *device, u8 port,
    struct net_device *ndev, void *cookie)
{
	struct ipx_entry {
		STAILQ_ENTRY(ipx_entry)	entry;
		union ipx_addr {
			struct sockaddr sa[0];
			struct sockaddr_in v4;
			struct sockaddr_in6 v6;
		} ipx_addr;
	};
	struct ipx_entry *entry;
	struct net_device *idev;
#if defined(INET) || defined(INET6)
	struct ifaddr *ifa;
#endif
	union ib_gid gid;
	int default_gids;
	u16 index_num;
	int i;

	STAILQ_HEAD(, ipx_entry) ipx_head;

	STAILQ_INIT(&ipx_head);

	/* make sure default GIDs are in */
	default_gids = roce_gid_enum_netdev_default(device, port, ndev);

	CURVNET_SET(ndev->if_vnet);
	IFNET_RLOCK();
	TAILQ_FOREACH(idev, &V_ifnet, if_link) {
		if (idev != ndev) {
			if (idev->if_type != IFT_L2VLAN)
				continue;
			if (ndev != rdma_vlan_dev_real_dev(idev))
				continue;
		}

		/* clone address information for IPv4 and IPv6 */
		IF_ADDR_RLOCK(idev);
#if defined(INET)
		TAILQ_FOREACH(ifa, &idev->if_addrhead, ifa_link) {
			if (ifa->ifa_addr == NULL ||
			    ifa->ifa_addr->sa_family != AF_INET)
				continue;
			entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
			if (entry == NULL) {
				pr_warn("roce_gid_update_addr_callback: "
				    "couldn't allocate entry for IPv4 update\n");
				continue;
			}
			entry->ipx_addr.v4 = *((struct sockaddr_in *)ifa->ifa_addr);
			STAILQ_INSERT_TAIL(&ipx_head, entry, entry);
		}
#endif
#if defined(INET6)
		TAILQ_FOREACH(ifa, &idev->if_addrhead, ifa_link) {
			if (ifa->ifa_addr == NULL ||
			    ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
			if (entry == NULL) {
				pr_warn("roce_gid_update_addr_callback: "
				    "couldn't allocate entry for IPv6 update\n");
				continue;
			}
			entry->ipx_addr.v6 = *((struct sockaddr_in6 *)ifa->ifa_addr);

			/* trash IPv6 scope ID */
			sa6_recoverscope(&entry->ipx_addr.v6);
			entry->ipx_addr.v6.sin6_scope_id = 0;

			STAILQ_INSERT_TAIL(&ipx_head, entry, entry);
		}
#endif
		IF_ADDR_RUNLOCK(idev);
	}
	IFNET_RUNLOCK();
	CURVNET_RESTORE();

	/* add missing GIDs, if any */
	STAILQ_FOREACH(entry, &ipx_head, entry) {
		unsigned long gid_type_mask = roce_gid_type_mask_support(device, port);

		if (rdma_ip2gid(&entry->ipx_addr.sa[0], &gid) != 0)
			continue;

		for (i = 0; i != IB_GID_TYPE_SIZE; i++) {
			if (!((1UL << i) & gid_type_mask))
				continue;
			/* check if entry found */
			if (ib_find_cached_gid_by_port(device, &gid, i,
			    port, ndev, &index_num) == 0)
				break;
		}
		if (i != IB_GID_TYPE_SIZE)
			continue;
		/* add new GID */
		update_gid(GID_ADD, device, port, &gid, ndev);
	}

	/* remove stale GIDs, if any */
	for (i = default_gids; ib_get_cached_gid(device, port, i, &gid, NULL) == 0; i++) {
		union ipx_addr ipx;

		/* don't delete empty entries */
		if (memcmp(&gid, &zgid, sizeof(zgid)) == 0)
			continue;

		/* zero default */
		memset(&ipx, 0, sizeof(ipx));

		rdma_gid2ip(&ipx.sa[0], &gid);

		STAILQ_FOREACH(entry, &ipx_head, entry) {
			if (memcmp(&entry->ipx_addr, &ipx, sizeof(ipx)) == 0)
				break;
		}
		/* check if entry found */
		if (entry != NULL)
			continue;

		/* remove GID */
		update_gid(GID_DEL, device, port, &gid, ndev);
	}

	while ((entry = STAILQ_FIRST(&ipx_head))) {
		STAILQ_REMOVE_HEAD(&ipx_head, entry);
		kfree(entry);
	}
}

static void
roce_gid_queue_scan_event_handler(struct work_struct *_work)
{
	struct roce_netdev_event_work *work =
		container_of(_work, struct roce_netdev_event_work, work);

	ib_enum_all_roce_netdevs(roce_gid_match_netdev, work->ndev,
	    roce_gid_update_addr_callback, NULL);

	dev_put(work->ndev);
	kfree(work);
}

static void
roce_gid_queue_scan_event(struct net_device *ndev)
{
	struct roce_netdev_event_work *work;

retry:
	if (is_eth_ipoib_intf(ndev))
		return;

	if (ndev->if_type != IFT_ETHER) {
		if (ndev->if_type == IFT_L2VLAN) {
			ndev = rdma_vlan_dev_real_dev(ndev);
			if (ndev != NULL)
				goto retry;
		}
		return;
	}

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		pr_warn("roce_gid_mgmt: Couldn't allocate work for addr_event\n");
		return;
	}

	INIT_WORK(&work->work, roce_gid_queue_scan_event_handler);
	dev_hold(ndev);

	work->ndev = ndev;

	queue_work(roce_gid_mgmt_wq, &work->work);
}

static void
roce_gid_delete_all_event_handler(struct work_struct *_work)
{
	struct roce_netdev_event_work *work =
		container_of(_work, struct roce_netdev_event_work, work);

	ib_cache_gid_del_all_by_netdev(work->ndev);
	dev_put(work->ndev);
	kfree(work);
}

static void
roce_gid_delete_all_event(struct net_device *ndev)
{
	struct roce_netdev_event_work *work;

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		pr_warn("roce_gid_mgmt: Couldn't allocate work for addr_event\n");
		return;
	}

	INIT_WORK(&work->work, roce_gid_delete_all_event_handler);
	dev_hold(ndev);
	work->ndev = ndev;
	queue_work(roce_gid_mgmt_wq, &work->work);
}

static int
inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *ndev = ptr;

	switch (event) {
	case NETDEV_UNREGISTER:
		roce_gid_delete_all_event(ndev);
		break;
	case NETDEV_REGISTER:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEIFADDR:
		roce_gid_queue_scan_event(ndev);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block nb_inetaddr = {
	.notifier_call = inetaddr_event
};

static void
roce_rescan_device_handler(struct work_struct *_work)
{
	struct roce_rescan_work *work =
	    container_of(_work, struct roce_rescan_work, work);

	ib_enum_roce_netdev(work->ib_dev, roce_gid_match_all, NULL,
	    roce_gid_update_addr_callback, NULL);
	kfree(work);
}

/* Caller must flush system workqueue before removing the ib_device */
int roce_rescan_device(struct ib_device *ib_dev)
{
	struct roce_rescan_work *work = kmalloc(sizeof(*work), GFP_KERNEL);

	if (!work)
		return -ENOMEM;

	work->ib_dev = ib_dev;
	INIT_WORK(&work->work, roce_rescan_device_handler);
	queue_work(roce_gid_mgmt_wq, &work->work);

	return 0;
}

int __init roce_gid_mgmt_init(void)
{
	roce_gid_mgmt_wq = alloc_ordered_workqueue("roce_gid_mgmt_wq", 0);
	if (!roce_gid_mgmt_wq) {
		pr_warn("roce_gid_mgmt: can't allocate work queue\n");
		return -ENOMEM;
	}

	register_inetaddr_notifier(&nb_inetaddr);

	/*
	 * We rely on the netdevice notifier to enumerate all existing
	 * devices in the system. Register to this notifier last to
	 * make sure we will not miss any IP add/del callbacks.
	 */
	register_netdevice_notifier(&nb_inetaddr);

	return 0;
}

void __exit roce_gid_mgmt_cleanup(void)
{
	unregister_inetaddr_notifier(&nb_inetaddr);
	unregister_netdevice_notifier(&nb_inetaddr);

	/*
	 * Ensure all gid deletion tasks complete before we go down,
	 * to avoid any reference to free'd memory. By the time
	 * ib-core is removed, all physical devices have been removed,
	 * so no issue with remaining hardware contexts.
	 */
	synchronize_rcu();
	drain_workqueue(roce_gid_mgmt_wq);
	destroy_workqueue(roce_gid_mgmt_wq);
}
