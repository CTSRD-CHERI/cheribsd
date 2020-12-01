/*-
 * Copyright (c) 2020 Mellanox Technologies. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS `AS IS' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/devctl.h>
#include <sys/module.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <net/infiniband.h>
#include <net/bpf.h>
#include <net/if_llatbl.h>
#include <net/netisr.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net/if_lagg.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <security/mac/mac_framework.h>

/* if_lagg(4) support */
struct mbuf *(*lagg_input_infiniband_p)(struct ifnet *, struct mbuf *); 

#ifdef INET
static inline void
infiniband_ipv4_multicast_map(uint32_t addr,
    const uint8_t *broadcast, uint8_t *buf)
{
	uint8_t scope;

	addr = ntohl(addr);
	scope = broadcast[5] & 0xF;

	buf[0] = 0;
	buf[1] = 0xff;
	buf[2] = 0xff;
	buf[3] = 0xff;
	buf[4] = 0xff;
	buf[5] = 0x10 | scope;
	buf[6] = 0x40;
	buf[7] = 0x1b;
	buf[8] = broadcast[8];
	buf[9] = broadcast[9];
	buf[10] = 0;
	buf[11] = 0;
	buf[12] = 0;
	buf[13] = 0;
	buf[14] = 0;
	buf[15] = 0;
	buf[16] = (addr >> 24) & 0xff;
	buf[17] = (addr >> 16) & 0xff;
	buf[18] = (addr >> 8) & 0xff;
	buf[19] = addr & 0xff;
}
#endif

#ifdef INET6
static inline void
infiniband_ipv6_multicast_map(const struct in6_addr *addr,
    const uint8_t *broadcast, uint8_t *buf)
{
	uint8_t scope;

	scope = broadcast[5] & 0xF;

	buf[0] = 0;
	buf[1] = 0xff;
	buf[2] = 0xff;
	buf[3] = 0xff;
	buf[4] = 0xff;
	buf[5] = 0x10 | scope;
	buf[6] = 0x60;
	buf[7] = 0x1b;
	buf[8] = broadcast[8];
	buf[9] = broadcast[9];
	memcpy(&buf[10], &addr->s6_addr[6], 10);
}
#endif

/*
 * This is for clients that have an infiniband_header in the mbuf.
 */
void
infiniband_bpf_mtap(struct ifnet *ifp, struct mbuf *mb)
{
	struct infiniband_header *ibh;
	struct ether_header eh;
  
	if (mb->m_len < sizeof(*ibh))
		return;

	ibh = mtod(mb, struct infiniband_header *);
	eh.ether_type = ibh->ib_protocol;
	memset(eh.ether_shost, 0, ETHER_ADDR_LEN);
	memcpy(eh.ether_dhost, ibh->ib_hwaddr + 4, ETHER_ADDR_LEN);
	mb->m_data += sizeof(*ibh);
	mb->m_len -= sizeof(*ibh);
	mb->m_pkthdr.len -= sizeof(*ibh);
	bpf_mtap2(ifp->if_bpf, &eh, sizeof(eh), mb);
	mb->m_data -= sizeof(*ibh);
	mb->m_len += sizeof(*ibh);
	mb->m_pkthdr.len += sizeof(*ibh);
}

/*
 * Infiniband output routine.
 */
static int
infiniband_output(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst,
    struct route *ro)
{
	uint8_t edst[INFINIBAND_ADDR_LEN];
#if defined(INET) || defined(INET6)
	struct llentry *lle = NULL;
#endif
	struct infiniband_header *ibh;
	int error = 0;
	uint16_t type;
	bool is_gw;

	NET_EPOCH_ASSERT();

	is_gw = ((ro != NULL) && (ro->ro_flags & RT_HAS_GW) != 0);

#ifdef MAC
	error = mac_ifnet_check_transmit(ifp, m);
	if (error)
		goto bad;
#endif

	M_PROFILE(m);
	if (ifp->if_flags & IFF_MONITOR) {
		error = ENETDOWN;
		goto bad;
	}
	if (!((ifp->if_flags & IFF_UP) &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING))) {
		error = ENETDOWN;
		goto bad;
	}

	switch (dst->sa_family) {
	case AF_LINK:
		goto output;
#ifdef INET
	case AF_INET:
		if (lle != NULL && (lle->la_flags & LLE_VALID)) {
			memcpy(edst, lle->ll_addr, sizeof(edst));
		} else if (m->m_flags & M_MCAST) {
			infiniband_ipv4_multicast_map(
			    ((const struct sockaddr_in *)dst)->sin_addr.s_addr,
			    ifp->if_broadcastaddr, edst);
		} else {
			error = arpresolve(ifp, is_gw, m, dst, edst, NULL, NULL);
			if (error) {
				if (error == EWOULDBLOCK)
					error = 0;
				m = NULL;	/* mbuf is consumed by resolver */
				goto bad;
			}
		}
		type = htons(ETHERTYPE_IP);
		break;
	case AF_ARP: {
		struct arphdr *ah;

		if (m->m_len < sizeof(*ah)) {
			error = EINVAL;
			goto bad;
		}

		ah = mtod(m, struct arphdr *);

		if (m->m_len < arphdr_len(ah)) {
			error = EINVAL;
			goto bad;
		}
		ah->ar_hrd = htons(ARPHRD_INFINIBAND);

		switch (ntohs(ah->ar_op)) {
		case ARPOP_REVREQUEST:
		case ARPOP_REVREPLY:
			type = htons(ETHERTYPE_REVARP);
			break;
		case ARPOP_REQUEST:
		case ARPOP_REPLY:
		default:
			type = htons(ETHERTYPE_ARP);
			break;
		}

		if (m->m_flags & M_BCAST) {
			memcpy(edst, ifp->if_broadcastaddr, INFINIBAND_ADDR_LEN);
		} else {
			if (ah->ar_hln != INFINIBAND_ADDR_LEN) {
				error = EINVAL;
				goto bad;
			}
			memcpy(edst, ar_tha(ah), INFINIBAND_ADDR_LEN);
		}
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		const struct ip6_hdr *ip6;

		ip6 = mtod(m, const struct ip6_hdr *);
		if (m->m_len < sizeof(*ip6)) {
			error = EINVAL;
			goto bad;
		} else if (lle != NULL && (lle->la_flags & LLE_VALID)) {
			memcpy(edst, lle->ll_addr, sizeof(edst));
		} else if (m->m_flags & M_MCAST) {
			infiniband_ipv6_multicast_map(
			    &((const struct sockaddr_in6 *)dst)->sin6_addr,
			    ifp->if_broadcastaddr, edst);
		} else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
			memcpy(edst, ifp->if_broadcastaddr, INFINIBAND_ADDR_LEN);
		} else {
			error = nd6_resolve(ifp, is_gw, m, dst, edst, NULL, NULL);
			if (error) {
				if (error == EWOULDBLOCK)
					error = 0;
				m = NULL;	/* mbuf is consumed by resolver */
				goto bad;
			}
		}
		type = htons(ETHERTYPE_IPV6);
		break;
	}
#endif
	default:
		error = EAFNOSUPPORT;
		goto bad;
	}

	/*
	 * Add local net header.  If no space in first mbuf,
	 * allocate another.
	 */
	M_PREPEND(m, INFINIBAND_HDR_LEN, M_NOWAIT);
	if (m == NULL) {
		error = ENOBUFS;
		goto bad;
	}
	ibh = mtod(m, struct infiniband_header *);

	ibh->ib_protocol = type;
	memcpy(ibh->ib_hwaddr, edst, sizeof(edst));

	/*
	 * Queue message on interface, update output statistics if
	 * successful, and start output if interface not yet active.
	 */
output:
	return (ifp->if_transmit(ifp, m));
bad:
	if (m != NULL)
		m_freem(m);
	return (error);
}

/*
 * Process a received Infiniband packet.
 */
static void
infiniband_input(struct ifnet *ifp, struct mbuf *m)
{
	struct infiniband_header *ibh;
	struct epoch_tracker et;
	int isr;

	CURVNET_SET_QUIET(ifp->if_vnet);

	if ((ifp->if_flags & IFF_UP) == 0) {
		if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
		m_freem(m);
		goto done;
	}

	ibh = mtod(m, struct infiniband_header *);

	/*
	 * Reset layer specific mbuf flags to avoid confusing upper
	 * layers:
	 */
	m->m_flags &= ~M_VLANTAG;
	m_clrprotoflags(m);

	if (INFINIBAND_IS_MULTICAST(ibh->ib_hwaddr)) {
		if (memcmp(ibh->ib_hwaddr, ifp->if_broadcastaddr,
		    ifp->if_addrlen) == 0)
			m->m_flags |= M_BCAST;
		else
			m->m_flags |= M_MCAST;
		if_inc_counter(ifp, IFCOUNTER_IMCASTS, 1);
	}

	/* Let BPF have it before we strip the header. */
	INFINIBAND_BPF_MTAP(ifp, m);

	/* Allow monitor mode to claim this frame, after stats are updated. */
	if (ifp->if_flags & IFF_MONITOR) {
		m_freem(m);
		goto done;
	}

	/* Direct packet to correct FIB based on interface config. */
	M_SETFIB(m, ifp->if_fib);

	/* Handle input from a lagg<N> port */
	if (ifp->if_type == IFT_INFINIBANDLAG) {
		KASSERT(lagg_input_infiniband_p != NULL,
		    ("%s: if_lagg not loaded!", __func__));
		m = (*lagg_input_infiniband_p)(ifp, m);
		if (__predict_false(m == NULL))
			goto done;
		ifp = m->m_pkthdr.rcvif;
	}

	/*
	 * Dispatch frame to upper layer.
	 */
	switch (ibh->ib_protocol) {
#ifdef INET
	case htons(ETHERTYPE_IP):
		isr = NETISR_IP;
		break;

	case htons(ETHERTYPE_ARP):
		if (ifp->if_flags & IFF_NOARP) {
			/* Discard packet if ARP is disabled on interface */
			m_freem(m);
			goto done;
		}
		isr = NETISR_ARP;
		break;
#endif
#ifdef INET6
	case htons(ETHERTYPE_IPV6):
		isr = NETISR_IPV6;
		break;
#endif
	default:
		if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
		m_freem(m);
		goto done;
	}

	/* Strip off the Infiniband header. */
	m_adj(m, INFINIBAND_HDR_LEN);

#ifdef MAC
	/*
	 * Tag the mbuf with an appropriate MAC label before any other
	 * consumers can get to it.
	 */
	mac_ifnet_create_mbuf(ifp, m);
#endif
	/* Allow monitor mode to claim this frame, after stats are updated. */
	NET_EPOCH_ENTER(et);
	netisr_dispatch(isr, m);
	NET_EPOCH_EXIT(et);
done:
	CURVNET_RESTORE();
}

static int
infiniband_resolvemulti(struct ifnet *ifp, struct sockaddr **llsa,
    struct sockaddr *sa)
{
	struct sockaddr_dl *sdl;
#ifdef INET
	struct sockaddr_in *sin;
#endif
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif
	uint8_t *e_addr;

	switch (sa->sa_family) {
	case AF_LINK:
		/*
		 * No mapping needed. Just check that it's a valid MC address.
		 */
		sdl = (struct sockaddr_dl *)sa;
		e_addr = LLADDR(sdl);
		if (!INFINIBAND_IS_MULTICAST(e_addr))
			return (EADDRNOTAVAIL);
		*llsa = NULL;
		return 0;

#ifdef INET
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
		if (!IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			return (EADDRNOTAVAIL);
		sdl = link_init_sdl(ifp, *llsa, IFT_INFINIBAND);
		sdl->sdl_alen = INFINIBAND_ADDR_LEN;
		e_addr = LLADDR(sdl);
		infiniband_ipv4_multicast_map(sin->sin_addr.s_addr, ifp->if_broadcastaddr,
		    e_addr);
		*llsa = (struct sockaddr *)sdl;
		return (0);
#endif
#ifdef INET6
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sa;
		/*
		 * An IP6 address of 0 means listen to all of the
		 * multicast address used for IP6. This has no meaning
		 * in infiniband.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			return (EADDRNOTAVAIL);
		if (!IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			return (EADDRNOTAVAIL);
		sdl = link_init_sdl(ifp, *llsa, IFT_INFINIBAND);
		sdl->sdl_alen = INFINIBAND_ADDR_LEN;
		e_addr = LLADDR(sdl);
		infiniband_ipv6_multicast_map(&sin6->sin6_addr, ifp->if_broadcastaddr, e_addr);
		*llsa = (struct sockaddr *)sdl;
		return (0);
#endif
	default:
		return (EAFNOSUPPORT);
	}
}

void
infiniband_ifattach(struct ifnet *ifp, const uint8_t *lla, const uint8_t *llb)
{
	struct sockaddr_dl *sdl;
	struct ifaddr *ifa;
	int i;

	ifp->if_addrlen = INFINIBAND_ADDR_LEN;
	ifp->if_hdrlen = INFINIBAND_HDR_LEN;
	ifp->if_mtu = INFINIBAND_MTU;
	if_attach(ifp);
	ifp->if_output = infiniband_output;
	ifp->if_input = infiniband_input;
	ifp->if_resolvemulti = infiniband_resolvemulti;

	if (ifp->if_baudrate == 0)
		ifp->if_baudrate = IF_Gbps(10);	/* default value */
	if (llb != NULL)
		ifp->if_broadcastaddr = llb;

	ifa = ifp->if_addr;
	KASSERT(ifa != NULL, ("%s: no lladdr!\n", __func__));
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_INFINIBAND;
	sdl->sdl_alen = ifp->if_addrlen;

	if (lla != NULL) {
		memcpy(LLADDR(sdl), lla, ifp->if_addrlen);

		if (ifp->if_hw_addr != NULL)
			memcpy(ifp->if_hw_addr, lla, ifp->if_addrlen);
	} else {
		lla = LLADDR(sdl);
	}

	/* Attach ethernet compatible network device */
	bpfattach(ifp, DLT_EN10MB, ETHER_HDR_LEN);

	/* Announce Infiniband MAC address if non-zero. */
	for (i = 0; i < ifp->if_addrlen; i++)
		if (lla[i] != 0)
			break;
	if (i != ifp->if_addrlen)
		if_printf(ifp, "Infiniband address: %20D\n", lla, ":");

	/* Add necessary bits are setup; announce it now. */
	EVENTHANDLER_INVOKE(infiniband_ifattach_event, ifp);

	if (IS_DEFAULT_VNET(curvnet))
		devctl_notify("INFINIBAND", ifp->if_xname, "IFATTACH", NULL);
}

/*
 * Perform common duties while detaching an Infiniband interface
 */
void
infiniband_ifdetach(struct ifnet *ifp)
{
	bpfdetach(ifp);
	if_detach(ifp);
}

static int
infiniband_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
	case MOD_UNLOAD:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t infiniband_mod = {
	.name = "if_infiniband",
	.evhand = &infiniband_modevent,
};

DECLARE_MODULE(if_infiniband, infiniband_mod, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(if_infiniband, 1);
