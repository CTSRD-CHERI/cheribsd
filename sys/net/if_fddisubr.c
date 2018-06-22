/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1995, 1996
 *	Matt Thomas <matt@3am-software.com>.  All rights reserved.
 * Copyright (c) 1982, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 *	from: if_ethersubr.c,v 1.5 1994/12/13 22:31:45 wollman Exp
 * $FreeBSD$
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_llc.h>
#include <net/if_types.h>
#include <net/if_llatbl.h>

#include <net/ethernet.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/fddi.h>

#if defined(INET) || defined(INET6)
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#endif
#ifdef INET6
#include <netinet6/nd6.h>
#endif

#ifdef DECNET
#include <netdnet/dn.h>
#endif

#include <security/mac/mac_framework.h>

static const u_char fddibroadcastaddr[FDDI_ADDR_LEN] =
			{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int fddi_resolvemulti(struct ifnet *, struct sockaddr **,
			      struct sockaddr *);
static int fddi_output(struct ifnet *, struct mbuf *, const struct sockaddr *,
		       struct route *); 
static void fddi_input(struct ifnet *ifp, struct mbuf *m);

#define	senderr(e)	do { error = (e); goto bad; } while (0)

/*
 * FDDI output routine.
 * Encapsulate a packet of type family for the local net.
 * Use trailer local net encapsulation if enough data in first
 * packet leaves a multiple of 512 bytes of data in remainder.
 */
static int
fddi_output(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst,
	struct route *ro)
{
	u_int16_t type;
	int loop_copy = 0, error = 0, hdrcmplt = 0;
 	u_char esrc[FDDI_ADDR_LEN], edst[FDDI_ADDR_LEN];
	struct fddi_header *fh;
#if defined(INET) || defined(INET6)
	int is_gw = 0;
#endif

#ifdef MAC
	error = mac_ifnet_check_transmit(ifp, m);
	if (error)
		senderr(error);
#endif

	if (ifp->if_flags & IFF_MONITOR)
		senderr(ENETDOWN);
	if (!((ifp->if_flags & IFF_UP) &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING)))
		senderr(ENETDOWN);
	getmicrotime(&ifp->if_lastchange);

#if defined(INET) || defined(INET6)
	if (ro != NULL)
		is_gw = (ro->ro_flags & RT_HAS_GW) != 0;
#endif

	switch (dst->sa_family) {
#ifdef INET
	case AF_INET: {
		error = arpresolve(ifp, is_gw, m, dst, edst, NULL, NULL);
		if (error)
			return (error == EWOULDBLOCK ? 0 : error);
		type = htons(ETHERTYPE_IP);
		break;
	}
	case AF_ARP:
	{
		struct arphdr *ah;
		ah = mtod(m, struct arphdr *);
		ah->ar_hrd = htons(ARPHRD_ETHER);

		loop_copy = -1; /* if this is for us, don't do it */

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

		if (m->m_flags & M_BCAST)
			bcopy(ifp->if_broadcastaddr, edst, FDDI_ADDR_LEN);
                else
			bcopy(ar_tha(ah), edst, FDDI_ADDR_LEN);

	}
	break;
#endif /* INET */
#ifdef INET6
	case AF_INET6:
		error = nd6_resolve(ifp, is_gw, m, dst, edst, NULL, NULL);
		if (error)
			return (error == EWOULDBLOCK ? 0 : error);
		type = htons(ETHERTYPE_IPV6);
		break;
#endif /* INET6 */
	case pseudo_AF_HDRCMPLT:
	{
		const struct ether_header *eh;

		hdrcmplt = 1;
		eh = (const struct ether_header *)dst->sa_data;
		bcopy(eh->ether_shost, esrc, FDDI_ADDR_LEN);
		/* FALLTHROUGH */
	}

	case AF_UNSPEC:
	{
		const struct ether_header *eh;

		loop_copy = -1;
		eh = (const struct ether_header *)dst->sa_data;
		bcopy(eh->ether_dhost, edst, FDDI_ADDR_LEN);
		if (*edst & 1)
			m->m_flags |= (M_BCAST|M_MCAST);
		type = eh->ether_type;
		break;
	}

	case AF_IMPLINK:
	{
		fh = mtod(m, struct fddi_header *);
		error = EPROTONOSUPPORT;
		switch (fh->fddi_fc & (FDDIFC_C|FDDIFC_L|FDDIFC_F)) {
			case FDDIFC_LLC_ASYNC: {
				/* legal priorities are 0 through 7 */
				if ((fh->fddi_fc & FDDIFC_Z) > 7)
			        	goto bad;
				break;
			}
			case FDDIFC_LLC_SYNC: {
				/* FDDIFC_Z bits reserved, must be zero */
				if (fh->fddi_fc & FDDIFC_Z)
					goto bad;
				break;
			}
			case FDDIFC_SMT: {
				/* FDDIFC_Z bits must be non zero */
				if ((fh->fddi_fc & FDDIFC_Z) == 0)
					goto bad;
				break;
			}
			default: {
				/* anything else is too dangerous */
               	 		goto bad;
			}
		}
		error = 0;
		if (fh->fddi_dhost[0] & 1)
			m->m_flags |= (M_BCAST|M_MCAST);
		goto queue_it;
	}
	default:
		if_printf(ifp, "can't handle af%d\n", dst->sa_family);
		senderr(EAFNOSUPPORT);
	}

	/*
	 * Add LLC header.
	 */
	if (type != 0) {
		struct llc *l;
		M_PREPEND(m, LLC_SNAPFRAMELEN, M_NOWAIT);
		if (m == NULL)
			senderr(ENOBUFS);
		l = mtod(m, struct llc *);
		l->llc_control = LLC_UI;
		l->llc_dsap = l->llc_ssap = LLC_SNAP_LSAP;
		l->llc_snap.org_code[0] =
			l->llc_snap.org_code[1] =
			l->llc_snap.org_code[2] = 0;
		l->llc_snap.ether_type = htons(type);
	}

	/*
	 * Add local net header.  If no space in first mbuf,
	 * allocate another.
	 */
	M_PREPEND(m, FDDI_HDR_LEN, M_NOWAIT);
	if (m == NULL)
		senderr(ENOBUFS);
	fh = mtod(m, struct fddi_header *);
	fh->fddi_fc = FDDIFC_LLC_ASYNC|FDDIFC_LLC_PRIO4;
	bcopy((caddr_t)edst, (caddr_t)fh->fddi_dhost, FDDI_ADDR_LEN);
  queue_it:
	if (hdrcmplt)
		bcopy((caddr_t)esrc, (caddr_t)fh->fddi_shost, FDDI_ADDR_LEN);
	else
		bcopy(IF_LLADDR(ifp), (caddr_t)fh->fddi_shost,
			FDDI_ADDR_LEN);

	/*
	 * If a simplex interface, and the packet is being sent to our
	 * Ethernet address or a broadcast address, loopback a copy.
	 * XXX To make a simplex device behave exactly like a duplex
	 * device, we should copy in the case of sending to our own
	 * ethernet address (thus letting the original actually appear
	 * on the wire). However, we don't do that here for security
	 * reasons and compatibility with the original behavior.
	 */
	if ((ifp->if_flags & IFF_SIMPLEX) && (loop_copy != -1)) {
		if ((m->m_flags & M_BCAST) || (loop_copy > 0)) {
			struct mbuf *n;
			n = m_copym(m, 0, M_COPYALL, M_NOWAIT);
			(void) if_simloop(ifp, n, dst->sa_family,
					  FDDI_HDR_LEN);
	     	} else if (bcmp(fh->fddi_dhost, fh->fddi_shost,
				FDDI_ADDR_LEN) == 0) {
			(void) if_simloop(ifp, m, dst->sa_family,
					  FDDI_HDR_LEN);
			return (0);	/* XXX */
		}
	}

	error = (ifp->if_transmit)(ifp, m);
	if (error)
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);

	return (error);

bad:
	if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
	if (m)
		m_freem(m);
	return (error);
}

/*
 * Process a received FDDI packet.
 */
static void
fddi_input(ifp, m)
	struct ifnet *ifp;
	struct mbuf *m;
{
	int isr;
	struct llc *l;
	struct fddi_header *fh;

	/*
	 * Do consistency checks to verify assumptions
	 * made by code past this point.
	 */
	if ((m->m_flags & M_PKTHDR) == 0) {
		if_printf(ifp, "discard frame w/o packet header\n");
		if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
		m_freem(m);
		return;
	}
	if (m->m_pkthdr.rcvif == NULL) {
		if_printf(ifp, "discard frame w/o interface pointer\n");
		if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
		m_freem(m);
		return;
        }

	m = m_pullup(m, FDDI_HDR_LEN);
	if (m == NULL) {
		if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
		goto dropanyway;
	}
	fh = mtod(m, struct fddi_header *);

	/*
	 * Discard packet if interface is not up.
	 */
	if (!((ifp->if_flags & IFF_UP) &&
	    (ifp->if_drv_flags & IFF_DRV_RUNNING)))
		goto dropanyway;

	/*
	 * Give bpf a chance at the packet.
	 */
	BPF_MTAP(ifp, m);

	/*
	 * Interface marked for monitoring; discard packet.
	 */
	if (ifp->if_flags & IFF_MONITOR) {
		m_freem(m);
		return;
	}

#ifdef MAC
	mac_ifnet_create_mbuf(ifp, m);
#endif

	/*
	 * Update interface statistics.
	 */
	if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	getmicrotime(&ifp->if_lastchange);

	/*
	 * Discard non local unicast packets when interface
	 * is in promiscuous mode.
	 */
	if ((ifp->if_flags & IFF_PROMISC) && ((fh->fddi_dhost[0] & 1) == 0) &&
	    (bcmp(IF_LLADDR(ifp), (caddr_t)fh->fddi_dhost,
	     FDDI_ADDR_LEN) != 0))
		goto dropanyway;

	/*
	 * Set mbuf flags for bcast/mcast.
	 */
	if (fh->fddi_dhost[0] & 1) {
		if (bcmp(ifp->if_broadcastaddr, fh->fddi_dhost,
		    FDDI_ADDR_LEN) == 0)
			m->m_flags |= M_BCAST;
		else
			m->m_flags |= M_MCAST;
		if_inc_counter(ifp, IFCOUNTER_IMCASTS, 1);
	}

#ifdef M_LINK0
	/*
	 * If this has a LLC priority of 0, then mark it so upper
	 * layers have a hint that it really came via a FDDI/Ethernet
	 * bridge.
	 */
	if ((fh->fddi_fc & FDDIFC_LLC_PRIO7) == FDDIFC_LLC_PRIO0)
		m->m_flags |= M_LINK0;
#endif

	/* Strip off FDDI header. */
	m_adj(m, FDDI_HDR_LEN);

	m = m_pullup(m, LLC_SNAPFRAMELEN);
	if (m == NULL) {
		if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
		goto dropanyway;
	}
	l = mtod(m, struct llc *);

	switch (l->llc_dsap) {
	case LLC_SNAP_LSAP:
	{
		u_int16_t type;
		if ((l->llc_control != LLC_UI) ||
		    (l->llc_ssap != LLC_SNAP_LSAP)) {
			if_inc_counter(ifp, IFCOUNTER_NOPROTO, 1);
			goto dropanyway;
		}
		if (l->llc_snap.org_code[0] != 0 ||
		    l->llc_snap.org_code[1] != 0 ||
		    l->llc_snap.org_code[2] != 0) {
			if_inc_counter(ifp, IFCOUNTER_NOPROTO, 1);
			goto dropanyway;
		}

		type = ntohs(l->llc_snap.ether_type);
		m_adj(m, LLC_SNAPFRAMELEN);

		switch (type) {
#ifdef INET
		case ETHERTYPE_IP:
			isr = NETISR_IP;
			break;

		case ETHERTYPE_ARP:
			if (ifp->if_flags & IFF_NOARP)
				goto dropanyway;
			isr = NETISR_ARP;
			break;
#endif
#ifdef INET6
		case ETHERTYPE_IPV6:
			isr = NETISR_IPV6;
			break;
#endif
#ifdef DECNET
		case ETHERTYPE_DECNET:
			isr = NETISR_DECNET;
			break;
#endif
		default:
			/* printf("fddi_input: unknown protocol 0x%x\n", type); */
			if_inc_counter(ifp, IFCOUNTER_NOPROTO, 1);
			goto dropanyway;
		}
		break;
	}
		
	default:
		/* printf("fddi_input: unknown dsap 0x%x\n", l->llc_dsap); */
		if_inc_counter(ifp, IFCOUNTER_NOPROTO, 1);
		goto dropanyway;
	}
	M_SETFIB(m, ifp->if_fib);
	netisr_dispatch(isr, m);
	return;

dropanyway:
	if_inc_counter(ifp, IFCOUNTER_IQDROPS, 1);
	if (m)
		m_freem(m);
	return;
}

/*
 * Perform common duties while attaching to interface list
 */
void
fddi_ifattach(ifp, lla, bpf)
	struct ifnet *ifp;
	const u_int8_t *lla;
	int bpf;
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;

	ifp->if_type = IFT_FDDI;
	ifp->if_addrlen = FDDI_ADDR_LEN;
	ifp->if_hdrlen = 21;

	if_attach(ifp);         /* Must be called before additional assignments */

	ifp->if_mtu = FDDIMTU;
	ifp->if_output = fddi_output;
	ifp->if_input = fddi_input;
	ifp->if_resolvemulti = fddi_resolvemulti;
	ifp->if_broadcastaddr = fddibroadcastaddr;
	ifp->if_baudrate = 100000000;
#ifdef IFF_NOTRAILERS
	ifp->if_flags |= IFF_NOTRAILERS;
#endif
	ifa = ifp->if_addr;
	KASSERT(ifa != NULL, ("%s: no lladdr!\n", __func__));

	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_FDDI;
	sdl->sdl_alen = ifp->if_addrlen;
	bcopy(lla, LLADDR(sdl), ifp->if_addrlen);

	if (bpf)
		bpfattach(ifp, DLT_FDDI, FDDI_HDR_LEN);

	return;
}

void
fddi_ifdetach(ifp, bpf)
	struct ifnet *ifp;
	int bpf;
{
     
	if (bpf)
		bpfdetach(ifp);

	if_detach(ifp);

	return;
}

int
fddi_ioctl (ifp, command, data)
	struct ifnet *ifp;
	u_long command;
	caddr_t data;
{
	struct ifaddr *ifa;
	struct ifreq *ifr;
	int error;

	ifa = (struct ifaddr *) data;
	ifr = (struct ifreq *) data;
	error = 0;

	switch (command) {
	CASE_IOC_IFREQ(SIOCSIFADDR):
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:	/* before arpwhohas */
			ifp->if_init(ifp->if_softc);
			arp_ifinit(ifp, ifa);
			break;
#endif
		default:
			ifp->if_init(ifp->if_softc);
			break;
		}
		break;
	CASE_IOC_IFREQ(SIOCGIFADDR):
		bcopy(IF_LLADDR(ifp), ifr_addr_get_data(ifr), FDDI_ADDR_LEN);
		break;
	CASE_IOC_IFREQ(SIOCSIFMTU):
		/*
		 * Set the interface MTU.
		 */
		if (ifr_mtu_get(ifr) > FDDIMTU) {
			error = EINVAL;
		} else {
			ifp->if_mtu = ifr_mtu_get(ifr);
		}
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

static int
fddi_resolvemulti(ifp, llsa, sa)
	struct ifnet *ifp;
	struct sockaddr **llsa;
	struct sockaddr *sa;
{
	struct sockaddr_dl *sdl;
#ifdef INET
	struct sockaddr_in *sin;
#endif
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif
	u_char *e_addr;

	switch(sa->sa_family) {
	case AF_LINK:
		/*
		 * No mapping needed. Just check that it's a valid MC address.
		 */
		sdl = (struct sockaddr_dl *)sa;
		e_addr = LLADDR(sdl);
		if ((e_addr[0] & 1) != 1)
			return (EADDRNOTAVAIL);
		*llsa = NULL;
		return (0);

#ifdef INET
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
		if (!IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			return (EADDRNOTAVAIL);
		sdl = link_init_sdl(ifp, *llsa, IFT_FDDI);
		sdl->sdl_nlen = 0;
		sdl->sdl_alen = FDDI_ADDR_LEN;
		sdl->sdl_slen = 0;
		e_addr = LLADDR(sdl);
		ETHER_MAP_IP_MULTICAST(&sin->sin_addr, e_addr);
		*llsa = (struct sockaddr *)sdl;
		return (0);
#endif
#ifdef INET6
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			/*
			 * An IP6 address of 0 means listen to all
			 * of the Ethernet multicast address used for IP6.
			 * (This is used for multicast routers.)
			 */
			ifp->if_flags |= IFF_ALLMULTI;
			*llsa = NULL;
			return (0);
		}
		if (!IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			return (EADDRNOTAVAIL);
		sdl = link_init_sdl(ifp, *llsa, IFT_FDDI);
		sdl->sdl_nlen = 0;
		sdl->sdl_alen = FDDI_ADDR_LEN;
		sdl->sdl_slen = 0;
		e_addr = LLADDR(sdl);
		ETHER_MAP_IPV6_MULTICAST(&sin6->sin6_addr, e_addr);
		*llsa = (struct sockaddr *)sdl;
		return (0);
#endif

	default:
		/*
		 * Well, the text isn't quite right, but it's the name
		 * that counts...
		 */
		return (EAFNOSUPPORT);
	}

	return (0);
}

static moduledata_t fddi_mod = {
	"fddi",	/* module name */
	NULL,	/* event handler */
	0	/* extra data */
};

DECLARE_MODULE(fddi, fddi_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(fddi, 1);
