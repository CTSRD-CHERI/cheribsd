/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1988, 1993
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
 * 3. Neither the name of the University nor the names of its contributors
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_sctp.h"
#ifndef INET
#error "IPDIVERT requires INET"
#endif

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <net/vnet.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#ifdef SCTP
#include <netinet/sctp_crc32.h>
#endif

#include <security/mac/mac_framework.h>
/*
 * Divert sockets
 */

/*
 * Allocate enough space to hold a full IP packet
 */
#define	DIVSNDQ		(65536 + 100)
#define	DIVRCVQ		(65536 + 100)

/*
 * Divert sockets work in conjunction with ipfw or other packet filters,
 * see the divert(4) manpage for features.
 * Packets are selected by the packet filter and tagged with an
 * MTAG_IPFW_RULE tag carrying the 'divert port' number (as set by
 * the packet filter) and information on the matching filter rule for
 * subsequent reinjection. The divert_port is used to put the packet
 * on the corresponding divert socket, while the rule number is passed
 * up (at least partially) as the sin_port in the struct sockaddr.
 *
 * Packets written to the divert socket carry in sin_addr a
 * destination address, and in sin_port the number of the filter rule
 * after which to continue processing.
 * If the destination address is INADDR_ANY, the packet is treated as
 * as outgoing and sent to ip_output(); otherwise it is treated as
 * incoming and sent to ip_input().
 * Further, sin_zero carries some information on the interface,
 * which can be used in the reinject -- see comments in the code.
 *
 * On reinjection, processing in ip_input() and ip_output()
 * will be exactly the same as for the original packet, except that
 * packet filter processing will start at the rule number after the one
 * written in the sin_port (ipfw does not allow a rule #0, so sin_port=0
 * will apply the entire ruleset to the packet).
 */

/* Internal variables. */
VNET_DEFINE_STATIC(struct inpcbhead, divcb);
VNET_DEFINE_STATIC(struct inpcbinfo, divcbinfo);

#define	V_divcb				VNET(divcb)
#define	V_divcbinfo			VNET(divcbinfo)

static u_long	div_sendspace = DIVSNDQ;	/* XXX sysctl ? */
static u_long	div_recvspace = DIVRCVQ;	/* XXX sysctl ? */

static eventhandler_tag ip_divert_event_tag;

static int div_output_inbound(int fmaily, struct socket *so, struct mbuf *m,
    struct sockaddr_in *sin);
static int div_output_outbound(int family, struct socket *so, struct mbuf *m);

/*
 * Initialize divert connection block queue.
 */
static void
div_zone_change(void *tag)
{

	uma_zone_set_max(V_divcbinfo.ipi_zone, maxsockets);
}

static int
div_inpcb_init(void *mem, int size, int flags)
{
	struct inpcb *inp = mem;

	INP_LOCK_INIT(inp, "inp", "divinp");
	return (0);
}

static void
div_init(void)
{

	/*
	 * XXX We don't use the hash list for divert IP, but it's easier to
	 * allocate one-entry hash lists than it is to check all over the
	 * place for hashbase == NULL.
	 */
	in_pcbinfo_init(&V_divcbinfo, "div", &V_divcb, 1, 1, "divcb",
	    div_inpcb_init, IPI_HASHFIELDS_NONE);
}

static void
div_destroy(void *unused __unused)
{

	in_pcbinfo_destroy(&V_divcbinfo);
}
VNET_SYSUNINIT(divert, SI_SUB_PROTO_DOMAININIT, SI_ORDER_ANY,
    div_destroy, NULL);

/*
 * IPPROTO_DIVERT is not in the real IP protocol number space; this
 * function should never be called.  Just in case, drop any packets.
 */
static int
div_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp;

	KMOD_IPSTAT_INC(ips_noproto);
	m_freem(m);
	return (IPPROTO_DONE);
}

/*
 * Divert a packet by passing it up to the divert socket at port 'port'.
 *
 * Setup generic address and protocol structures for div_input routine,
 * then pass them along with mbuf chain.
 */
static void
divert_packet(struct mbuf *m, bool incoming)
{
	struct ip *ip;
	struct inpcb *inp;
	struct socket *sa;
	u_int16_t nport;
	struct sockaddr_in divsrc;
	struct m_tag *mtag;

	NET_EPOCH_ASSERT();

	mtag = m_tag_locate(m, MTAG_IPFW_RULE, 0, NULL);
	if (mtag == NULL) {
		m_freem(m);
		return;
	}
	/* Assure header */
	if (m->m_len < sizeof(struct ip) &&
	    (m = m_pullup(m, sizeof(struct ip))) == NULL)
		return;
	ip = mtod(m, struct ip *);

	/* Delayed checksums are currently not compatible with divert. */
	if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
		in_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	}
#ifdef SCTP
	if (m->m_pkthdr.csum_flags & CSUM_SCTP) {
		sctp_delayed_cksum(m, (uint32_t)(ip->ip_hl << 2));
		m->m_pkthdr.csum_flags &= ~CSUM_SCTP;
	}
#endif
	bzero(&divsrc, sizeof(divsrc));
	divsrc.sin_len = sizeof(divsrc);
	divsrc.sin_family = AF_INET;
	/* record matching rule, in host format */
	divsrc.sin_port = ((struct ipfw_rule_ref *)(mtag+1))->rulenum;
	/*
	 * Record receive interface address, if any.
	 * But only for incoming packets.
	 */
	if (incoming) {
		struct ifaddr *ifa;
		struct ifnet *ifp;

		/* Sanity check */
		M_ASSERTPKTHDR(m);

		/* Find IP address for receive interface */
		ifp = m->m_pkthdr.rcvif;
		CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			divsrc.sin_addr =
			    ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
			break;
		}
	}
	/*
	 * Record the incoming interface name whenever we have one.
	 */
	if (m->m_pkthdr.rcvif) {
		/*
		 * Hide the actual interface name in there in the
		 * sin_zero array. XXX This needs to be moved to a
		 * different sockaddr type for divert, e.g.
		 * sockaddr_div with multiple fields like
		 * sockaddr_dl. Presently we have only 7 bytes
		 * but that will do for now as most interfaces
		 * are 4 or less + 2 or less bytes for unit.
		 * There is probably a faster way of doing this,
		 * possibly taking it from the sockaddr_dl on the iface.
		 * This solves the problem of a P2P link and a LAN interface
		 * having the same address, which can result in the wrong
		 * interface being assigned to the packet when fed back
		 * into the divert socket. Theoretically if the daemon saves
		 * and re-uses the sockaddr_in as suggested in the man pages,
		 * this iface name will come along for the ride.
		 * (see div_output for the other half of this.)
		 */
		strlcpy(divsrc.sin_zero, m->m_pkthdr.rcvif->if_xname,
		    sizeof(divsrc.sin_zero));
	}

	/* Put packet on socket queue, if any */
	sa = NULL;
	nport = htons((u_int16_t)(((struct ipfw_rule_ref *)(mtag+1))->info));
	CK_LIST_FOREACH(inp, &V_divcb, inp_list) {
		/* XXX why does only one socket match? */
		if (inp->inp_lport == nport) {
			INP_RLOCK(inp);
			sa = inp->inp_socket;
			SOCKBUF_LOCK(&sa->so_rcv);
			if (sbappendaddr_locked(&sa->so_rcv,
			    (struct sockaddr *)&divsrc, m,
			    (struct mbuf *)0) == 0) {
				SOCKBUF_UNLOCK(&sa->so_rcv);
				sa = NULL;	/* force mbuf reclaim below */
			} else
				sorwakeup_locked(sa);
			INP_RUNLOCK(inp);
			break;
		}
	}
	if (sa == NULL) {
		m_freem(m);
		KMOD_IPSTAT_INC(ips_noproto);
		KMOD_IPSTAT_DEC(ips_delivered);
        }
}

/*
 * Deliver packet back into the IP processing machinery.
 *
 * If no address specified, or address is 0.0.0.0, send to ip_output();
 * otherwise, send to ip_input() and mark as having been received on
 * the interface with that address.
 */
static int
div_output(struct socket *so, struct mbuf *m, struct sockaddr_in *sin,
    struct mbuf *control)
{
	struct epoch_tracker et;
	const struct ip *ip;
	struct m_tag *mtag;
	struct ipfw_rule_ref *dt;
	int error, family;

	/*
	 * An mbuf may hasn't come from userland, but we pretend
	 * that it has.
	 */
	m->m_pkthdr.rcvif = NULL;
	m->m_nextpkt = NULL;
	M_SETFIB(m, so->so_fibnum);

	if (control)
		m_freem(control);		/* XXX */

	mtag = m_tag_locate(m, MTAG_IPFW_RULE, 0, NULL);
	if (mtag == NULL) {
		/* this should be normal */
		mtag = m_tag_alloc(MTAG_IPFW_RULE, 0,
		    sizeof(struct ipfw_rule_ref), M_NOWAIT | M_ZERO);
		if (mtag == NULL) {
			m_freem(m);
			return (ENOBUFS);
		}
		m_tag_prepend(m, mtag);
	}
	dt = (struct ipfw_rule_ref *)(mtag+1);

	/* Loopback avoidance and state recovery */
	if (sin) {
		int i;

		/* set the starting point. We provide a non-zero slot,
		 * but a non_matching chain_id to skip that info and use
		 * the rulenum/rule_id.
		 */
		dt->slot = 1; /* dummy, chain_id is invalid */
		dt->chain_id = 0;
		dt->rulenum = sin->sin_port+1; /* host format ? */
		dt->rule_id = 0;
		/* XXX: broken for IPv6 */
		/*
		 * Find receive interface with the given name, stuffed
		 * (if it exists) in the sin_zero[] field.
		 * The name is user supplied data so don't trust its size
		 * or that it is zero terminated.
		 */
		for (i = 0; i < sizeof(sin->sin_zero) && sin->sin_zero[i]; i++)
			;
		if ( i > 0 && i < sizeof(sin->sin_zero))
			m->m_pkthdr.rcvif = ifunit(sin->sin_zero);
	}

	ip = mtod(m, struct ip *);
	switch (ip->ip_v) {
	case IPVERSION:
		family = AF_INET;
		break;
#ifdef INET6
	case IPV6_VERSION >> 4:
		family = AF_INET6;
		break;
#endif
	default:
		m_freem(m);
		return (EAFNOSUPPORT);
	}

	/* Reinject packet into the system as incoming or outgoing */
	NET_EPOCH_ENTER(et);
	if (!sin || sin->sin_addr.s_addr == 0) {
		dt->info |= IPFW_IS_DIVERT | IPFW_INFO_OUT;
		error = div_output_outbound(family, so, m);
	} else {
		dt->info |= IPFW_IS_DIVERT | IPFW_INFO_IN;
		error = div_output_inbound(family, so, m, sin);
	}
	NET_EPOCH_EXIT(et);

	if (error != 0)
		m_freem(m);

	return (error);
}

/*
 * Sends mbuf @m to the wire via ip[6]_output().
 *
 * Returns 0 on success, @m is consumed.
 * On failure, returns error code. It is caller responsibility to free @m.
 */
static int
div_output_outbound(int family, struct socket *so, struct mbuf *m)
{
	struct ip *const ip = mtod(m, struct ip *);
	struct mbuf *options;
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	INP_RLOCK(inp);
	switch (family) {
	case AF_INET:
		/*
		 * Don't allow both user specified and setsockopt
		 * options, and don't allow packet length sizes that
		 * will crash.
		 */
		if ((((ip->ip_hl << 2) != sizeof(struct ip)) &&
		    inp->inp_options != NULL) ||
		    ((u_short)ntohs(ip->ip_len) > m->m_pkthdr.len)) {
			INP_RUNLOCK(inp);
			return (EINVAL);
		}
		break;
#ifdef INET6
	case AF_INET6:
	    {
		struct ip6_hdr *const ip6 = mtod(m, struct ip6_hdr *);

		/* Don't allow packet length sizes that will crash */
		if (((u_short)ntohs(ip6->ip6_plen) > m->m_pkthdr.len)) {
			INP_RUNLOCK(inp);
			return (EINVAL);
		}
		break;
	    }
#endif
	}

	/* Send packet to output processing */
	KMOD_IPSTAT_INC(ips_rawout);		/* XXX */

#ifdef MAC
	mac_inpcb_create_mbuf(inp, m);
#endif
	/*
	 * Get ready to inject the packet into ip_output().
	 * Just in case socket options were specified on the
	 * divert socket, we duplicate them.  This is done
	 * to avoid having to hold the PCB locks over the call
	 * to ip_output(), as doing this results in a number of
	 * lock ordering complexities.
	 *
	 * Note that we set the multicast options argument for
	 * ip_output() to NULL since it should be invariant that
	 * they are not present.
	 */
	KASSERT(inp->inp_moptions == NULL,
	    ("multicast options set on a divert socket"));
	/*
	 * XXXCSJP: It is unclear to me whether or not it makes
	 * sense for divert sockets to have options.  However,
	 * for now we will duplicate them with the INP locks
	 * held so we can use them in ip_output() without
	 * requring a reference to the pcb.
	 */
	options = NULL;
	if (inp->inp_options != NULL) {
		options = m_dup(inp->inp_options, M_NOWAIT);
		if (options == NULL) {
			INP_RUNLOCK(inp);
			return (ENOBUFS);
		}
	}
	INP_RUNLOCK(inp);

	error = 0;
	switch (family) {
	case AF_INET:
		error = ip_output(m, options, NULL,
		    ((so->so_options & SO_DONTROUTE) ? IP_ROUTETOIF : 0)
		    | IP_ALLOWBROADCAST | IP_RAWOUTPUT, NULL, NULL);
		break;
#ifdef INET6
	case AF_INET6:
		error = ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
		break;
#endif
	}
	if (options != NULL)
		m_freem(options);

	return (error);
}

/*
 * Schedules mbuf @m for local processing via IPv4/IPv6 netisr queue.
 *
 * Returns 0 on success, @m is consumed.
 * Returns error code on failure. It is caller responsibility to free @m.
 */
static int
div_output_inbound(int family, struct socket *so, struct mbuf *m,
    struct sockaddr_in *sin)
{
	const struct ip *ip;
	struct ifaddr *ifa;

	if (m->m_pkthdr.rcvif == NULL) {
		/*
		 * No luck with the name, check by IP address.
		 * Clear the port and the ifname to make sure
		 * there are no distractions for ifa_ifwithaddr.
		 */

		/* XXX: broken for IPv6 */
		bzero(sin->sin_zero, sizeof(sin->sin_zero));
		sin->sin_port = 0;
		ifa = ifa_ifwithaddr((struct sockaddr *) sin);
		if (ifa == NULL)
			return (EADDRNOTAVAIL);
		m->m_pkthdr.rcvif = ifa->ifa_ifp;
	}
#ifdef MAC
	mac_socket_create_mbuf(so, m);
#endif
	/* Send packet to input processing via netisr */
	switch (family) {
	case AF_INET:
		ip = mtod(m, struct ip *);
		/*
		 * Restore M_BCAST flag when destination address is
		 * broadcast. It is expected by ip_tryforward().
		 */
		if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)))
			m->m_flags |= M_MCAST;
		else if (in_broadcast(ip->ip_dst, m->m_pkthdr.rcvif))
			m->m_flags |= M_BCAST;
		netisr_queue_src(NETISR_IP, (uintptr_t)so, m);
		break;
#ifdef INET6
	case AF_INET6:
		netisr_queue_src(NETISR_IPV6, (uintptr_t)so, m);
		break;
#endif
	default:
		return (EINVAL);
	}

	return (0);
}

static int
div_attach(struct socket *so, int proto, struct thread *td)
{
	struct inpcb *inp;
	int error;

	inp  = sotoinpcb(so);
	KASSERT(inp == NULL, ("div_attach: inp != NULL"));
	if (td != NULL) {
		error = priv_check(td, PRIV_NETINET_DIVERT);
		if (error)
			return (error);
	}
	error = soreserve(so, div_sendspace, div_recvspace);
	if (error)
		return error;
	INP_INFO_WLOCK(&V_divcbinfo);
	error = in_pcballoc(so, &V_divcbinfo);
	if (error) {
		INP_INFO_WUNLOCK(&V_divcbinfo);
		return error;
	}
	inp = (struct inpcb *)so->so_pcb;
	INP_INFO_WUNLOCK(&V_divcbinfo);
	inp->inp_ip_p = proto;
	inp->inp_vflag |= INP_IPV4;
	inp->inp_flags |= INP_HDRINCL;
	INP_WUNLOCK(inp);
	return 0;
}

static void
div_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("div_detach: inp == NULL"));
	INP_INFO_WLOCK(&V_divcbinfo);
	INP_WLOCK(inp);
	in_pcbdetach(inp);
	in_pcbfree(inp);
	INP_INFO_WUNLOCK(&V_divcbinfo);
}

static int
div_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("div_bind: inp == NULL"));
	/* in_pcbbind assumes that nam is a sockaddr_in
	 * and in_pcbbind requires a valid address. Since divert
	 * sockets don't we need to make sure the address is
	 * filled in properly.
	 * XXX -- divert should not be abusing in_pcbind
	 * and should probably have its own family.
	 */
	if (nam->sa_family != AF_INET)
		return EAFNOSUPPORT;
	((struct sockaddr_in *)nam)->sin_addr.s_addr = INADDR_ANY;
	INP_INFO_WLOCK(&V_divcbinfo);
	INP_WLOCK(inp);
	INP_HASH_WLOCK(&V_divcbinfo);
	error = in_pcbbind(inp, nam, td->td_ucred);
	INP_HASH_WUNLOCK(&V_divcbinfo);
	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_divcbinfo);
	return error;
}

static int
div_shutdown(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("div_shutdown: inp == NULL"));
	INP_WLOCK(inp);
	socantsendmore(so);
	INP_WUNLOCK(inp);
	return 0;
}

static int
div_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
    struct mbuf *control, struct thread *td)
{

	/* Packet must have a header (but that's about it) */
	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == NULL) {
		KMOD_IPSTAT_INC(ips_toosmall);
		m_freem(m);
		return EINVAL;
	}

	/* Send packet */
	return div_output(so, m, (struct sockaddr_in *)nam, control);
}

static void
div_ctlinput(int cmd, struct sockaddr *sa, void *vip)
{
        struct in_addr faddr;

	faddr = ((struct sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
        	return;
	if (PRC_IS_REDIRECT(cmd))
		return;
}

static int
div_pcblist(SYSCTL_HANDLER_ARGS)
{
	struct xinpgen xig;
	struct epoch_tracker et;
	struct inpcb *inp;
	int error;

	if (req->newptr != 0)
		return EPERM;

	if (req->oldptr == 0) {
		int n;

		n = V_divcbinfo.ipi_count;
		n += imax(n / 8, 10);
		req->oldidx = 2 * (sizeof xig) + n * sizeof(struct xinpcb);
		return 0;
	}

	if ((error = sysctl_wire_old_buffer(req, 0)) != 0)
		return (error);

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof xig;
	xig.xig_count = V_divcbinfo.ipi_count;
	xig.xig_gen = V_divcbinfo.ipi_gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error)
		return error;

	NET_EPOCH_ENTER(et);
	for (inp = CK_LIST_FIRST(V_divcbinfo.ipi_listhead);
	    inp != NULL;
	    inp = CK_LIST_NEXT(inp, inp_list)) {
		INP_RLOCK(inp);
		if (inp->inp_gencnt <= xig.xig_gen) {
			struct xinpcb xi;

			in_pcbtoxinpcb(inp, &xi);
			INP_RUNLOCK(inp);
			error = SYSCTL_OUT(req, &xi, sizeof xi);
		} else
			INP_RUNLOCK(inp);
	}
	NET_EPOCH_EXIT(et);

	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		xig.xig_gen = V_divcbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = V_divcbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}

	return (error);
}

#ifdef SYSCTL_NODE
static SYSCTL_NODE(_net_inet, IPPROTO_DIVERT, divert,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "IPDIVERT");
SYSCTL_PROC(_net_inet_divert, OID_AUTO, pcblist,
   CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, 0, div_pcblist, "S,xinpcb",
    "List of active divert sockets");
#endif

struct pr_usrreqs div_usrreqs = {
	.pru_attach =		div_attach,
	.pru_bind =		div_bind,
	.pru_control =		in_control,
	.pru_detach =		div_detach,
	.pru_peeraddr =		in_getpeeraddr,
	.pru_send =		div_send,
	.pru_shutdown =		div_shutdown,
	.pru_sockaddr =		in_getsockaddr,
	.pru_sosetlabel =	in_pcbsosetlabel
};

struct protosw div_protosw = {
	.pr_type =		SOCK_RAW,
	.pr_protocol =		IPPROTO_DIVERT,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_input =		div_input,
	.pr_ctlinput =		div_ctlinput,
	.pr_ctloutput =		ip_ctloutput,
	.pr_init =		div_init,
	.pr_usrreqs =		&div_usrreqs
};

static int
div_modevent(module_t mod, int type, void *unused)
{
	int err = 0;

	switch (type) {
	case MOD_LOAD:
		/*
		 * Protocol will be initialized by pf_proto_register().
		 * We don't have to register ip_protox because we are not
		 * a true IP protocol that goes over the wire.
		 */
		err = pf_proto_register(PF_INET, &div_protosw);
		if (err != 0)
			return (err);
		ip_divert_ptr = divert_packet;
		ip_divert_event_tag = EVENTHANDLER_REGISTER(maxsockets_change,
		    div_zone_change, NULL, EVENTHANDLER_PRI_ANY);
		break;
	case MOD_QUIESCE:
		/*
		 * IPDIVERT may normally not be unloaded because of the
		 * potential race conditions.  Tell kldunload we can't be
		 * unloaded unless the unload is forced.
		 */
		err = EPERM;
		break;
	case MOD_UNLOAD:
		/*
		 * Forced unload.
		 *
		 * Module ipdivert can only be unloaded if no sockets are
		 * connected.  Maybe this can be changed later to forcefully
		 * disconnect any open sockets.
		 *
		 * XXXRW: Note that there is a slight race here, as a new
		 * socket open request could be spinning on the lock and then
		 * we destroy the lock.
		 */
		INP_INFO_WLOCK(&V_divcbinfo);
		if (V_divcbinfo.ipi_count != 0) {
			err = EBUSY;
			INP_INFO_WUNLOCK(&V_divcbinfo);
			break;
		}
		ip_divert_ptr = NULL;
		err = pf_proto_unregister(PF_INET, IPPROTO_DIVERT, SOCK_RAW);
		INP_INFO_WUNLOCK(&V_divcbinfo);
#ifndef VIMAGE
		div_destroy(NULL);
#endif
		EVENTHANDLER_DEREGISTER(maxsockets_change, ip_divert_event_tag);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t ipdivertmod = {
        "ipdivert",
        div_modevent,
        0
};

DECLARE_MODULE(ipdivert, ipdivertmod, SI_SUB_PROTO_FIREWALL, SI_ORDER_ANY);
MODULE_DEPEND(ipdivert, ipfw, 3, 3, 3);
MODULE_VERSION(ipdivert, 1);
