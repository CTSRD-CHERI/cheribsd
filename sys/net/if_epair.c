/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2008 The FreeBSD Foundation
 * Copyright (c) 2009-2021 Bjoern A. Zeeb <bz@FreeBSD.org>
 *
 * This software was developed by CK Software GmbH under sponsorship
 * from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
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

/*
 * A pair of virtual back-to-back connected ethernet like interfaces
 * (``two interfaces with a virtual cross-over cable'').
 *
 * This is mostly intended to be used to provide connectivity between
 * different virtual network stack instances.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_rss.h"
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/hash.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/taskqueue.h>
#include <sys/types.h>
#include <sys/buf_ring.h>
#include <sys/bus.h>
#include <sys/interrupt.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_media.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/netisr.h>
#ifdef RSS
#include <net/rss_config.h>
#ifdef INET
#include <netinet/in_rss.h>
#endif
#ifdef INET6
#include <netinet6/in6_rss.h>
#endif
#endif
#include <net/vnet.h>

static int epair_clone_match(struct if_clone *, const char *);
static int epair_clone_create(struct if_clone *, char *, size_t,
    void * __capability);
static int epair_clone_destroy(struct if_clone *, struct ifnet *);

static const char epairname[] = "epair";
#define	RXRSIZE	4096	/* Probably overkill by 4-8x. */

static MALLOC_DEFINE(M_EPAIR, epairname,
    "Pair of virtual cross-over connected Ethernet-like interfaces");

VNET_DEFINE_STATIC(struct if_clone *, epair_cloner);
#define	V_epair_cloner	VNET(epair_cloner)

static unsigned int next_index = 0;
#define	EPAIR_LOCK_INIT()		mtx_init(&epair_n_index_mtx, "epairidx", \
					    NULL, MTX_DEF)
#define	EPAIR_LOCK_DESTROY()		mtx_destroy(&epair_n_index_mtx)
#define	EPAIR_LOCK()			mtx_lock(&epair_n_index_mtx)
#define	EPAIR_UNLOCK()			mtx_unlock(&epair_n_index_mtx)

struct epair_softc;
struct epair_queue {
	int			 id;
	struct buf_ring		*rxring[2];
	volatile int		 ridx;		/* 0 || 1 */
	struct task		 tx_task;
	struct epair_softc	*sc;
};

static struct mtx epair_n_index_mtx;
struct epair_softc {
	struct ifnet		*ifp;		/* This ifp. */
	struct ifnet		*oifp;		/* other ifp of pair. */
	int			 num_queues;
	struct epair_queue	*queues;
	struct ifmedia		 media;		/* Media config (fake). */
	STAILQ_ENTRY(epair_softc) entry;
};

struct epair_tasks_t {
	int			 tasks;
	struct taskqueue	 *tq[MAXCPU];
};

static struct epair_tasks_t epair_tasks;

static void
epair_clear_mbuf(struct mbuf *m)
{
	/* Remove any CSUM_SND_TAG as ether_input will barf. */
	if (m->m_pkthdr.csum_flags & CSUM_SND_TAG) {
		m_snd_tag_rele(m->m_pkthdr.snd_tag);
		m->m_pkthdr.snd_tag = NULL;
		m->m_pkthdr.csum_flags &= ~CSUM_SND_TAG;
	}

	m_tag_delete_nonpersistent(m);
}

static void
epair_if_input(struct epair_softc *sc, struct epair_queue *q, int ridx)
{
	struct ifnet *ifp;
	struct mbuf *m;

	ifp = sc->ifp;
	CURVNET_SET(ifp->if_vnet);
	while (! buf_ring_empty(q->rxring[ridx])) {
		m = buf_ring_dequeue_mc(q->rxring[ridx]);
		if (m == NULL)
			continue;

		MPASS((m->m_pkthdr.csum_flags & CSUM_SND_TAG) == 0);
		(*ifp->if_input)(ifp, m);

	}
	CURVNET_RESTORE();
}

static void
epair_tx_start_deferred(void *arg, int pending)
{
	struct epair_queue *q = (struct epair_queue *)arg;
	struct epair_softc *sc = q->sc;
	int ridx, nidx;

	if_ref(sc->ifp);
	ridx = atomic_load_int(&q->ridx);
	do {
		nidx = (ridx == 0) ? 1 : 0;
	} while (!atomic_fcmpset_int(&q->ridx, &ridx, nidx));
	epair_if_input(sc, q, ridx);

	if (! buf_ring_empty(q->rxring[nidx]))
		taskqueue_enqueue(epair_tasks.tq[q->id], &q->tx_task);

	if_rele(sc->ifp);
}

static int
epair_menq(struct mbuf *m, struct epair_softc *osc)
{
	struct ifnet *ifp, *oifp;
	int len, ret;
	int ridx;
	short mflags;
	struct epair_queue *q = NULL;
	uint32_t bucket;
	bool was_empty;
#ifdef RSS
	struct ether_header *eh;
#endif

	/*
	 * I know this looks weird. We pass the "other sc" as we need that one
	 * and can get both ifps from it as well.
	 */
	oifp = osc->ifp;
	ifp = osc->oifp;

	M_ASSERTPKTHDR(m);
	epair_clear_mbuf(m);
	if_setrcvif(m, oifp);
	M_SETFIB(m, oifp->if_fib);

	/* Save values as once the mbuf is queued, it's not ours anymore. */
	len = m->m_pkthdr.len;
	mflags = m->m_flags;

	MPASS(m->m_nextpkt == NULL);
	MPASS((m->m_pkthdr.csum_flags & CSUM_SND_TAG) == 0);

#ifdef RSS
	ret = rss_m2bucket(m, &bucket);
	if (ret) {
		/* Actually hash the packet. */
		eh = mtod(m, struct ether_header *);

		switch (ntohs(eh->ether_type)) {
#ifdef INET
		case ETHERTYPE_IP:
			rss_soft_m2cpuid_v4(m, 0, &bucket);
			break;
#endif
#ifdef INET6
		case ETHERTYPE_IPV6:
			rss_soft_m2cpuid_v6(m, 0, &bucket);
			break;
#endif
		default:
			bucket = 0;
			break;
		}
	}
	bucket %= osc->num_queues;
#else
	bucket = 0;
#endif
	q = &osc->queues[bucket];

	ridx = atomic_load_int(&q->ridx);
	was_empty = buf_ring_empty(q->rxring[ridx]);
	ret = buf_ring_enqueue(q->rxring[ridx], m);
	if (ret != 0) {
		/* Ring is full. */
		if_inc_counter(ifp, IFCOUNTER_OQDROPS, 1);
		m_freem(m);
		goto done;
	}

	if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
	/*
	 * IFQ_HANDOFF_ADJ/ip_handoff() update statistics,
	 * but as we bypass all this we have to duplicate
	 * the logic another time.
	 */
	if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
	if (mflags & (M_BCAST|M_MCAST))
		if_inc_counter(ifp, IFCOUNTER_OMCASTS, 1);
	/* Someone else received the packet. */
	if_inc_counter(oifp, IFCOUNTER_IPACKETS, 1);

done:
	if (was_empty)
		taskqueue_enqueue(epair_tasks.tq[bucket], &q->tx_task);

	return (0);
}

static void
epair_start(struct ifnet *ifp)
{
	struct mbuf *m;
	struct epair_softc *sc;
	struct ifnet *oifp;

	/*
	 * We get packets here from ether_output via if_handoff()
	 * and need to put them into the input queue of the oifp
	 * and will put the packet into the receive-queue (rxq) of the
	 * other interface (oifp) of our pair.
	 */
	sc = ifp->if_softc;
	oifp = sc->oifp;
	sc = oifp->if_softc;
	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;
		M_ASSERTPKTHDR(m);
		BPF_MTAP(ifp, m);

		/* In case either interface is not usable drop the packet. */
		if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0 ||
		    (ifp->if_flags & IFF_UP) == 0 ||
		    (oifp->if_drv_flags & IFF_DRV_RUNNING) == 0 ||
		    (oifp->if_flags & IFF_UP) == 0) {
			m_freem(m);
			continue;
		}

		(void) epair_menq(m, sc);
	}
}

static int
epair_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct epair_softc *sc;
	struct ifnet *oifp;
	int error;
#ifdef ALTQ
	int len;
	short mflags;
#endif

	if (m == NULL)
		return (0);
	M_ASSERTPKTHDR(m);

	/*
	 * We are not going to use the interface en/dequeue mechanism
	 * on the TX side. We are called from ether_output_frame()
	 * and will put the packet into the receive-queue (rxq) of the
	 * other interface (oifp) of our pair.
	 */
	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0) {
		m_freem(m);
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENXIO);
	}
	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENETDOWN);
	}

	BPF_MTAP(ifp, m);

	/*
	 * In case the outgoing interface is not usable,
	 * drop the packet.
	 */
	sc = ifp->if_softc;
	oifp = sc->oifp;
	if ((oifp->if_drv_flags & IFF_DRV_RUNNING) == 0 ||
	    (oifp->if_flags & IFF_UP) == 0) {
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		m_freem(m);
		return (0);
	}

#ifdef ALTQ
	len = m->m_pkthdr.len;
	mflags = m->m_flags;

	/* Support ALTQ via the classic if_start() path. */
	IF_LOCK(&ifp->if_snd);
	if (ALTQ_IS_ENABLED(&ifp->if_snd)) {
		ALTQ_ENQUEUE(&ifp->if_snd, m, NULL, error);
		if (error)
			if_inc_counter(ifp, IFCOUNTER_OQDROPS, 1);
		IF_UNLOCK(&ifp->if_snd);
		if (!error) {
			if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
			if (mflags & (M_BCAST|M_MCAST))
				if_inc_counter(ifp, IFCOUNTER_OMCASTS, 1);
			epair_start(ifp);
		}
		return (error);
	}
	IF_UNLOCK(&ifp->if_snd);
#endif

	error = epair_menq(m, oifp->if_softc);
	return (error);
}

static int
epair_media_change(struct ifnet *ifp __unused)
{

	/* Do nothing. */
	return (0);
}

static void
epair_media_status(struct ifnet *ifp __unused, struct ifmediareq *imr)
{

	imr->ifm_status = IFM_AVALID | IFM_ACTIVE;
	imr->ifm_active = IFM_ETHER | IFM_10G_T | IFM_FDX;
}

static int
epair_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct epair_softc *sc;
	struct ifreq *ifr;
	int error;

	ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCSIFFLAGS:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = 0;
		break;

	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		sc = ifp->if_softc;
		error = ifmedia_ioctl(ifp, ifr, &sc->media, cmd);
		break;

	case SIOCSIFMTU:
		/* We basically allow all kinds of MTUs. */
		ifp->if_mtu = ifr->ifr_mtu;
		error = 0;
		break;

	default:
		/* Let the common ethernet handler process this. */
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}

static void
epair_init(void *dummy __unused)
{
}

/*
 * Interface cloning functions.
 * We use our private ones so that we can create/destroy our secondary
 * device along with the primary one.
 */
static int
epair_clone_match(struct if_clone *ifc, const char *name)
{
	const char *cp;

	/*
	 * Our base name is epair.
	 * Our interfaces will be named epair<n>[ab].
	 * So accept anything of the following list:
	 * - epair
	 * - epair<n>
	 * but not the epair<n>[ab] versions.
	 */
	if (strncmp(epairname, name, sizeof(epairname)-1) != 0)
		return (0);

	for (cp = name + sizeof(epairname) - 1; *cp != '\0'; cp++) {
		if (*cp < '0' || *cp > '9')
			return (0);
	}

	return (1);
}

static void
epair_clone_add(struct if_clone *ifc, struct epair_softc *scb)
{
	struct ifnet *ifp;
	uint8_t eaddr[ETHER_ADDR_LEN];	/* 00:00:00:00:00:00 */

	ifp = scb->ifp;
	/* Copy epairNa etheraddr and change the last byte. */
	memcpy(eaddr, scb->oifp->if_hw_addr, ETHER_ADDR_LEN);
	eaddr[5] = 0x0b;
	ether_ifattach(ifp, eaddr);

	if_clone_addif(ifc, ifp);
}

static int
epair_clone_create(struct if_clone *ifc, char *name, size_t len,
    void * __capability params)
{
	struct epair_softc *sca, *scb;
	struct ifnet *ifp;
	char *dp;
	int error, unit, wildcard;
	uint64_t hostid;
	uint32_t key[3];
	uint32_t hash;
	uint8_t eaddr[ETHER_ADDR_LEN];	/* 00:00:00:00:00:00 */

	/* Try to see if a special unit was requested. */
	error = ifc_name2unit(name, &unit);
	if (error != 0)
		return (error);
	wildcard = (unit < 0);

	error = ifc_alloc_unit(ifc, &unit);
	if (error != 0)
		return (error);

	/*
	 * If no unit had been given, we need to adjust the ifName.
	 * Also make sure there is space for our extra [ab] suffix.
	 */
	for (dp = name; *dp != '\0'; dp++);
	if (wildcard) {
		error = snprintf(dp, len - (dp - name), "%d", unit);
		if (error > len - (dp - name) - 1) {
			/* ifName too long. */
			ifc_free_unit(ifc, unit);
			return (ENOSPC);
		}
		dp += error;
	}
	if (len - (dp - name) - 1 < 1) {
		/* No space left for our [ab] suffix. */
		ifc_free_unit(ifc, unit);
		return (ENOSPC);
	}
	*dp = 'b';
	/* Must not change dp so we can replace 'a' by 'b' later. */
	*(dp+1) = '\0';

	/* Check if 'a' and 'b' interfaces already exist. */ 
	if (ifunit(name) != NULL)
		return (EEXIST);
	*dp = 'a';
	if (ifunit(name) != NULL)
		return (EEXIST);

	/* Allocate memory for both [ab] interfaces */
	sca = malloc(sizeof(struct epair_softc), M_EPAIR, M_WAITOK | M_ZERO);
	sca->ifp = if_alloc(IFT_ETHER);
	sca->num_queues = epair_tasks.tasks;
	if (sca->ifp == NULL) {
		free(sca, M_EPAIR);
		ifc_free_unit(ifc, unit);
		return (ENOSPC);
	}
	sca->queues = mallocarray(sca->num_queues, sizeof(struct epair_queue),
	    M_EPAIR, M_WAITOK);
	for (int i = 0; i < sca->num_queues; i++) {
		struct epair_queue *q = &sca->queues[i];
		q->id = i;
		q->rxring[0] = buf_ring_alloc(RXRSIZE, M_EPAIR, M_WAITOK, NULL);
		q->rxring[1] = buf_ring_alloc(RXRSIZE, M_EPAIR, M_WAITOK, NULL);
		q->ridx = 0;
		q->sc = sca;
		NET_TASK_INIT(&q->tx_task, 0, epair_tx_start_deferred, q);
	}

	scb = malloc(sizeof(struct epair_softc), M_EPAIR, M_WAITOK | M_ZERO);
	scb->ifp = if_alloc(IFT_ETHER);
	scb->num_queues = epair_tasks.tasks;
	if (scb->ifp == NULL) {
		free(scb, M_EPAIR);
		if_free(sca->ifp);
		free(sca, M_EPAIR);
		ifc_free_unit(ifc, unit);
		return (ENOSPC);
	}
	scb->queues = mallocarray(scb->num_queues, sizeof(struct epair_queue),
	    M_EPAIR, M_WAITOK);
	for (int i = 0; i < scb->num_queues; i++) {
		struct epair_queue *q = &scb->queues[i];
		q->id = i;
		q->rxring[0] = buf_ring_alloc(RXRSIZE, M_EPAIR, M_WAITOK, NULL);
		q->rxring[1] = buf_ring_alloc(RXRSIZE, M_EPAIR, M_WAITOK, NULL);
		q->ridx = 0;
		q->sc = scb;
		NET_TASK_INIT(&q->tx_task, 0, epair_tx_start_deferred, q);
	}

	/*
	 * Cross-reference the interfaces so we will be able to free both.
	 */
	sca->oifp = scb->ifp;
	scb->oifp = sca->ifp;

	EPAIR_LOCK();
#ifdef SMP
	/* Get an approximate distribution. */
	hash = next_index % mp_ncpus;
#else
	hash = 0;
#endif
	EPAIR_UNLOCK();

	/* Initialise pseudo media types. */
	ifmedia_init(&sca->media, 0, epair_media_change, epair_media_status);
	ifmedia_add(&sca->media, IFM_ETHER | IFM_10G_T, 0, NULL);
	ifmedia_set(&sca->media, IFM_ETHER | IFM_10G_T);
	ifmedia_init(&scb->media, 0, epair_media_change, epair_media_status);
	ifmedia_add(&scb->media, IFM_ETHER | IFM_10G_T, 0, NULL);
	ifmedia_set(&scb->media, IFM_ETHER | IFM_10G_T);

	/* Finish initialization of interface <n>a. */
	ifp = sca->ifp;
	ifp->if_softc = sca;
	strlcpy(ifp->if_xname, name, IFNAMSIZ);
	ifp->if_dname = epairname;
	ifp->if_dunit = unit;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_flags |= IFF_KNOWSEPOCH;
	ifp->if_capabilities = IFCAP_VLAN_MTU;
	ifp->if_capenable = IFCAP_VLAN_MTU;
	ifp->if_start = epair_start;
	ifp->if_ioctl = epair_ioctl;
	ifp->if_init  = epair_init;
	if_setsendqlen(ifp, ifqmaxlen);
	if_setsendqready(ifp);

	/*
	 * Calculate the etheraddr hashing the hostid and the
	 * interface index. The result would be hopefully unique.
	 * Note that the "a" component of an epair instance may get moved
	 * to a different VNET after creation. In that case its index
	 * will be freed and the index can get reused by new epair instance.
	 * Make sure we do not create same etheraddr again.
	 */
	getcredhostid(curthread->td_ucred, (unsigned long *)&hostid);
	if (hostid == 0) 
		arc4rand(&hostid, sizeof(hostid), 0);

	EPAIR_LOCK();
	if (ifp->if_index > next_index)
		next_index = ifp->if_index;
	else
		next_index++;

	key[0] = (uint32_t)next_index;
	EPAIR_UNLOCK();
	key[1] = (uint32_t)(hostid & 0xffffffff);
	key[2] = (uint32_t)((hostid >> 32) & 0xfffffffff);
	hash = jenkins_hash32(key, 3, 0);

	eaddr[0] = 0x02;
	memcpy(&eaddr[1], &hash, 4);
	eaddr[5] = 0x0a;
	ether_ifattach(ifp, eaddr);
	ifp->if_baudrate = IF_Gbps(10);	/* arbitrary maximum */
	ifp->if_transmit = epair_transmit;

	/* Swap the name and finish initialization of interface <n>b. */
	*dp = 'b';

	ifp = scb->ifp;
	ifp->if_softc = scb;
	strlcpy(ifp->if_xname, name, IFNAMSIZ);
	ifp->if_dname = epairname;
	ifp->if_dunit = unit;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_flags |= IFF_KNOWSEPOCH;
	ifp->if_capabilities = IFCAP_VLAN_MTU;
	ifp->if_capenable = IFCAP_VLAN_MTU;
	ifp->if_start = epair_start;
	ifp->if_ioctl = epair_ioctl;
	ifp->if_init  = epair_init;
	if_setsendqlen(ifp, ifqmaxlen);
	if_setsendqready(ifp);
	/* We need to play some tricks here for the second interface. */
	strlcpy(name, epairname, len);

	/* Correctly set the name for the cloner list. */
	strlcpy(name, scb->ifp->if_xname, len);
	epair_clone_add(ifc, scb);

	ifp->if_baudrate = IF_Gbps(10);	/* arbitrary maximum */
	ifp->if_transmit = epair_transmit;

	/*
	 * Restore name to <n>a as the ifp for this will go into the
	 * cloner list for the initial call.
	 */
	strlcpy(name, sca->ifp->if_xname, len);

	/* Tell the world, that we are ready to rock. */
	sca->ifp->if_drv_flags |= IFF_DRV_RUNNING;
	if_link_state_change(sca->ifp, LINK_STATE_UP);
	scb->ifp->if_drv_flags |= IFF_DRV_RUNNING;
	if_link_state_change(scb->ifp, LINK_STATE_UP);

	return (0);
}

static void
epair_drain_rings(struct epair_softc *sc)
{
	int ridx;
	struct mbuf *m;

	for (ridx = 0; ridx < 2; ridx++) {
		for (int i = 0; i < sc->num_queues; i++) {
			struct epair_queue *q = &sc->queues[i];
			do {
				m = buf_ring_dequeue_sc(q->rxring[ridx]);
				if (m == NULL)
					break;
				m_freem(m);
			} while (1);
		}
	}
}

static int
epair_clone_destroy(struct if_clone *ifc, struct ifnet *ifp)
{
	struct ifnet *oifp;
	struct epair_softc *sca, *scb;
	int unit, error;

	/*
	 * In case we called into if_clone_destroyif() ourselves
	 * again to remove the second interface, the softc will be
	 * NULL. In that case so not do anything but return success.
	 */
	if (ifp->if_softc == NULL)
		return (0);

	unit = ifp->if_dunit;
	sca = ifp->if_softc;
	oifp = sca->oifp;
	scb = oifp->if_softc;

	/* Frist get the interfaces down and detached. */
	if_link_state_change(ifp, LINK_STATE_DOWN);
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	if_link_state_change(oifp, LINK_STATE_DOWN);
	oifp->if_drv_flags &= ~IFF_DRV_RUNNING;

	ether_ifdetach(ifp);
	ether_ifdetach(oifp);

	/* Third free any queued packets and all the resources. */
	CURVNET_SET_QUIET(oifp->if_vnet);
	epair_drain_rings(scb);
	oifp->if_softc = NULL;
	error = if_clone_destroyif(ifc, oifp);
	if (error)
		panic("%s: if_clone_destroyif() for our 2nd iface failed: %d",
		    __func__, error);
	if_free(oifp);
	ifmedia_removeall(&scb->media);
	for (int i = 0; i < scb->num_queues; i++) {
		struct epair_queue *q = &scb->queues[i];
		buf_ring_free(q->rxring[0], M_EPAIR);
		buf_ring_free(q->rxring[1], M_EPAIR);
	}
	free(scb->queues, M_EPAIR);
	free(scb, M_EPAIR);
	CURVNET_RESTORE();

	epair_drain_rings(sca);
	if_free(ifp);
	ifmedia_removeall(&sca->media);
	for (int i = 0; i < sca->num_queues; i++) {
		struct epair_queue *q = &sca->queues[i];
		buf_ring_free(q->rxring[0], M_EPAIR);
		buf_ring_free(q->rxring[1], M_EPAIR);
	}
	free(sca->queues, M_EPAIR);
	free(sca, M_EPAIR);

	/* Last free the cloner unit. */
	ifc_free_unit(ifc, unit);

	return (0);
}

static void
vnet_epair_init(const void *unused __unused)
{

	V_epair_cloner = if_clone_advanced(epairname, 0,
	    epair_clone_match, epair_clone_create, epair_clone_destroy);
}
VNET_SYSINIT(vnet_epair_init, SI_SUB_PSEUDO, SI_ORDER_ANY,
    vnet_epair_init, NULL);

static void
vnet_epair_uninit(const void *unused __unused)
{

	if_clone_detach(V_epair_cloner);
}
VNET_SYSUNINIT(vnet_epair_uninit, SI_SUB_INIT_IF, SI_ORDER_ANY,
    vnet_epair_uninit, NULL);

static int
epair_mod_init(void)
{
	char name[32];
	epair_tasks.tasks = 0;

#ifdef RSS
	struct pcpu *pcpu;
	int cpu;

	CPU_FOREACH(cpu) {
		cpuset_t cpu_mask;

		/* Pin to this CPU so we get appropriate NUMA allocations. */
		pcpu = pcpu_find(cpu);
		thread_lock(curthread);
		sched_bind(curthread, cpu);
		thread_unlock(curthread);

		snprintf(name, sizeof(name), "epair_task_%d", cpu);

		epair_tasks.tq[cpu] = taskqueue_create(name, M_WAITOK,
		    taskqueue_thread_enqueue,
		    &epair_tasks.tq[cpu]);
		CPU_SETOF(cpu, &cpu_mask);
		taskqueue_start_threads_cpuset(&epair_tasks.tq[cpu], 1, PI_NET,
		    &cpu_mask, "%s", name);

		epair_tasks.tasks++;
	}
#else
	snprintf(name, sizeof(name), "epair_task");

	epair_tasks.tq[0] = taskqueue_create(name, M_WAITOK,
	    taskqueue_thread_enqueue,
	    &epair_tasks.tq[0]);
	taskqueue_start_threads(&epair_tasks.tq[0], 1, PI_NET, "%s", name);

	epair_tasks.tasks = 1;
#endif

	return (0);
}

static void
epair_mod_cleanup(void)
{

	for (int i = 0; i < epair_tasks.tasks; i++) {
		taskqueue_drain_all(epair_tasks.tq[i]);
		taskqueue_free(epair_tasks.tq[i]);
	}
}

static int
epair_modevent(module_t mod, int type, void *data)
{
	int ret;

	switch (type) {
	case MOD_LOAD:
		EPAIR_LOCK_INIT();
		ret = epair_mod_init();
		if (ret != 0)
			return (ret);
		if (bootverbose)
			printf("%s: %s initialized.\n", __func__, epairname);
		break;
	case MOD_UNLOAD:
		epair_mod_cleanup();
		EPAIR_LOCK_DESTROY();
		if (bootverbose)
			printf("%s: %s unloaded.\n", __func__, epairname);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t epair_mod = {
	"if_epair",
	epair_modevent,
	0
};

DECLARE_MODULE(if_epair, epair_mod, SI_SUB_PSEUDO, SI_ORDER_MIDDLE);
MODULE_VERSION(if_epair, 3);
// CHERI CHANGES START
// {
//   "updated": 20210525,
//   "target_type": "kernel",
//   "changes": [
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
