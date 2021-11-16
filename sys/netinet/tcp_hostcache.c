/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2002 Andre Oppermann, Internet Business Solutions AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The tcp_hostcache moves the tcp-specific cached metrics from the routing
 * table to a dedicated structure indexed by the remote IP address.  It keeps
 * information on the measured TCP parameters of past TCP sessions to allow
 * better initial start values to be used with later connections to/from the
 * same source.  Depending on the network parameters (delay, max MTU,
 * congestion window) between local and remote sites, this can lead to
 * significant speed-ups for new TCP connections after the first one.
 *
 * Due to the tcp_hostcache, all TCP-specific metrics information in the
 * routing table have been removed.  The inpcb no longer keeps a pointer to
 * the routing entry, and protocol-initiated route cloning has been removed
 * as well.  With these changes, the routing table has gone back to being
 * more lightwight and only carries information related to packet forwarding.
 *
 * tcp_hostcache is designed for multiple concurrent access in SMP
 * environments and high contention.  All bucket rows have their own lock and
 * thus multiple lookups and modifies can be done at the same time as long as
 * they are in different bucket rows.  If a request for insertion of a new
 * record can't be satisfied, it simply returns an empty structure.  Nobody
 * and nothing outside of tcp_hostcache.c will ever point directly to any
 * entry in the tcp_hostcache.  All communication is done in an
 * object-oriented way and only functions of tcp_hostcache will manipulate
 * hostcache entries.  Otherwise, we are unable to achieve good behaviour in
 * concurrent access situations.  Since tcp_hostcache is only caching
 * information, there are no fatal consequences if we either can't satisfy
 * any particular request or have to drop/overwrite an existing entry because
 * of bucket limit memory constrains.
 */

/*
 * Many thanks to jlemon for basic structure of tcp_syncache which is being
 * followed here.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/hash.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>

#include <vm/uma.h>

TAILQ_HEAD(hc_qhead, hc_metrics);

struct hc_head {
	struct hc_qhead	hch_bucket;
	u_int		hch_length;
	struct mtx	hch_mtx;
};

struct hc_metrics {
	/* housekeeping */
	TAILQ_ENTRY(hc_metrics) rmx_q;
	struct		hc_head *rmx_head; /* head of bucket tail queue */
	struct		in_addr ip4;	/* IP address */
	struct		in6_addr ip6;	/* IP6 address */
	uint32_t	ip6_zoneid;	/* IPv6 scope zone id */
	/* endpoint specific values for tcp */
	uint32_t	rmx_mtu;	/* MTU for this path */
	uint32_t	rmx_ssthresh;	/* outbound gateway buffer limit */
	uint32_t	rmx_rtt;	/* estimated round trip time */
	uint32_t	rmx_rttvar;	/* estimated rtt variance */
	uint32_t	rmx_cwnd;	/* congestion window */
	uint32_t	rmx_sendpipe;	/* outbound delay-bandwidth product */
	uint32_t	rmx_recvpipe;	/* inbound delay-bandwidth product */
	/* TCP hostcache internal data */
	int		rmx_expire;	/* lifetime for object */
#ifdef	TCP_HC_COUNTERS
	u_long		rmx_hits;	/* number of hits */
	u_long		rmx_updates;	/* number of updates */
#endif
};

struct tcp_hostcache {
	struct hc_head	*hashbase;
	uma_zone_t	zone;
	u_int		hashsize;
	u_int		hashmask;
	u_int		hashsalt;
	u_int		bucket_limit;
	u_int		cache_count;
	u_int		cache_limit;
	int		expire;
	int		prune;
	int		purgeall;
};

/* Arbitrary values */
#define TCP_HOSTCACHE_HASHSIZE		512
#define TCP_HOSTCACHE_BUCKETLIMIT	30
#define TCP_HOSTCACHE_EXPIRE		60*60	/* one hour */
#define TCP_HOSTCACHE_PRUNE		5*60	/* every 5 minutes */

VNET_DEFINE_STATIC(struct tcp_hostcache, tcp_hostcache);
#define	V_tcp_hostcache		VNET(tcp_hostcache)

VNET_DEFINE_STATIC(struct callout, tcp_hc_callout);
#define	V_tcp_hc_callout	VNET(tcp_hc_callout)

static struct hc_metrics *tcp_hc_lookup(struct in_conninfo *, bool);
static struct hc_metrics *tcp_hc_insert(struct in_conninfo *);
static int sysctl_tcp_hc_list(SYSCTL_HANDLER_ARGS);
static int sysctl_tcp_hc_histo(SYSCTL_HANDLER_ARGS);
static int sysctl_tcp_hc_purgenow(SYSCTL_HANDLER_ARGS);
static void tcp_hc_purge_internal(int);
static void tcp_hc_purge(void *);

static SYSCTL_NODE(_net_inet_tcp, OID_AUTO, hostcache,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "TCP Host cache");

VNET_DEFINE(int, tcp_use_hostcache) = 1;
#define V_tcp_use_hostcache  VNET(tcp_use_hostcache)
SYSCTL_INT(_net_inet_tcp_hostcache, OID_AUTO, enable, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(tcp_use_hostcache), 0,
    "Enable the TCP hostcache");

SYSCTL_UINT(_net_inet_tcp_hostcache, OID_AUTO, cachelimit, CTLFLAG_VNET | CTLFLAG_RDTUN,
    &VNET_NAME(tcp_hostcache.cache_limit), 0,
    "Overall entry limit for hostcache");

SYSCTL_UINT(_net_inet_tcp_hostcache, OID_AUTO, hashsize, CTLFLAG_VNET | CTLFLAG_RDTUN,
    &VNET_NAME(tcp_hostcache.hashsize), 0,
    "Size of TCP hostcache hashtable");

SYSCTL_UINT(_net_inet_tcp_hostcache, OID_AUTO, bucketlimit,
    CTLFLAG_VNET | CTLFLAG_RDTUN, &VNET_NAME(tcp_hostcache.bucket_limit), 0,
    "Per-bucket hash limit for hostcache");

SYSCTL_UINT(_net_inet_tcp_hostcache, OID_AUTO, count, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(tcp_hostcache.cache_count), 0,
    "Current number of entries in hostcache");

SYSCTL_INT(_net_inet_tcp_hostcache, OID_AUTO, expire, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(tcp_hostcache.expire), 0,
    "Expire time of TCP hostcache entries");

SYSCTL_INT(_net_inet_tcp_hostcache, OID_AUTO, prune, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(tcp_hostcache.prune), 0,
    "Time between purge runs");

SYSCTL_INT(_net_inet_tcp_hostcache, OID_AUTO, purge, CTLFLAG_VNET | CTLFLAG_RW,
    &VNET_NAME(tcp_hostcache.purgeall), 0,
    "Expire all entires on next purge run");

SYSCTL_PROC(_net_inet_tcp_hostcache, OID_AUTO, list,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_SKIP | CTLFLAG_MPSAFE,
    0, 0, sysctl_tcp_hc_list, "A",
    "List of all hostcache entries");

SYSCTL_PROC(_net_inet_tcp_hostcache, OID_AUTO, histo,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_SKIP | CTLFLAG_MPSAFE,
    0, 0, sysctl_tcp_hc_histo, "A",
    "Print a histogram of hostcache hashbucket utilization");

SYSCTL_PROC(_net_inet_tcp_hostcache, OID_AUTO, purgenow,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    NULL, 0, sysctl_tcp_hc_purgenow, "I",
    "Immediately purge all entries");

static MALLOC_DEFINE(M_HOSTCACHE, "hostcache", "TCP hostcache");

/* Use jenkins_hash32(), as in other parts of the tcp stack */
#define HOSTCACHE_HASH(ip) \
	(jenkins_hash32((uint32_t *)(ip), 1, V_tcp_hostcache.hashsalt) & \
	 V_tcp_hostcache.hashmask)

#define HOSTCACHE_HASH6(ip6)				\
	(jenkins_hash32((uint32_t *)&((ip6)->s6_addr32[0]), 4, \
	 V_tcp_hostcache.hashsalt) & \
	 V_tcp_hostcache.hashmask)

#define THC_LOCK(h)		mtx_lock(&(h)->hch_mtx)
#define THC_UNLOCK(h)		mtx_unlock(&(h)->hch_mtx)

void
tcp_hc_init(void)
{
	u_int cache_limit;
	int i;

	/*
	 * Initialize hostcache structures.
	 */
	atomic_store_int(&V_tcp_hostcache.cache_count, 0);
	V_tcp_hostcache.hashsize = TCP_HOSTCACHE_HASHSIZE;
	V_tcp_hostcache.bucket_limit = TCP_HOSTCACHE_BUCKETLIMIT;
	V_tcp_hostcache.expire = TCP_HOSTCACHE_EXPIRE;
	V_tcp_hostcache.prune = TCP_HOSTCACHE_PRUNE;
	V_tcp_hostcache.hashsalt = arc4random();

	TUNABLE_INT_FETCH("net.inet.tcp.hostcache.hashsize",
	    &V_tcp_hostcache.hashsize);
	if (!powerof2(V_tcp_hostcache.hashsize)) {
		printf("WARNING: hostcache hash size is not a power of 2.\n");
		V_tcp_hostcache.hashsize = TCP_HOSTCACHE_HASHSIZE; /* default */
	}
	V_tcp_hostcache.hashmask = V_tcp_hostcache.hashsize - 1;

	TUNABLE_INT_FETCH("net.inet.tcp.hostcache.bucketlimit",
	    &V_tcp_hostcache.bucket_limit);

	cache_limit = V_tcp_hostcache.hashsize * V_tcp_hostcache.bucket_limit;
	V_tcp_hostcache.cache_limit = cache_limit;
	TUNABLE_INT_FETCH("net.inet.tcp.hostcache.cachelimit",
	    &V_tcp_hostcache.cache_limit);
	if (V_tcp_hostcache.cache_limit > cache_limit)
		V_tcp_hostcache.cache_limit = cache_limit;

	/*
	 * Allocate the hash table.
	 */
	V_tcp_hostcache.hashbase = (struct hc_head *)
	    malloc(V_tcp_hostcache.hashsize * sizeof(struct hc_head),
		   M_HOSTCACHE, M_WAITOK | M_ZERO);

	/*
	 * Initialize the hash buckets.
	 */
	for (i = 0; i < V_tcp_hostcache.hashsize; i++) {
		TAILQ_INIT(&V_tcp_hostcache.hashbase[i].hch_bucket);
		V_tcp_hostcache.hashbase[i].hch_length = 0;
		mtx_init(&V_tcp_hostcache.hashbase[i].hch_mtx, "tcp_hc_entry",
			  NULL, MTX_DEF);
	}

	/*
	 * Allocate the hostcache entries.
	 */
	V_tcp_hostcache.zone =
	    uma_zcreate("hostcache", sizeof(struct hc_metrics),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	uma_zone_set_max(V_tcp_hostcache.zone, V_tcp_hostcache.cache_limit);

	/*
	 * Set up periodic cache cleanup.
	 */
	callout_init(&V_tcp_hc_callout, 1);
	callout_reset(&V_tcp_hc_callout, V_tcp_hostcache.prune * hz,
	    tcp_hc_purge, curvnet);
}

#ifdef VIMAGE
void
tcp_hc_destroy(void)
{
	int i;

	callout_drain(&V_tcp_hc_callout);

	/* Purge all hc entries. */
	tcp_hc_purge_internal(1);

	/* Free the uma zone and the allocated hash table. */
	uma_zdestroy(V_tcp_hostcache.zone);

	for (i = 0; i < V_tcp_hostcache.hashsize; i++)
		mtx_destroy(&V_tcp_hostcache.hashbase[i].hch_mtx);
	free(V_tcp_hostcache.hashbase, M_HOSTCACHE);
}
#endif

/*
 * Internal function: look up an entry in the hostcache or return NULL.
 *
 * If an entry has been returned, the caller becomes responsible for
 * unlocking the bucket row after he is done reading/modifying the entry.
 */
static struct hc_metrics *
tcp_hc_lookup(struct in_conninfo *inc, bool update)
{
	int hash;
	struct hc_head *hc_head;
	struct hc_metrics *hc_entry;

	KASSERT(inc != NULL, ("%s: NULL in_conninfo", __func__));

	/*
	 * Hash the foreign ip address.
	 */
	if (inc->inc_flags & INC_ISIPV6)
		hash = HOSTCACHE_HASH6(&inc->inc6_faddr);
	else
		hash = HOSTCACHE_HASH(&inc->inc_faddr);

	hc_head = &V_tcp_hostcache.hashbase[hash];

	/*
	 * Acquire lock for this bucket row; we release the lock if we don't
	 * find an entry, otherwise the caller has to unlock after he is
	 * done.
	 */
	THC_LOCK(hc_head);

	/*
	 * Iterate through entries in bucket row looking for a match.
	 */
	TAILQ_FOREACH(hc_entry, &hc_head->hch_bucket, rmx_q) {
		if (inc->inc_flags & INC_ISIPV6) {
			/* XXX: check ip6_zoneid */
			if (memcmp(&inc->inc6_faddr, &hc_entry->ip6,
			    sizeof(inc->inc6_faddr)) == 0)
				goto found;
		} else {
			if (memcmp(&inc->inc_faddr, &hc_entry->ip4,
			    sizeof(inc->inc_faddr)) == 0)
				goto found;
		}
	}

	/*
	 * We were unsuccessful and didn't find anything.
	 */
	THC_UNLOCK(hc_head);
	return (NULL);

found:
#ifdef	TCP_HC_COUNTERS
	if (update)
		hc_entry->rmx_updates++;
	else
		hc_entry->rmx_hits++;
#endif
	hc_entry->rmx_expire = V_tcp_hostcache.expire;

	return (hc_entry);
}

/*
 * Internal function: insert an entry into the hostcache or return NULL if
 * unable to allocate a new one.
 *
 * If an entry has been returned, the caller becomes responsible for
 * unlocking the bucket row after he is done reading/modifying the entry.
 */
static struct hc_metrics *
tcp_hc_insert(struct in_conninfo *inc)
{
	int hash;
	struct hc_head *hc_head;
	struct hc_metrics *hc_entry;

	KASSERT(inc != NULL, ("%s: NULL in_conninfo", __func__));

	/*
	 * Hash the foreign ip address.
	 */
	if (inc->inc_flags & INC_ISIPV6)
		hash = HOSTCACHE_HASH6(&inc->inc6_faddr);
	else
		hash = HOSTCACHE_HASH(&inc->inc_faddr);

	hc_head = &V_tcp_hostcache.hashbase[hash];

	/*
	 * Acquire lock for this bucket row; we release the lock if we don't
	 * find an entry, otherwise the caller has to unlock after he is
	 * done.
	 */
	THC_LOCK(hc_head);

	/*
	 * If the bucket limit is reached, reuse the least-used element.
	 */
	if (hc_head->hch_length >= V_tcp_hostcache.bucket_limit ||
	    atomic_load_int(&V_tcp_hostcache.cache_count) >= V_tcp_hostcache.cache_limit) {
		hc_entry = TAILQ_LAST(&hc_head->hch_bucket, hc_qhead);
		/*
		 * At first we were dropping the last element, just to
		 * reacquire it in the next two lines again, which isn't very
		 * efficient.  Instead just reuse the least used element.
		 * We may drop something that is still "in-use" but we can be
		 * "lossy".
		 * Just give up if this bucket row is empty and we don't have
		 * anything to replace.
		 */
		if (hc_entry == NULL) {
			THC_UNLOCK(hc_head);
			return (NULL);
		}
		TAILQ_REMOVE(&hc_head->hch_bucket, hc_entry, rmx_q);
		KASSERT(V_tcp_hostcache.hashbase[hash].hch_length > 0 &&
		    V_tcp_hostcache.hashbase[hash].hch_length <=
		    V_tcp_hostcache.bucket_limit,
		    ("tcp_hostcache: bucket length range violated at %u: %u",
		    hash, V_tcp_hostcache.hashbase[hash].hch_length));
		V_tcp_hostcache.hashbase[hash].hch_length--;
		atomic_subtract_int(&V_tcp_hostcache.cache_count, 1);
		TCPSTAT_INC(tcps_hc_bucketoverflow);
#if 0
		uma_zfree(V_tcp_hostcache.zone, hc_entry);
#endif
	} else {
		/*
		 * Allocate a new entry, or balk if not possible.
		 */
		hc_entry = uma_zalloc(V_tcp_hostcache.zone, M_NOWAIT);
		if (hc_entry == NULL) {
			THC_UNLOCK(hc_head);
			return (NULL);
		}
	}

	/*
	 * Initialize basic information of hostcache entry.
	 */
	bzero(hc_entry, sizeof(*hc_entry));
	if (inc->inc_flags & INC_ISIPV6) {
		hc_entry->ip6 = inc->inc6_faddr;
		hc_entry->ip6_zoneid = inc->inc6_zoneid;
	} else
		hc_entry->ip4 = inc->inc_faddr;
	hc_entry->rmx_head = hc_head;
	hc_entry->rmx_expire = V_tcp_hostcache.expire;

	/*
	 * Put it upfront.
	 */
	TAILQ_INSERT_HEAD(&hc_head->hch_bucket, hc_entry, rmx_q);
	V_tcp_hostcache.hashbase[hash].hch_length++;
	KASSERT(V_tcp_hostcache.hashbase[hash].hch_length <
	    V_tcp_hostcache.bucket_limit,
	    ("tcp_hostcache: bucket length too high at %u: %u",
	    hash, V_tcp_hostcache.hashbase[hash].hch_length));
	atomic_add_int(&V_tcp_hostcache.cache_count, 1);
	TCPSTAT_INC(tcps_hc_added);

	return (hc_entry);
}

/*
 * External function: look up an entry in the hostcache and fill out the
 * supplied TCP metrics structure.  Fills in NULL when no entry was found or
 * a value is not set.
 */
void
tcp_hc_get(struct in_conninfo *inc, struct hc_metrics_lite *hc_metrics_lite)
{
	struct hc_metrics *hc_entry;

	if (!V_tcp_use_hostcache) {
		bzero(hc_metrics_lite, sizeof(*hc_metrics_lite));
		return;
	}

	/*
	 * Find the right bucket.
	 */
	hc_entry = tcp_hc_lookup(inc, false);

	/*
	 * If we don't have an existing object.
	 */
	if (hc_entry == NULL) {
		bzero(hc_metrics_lite, sizeof(*hc_metrics_lite));
		return;
	}

	hc_metrics_lite->rmx_mtu = hc_entry->rmx_mtu;
	hc_metrics_lite->rmx_ssthresh = hc_entry->rmx_ssthresh;
	hc_metrics_lite->rmx_rtt = hc_entry->rmx_rtt;
	hc_metrics_lite->rmx_rttvar = hc_entry->rmx_rttvar;
	hc_metrics_lite->rmx_cwnd = hc_entry->rmx_cwnd;
	hc_metrics_lite->rmx_sendpipe = hc_entry->rmx_sendpipe;
	hc_metrics_lite->rmx_recvpipe = hc_entry->rmx_recvpipe;

	/*
	 * Unlock bucket row.
	 */
	THC_UNLOCK(hc_entry->rmx_head);
}

/*
 * External function: look up an entry in the hostcache and return the
 * discovered path MTU.  Returns 0 if no entry is found or value is not
 * set.
 */
uint32_t
tcp_hc_getmtu(struct in_conninfo *inc)
{
	struct hc_metrics *hc_entry;
	uint32_t mtu;

	if (!V_tcp_use_hostcache)
		return (0);

	hc_entry = tcp_hc_lookup(inc, false);
	if (hc_entry == NULL) {
		return (0);
	}

	mtu = hc_entry->rmx_mtu;
	THC_UNLOCK(hc_entry->rmx_head);
	return (mtu);
}

/*
 * External function: update the MTU value of an entry in the hostcache.
 * Creates a new entry if none was found.
 */
void
tcp_hc_updatemtu(struct in_conninfo *inc, uint32_t mtu)
{
	struct hc_metrics_lite hcml = { .rmx_mtu = mtu };

	return (tcp_hc_update(inc, &hcml));
}

/*
 * External function: update the TCP metrics of an entry in the hostcache.
 * Creates a new entry if none was found.
 */
void
tcp_hc_update(struct in_conninfo *inc, struct hc_metrics_lite *hcml)
{
	struct hc_metrics *hc_entry;

	if (!V_tcp_use_hostcache)
		return;

	hc_entry = tcp_hc_lookup(inc, true);
	if (hc_entry == NULL) {
		hc_entry = tcp_hc_insert(inc);
		if (hc_entry == NULL)
			return;
	}

	if (hcml->rmx_mtu != 0) {
		hc_entry->rmx_mtu = hcml->rmx_mtu;
	}
	if (hcml->rmx_rtt != 0) {
		if (hc_entry->rmx_rtt == 0)
			hc_entry->rmx_rtt = hcml->rmx_rtt;
		else
			hc_entry->rmx_rtt = ((uint64_t)hc_entry->rmx_rtt +
			    (uint64_t)hcml->rmx_rtt) / 2;
		TCPSTAT_INC(tcps_cachedrtt);
	}
	if (hcml->rmx_rttvar != 0) {
		if (hc_entry->rmx_rttvar == 0)
			hc_entry->rmx_rttvar = hcml->rmx_rttvar;
		else
			hc_entry->rmx_rttvar = ((uint64_t)hc_entry->rmx_rttvar +
			    (uint64_t)hcml->rmx_rttvar) / 2;
		TCPSTAT_INC(tcps_cachedrttvar);
	}
	if (hcml->rmx_ssthresh != 0) {
		if (hc_entry->rmx_ssthresh == 0)
			hc_entry->rmx_ssthresh = hcml->rmx_ssthresh;
		else
			hc_entry->rmx_ssthresh =
			    (hc_entry->rmx_ssthresh + hcml->rmx_ssthresh) / 2;
		TCPSTAT_INC(tcps_cachedssthresh);
	}
	if (hcml->rmx_cwnd != 0) {
		if (hc_entry->rmx_cwnd == 0)
			hc_entry->rmx_cwnd = hcml->rmx_cwnd;
		else
			hc_entry->rmx_cwnd = ((uint64_t)hc_entry->rmx_cwnd +
			    (uint64_t)hcml->rmx_cwnd) / 2;
		/* TCPSTAT_INC(tcps_cachedcwnd); */
	}
	if (hcml->rmx_sendpipe != 0) {
		if (hc_entry->rmx_sendpipe == 0)
			hc_entry->rmx_sendpipe = hcml->rmx_sendpipe;
		else
			hc_entry->rmx_sendpipe =
			    ((uint64_t)hc_entry->rmx_sendpipe +
			    (uint64_t)hcml->rmx_sendpipe) /2;
		/* TCPSTAT_INC(tcps_cachedsendpipe); */
	}
	if (hcml->rmx_recvpipe != 0) {
		if (hc_entry->rmx_recvpipe == 0)
			hc_entry->rmx_recvpipe = hcml->rmx_recvpipe;
		else
			hc_entry->rmx_recvpipe =
			    ((uint64_t)hc_entry->rmx_recvpipe +
			    (uint64_t)hcml->rmx_recvpipe) /2;
		/* TCPSTAT_INC(tcps_cachedrecvpipe); */
	}

	TAILQ_REMOVE(&hc_entry->rmx_head->hch_bucket, hc_entry, rmx_q);
	TAILQ_INSERT_HEAD(&hc_entry->rmx_head->hch_bucket, hc_entry, rmx_q);
	THC_UNLOCK(hc_entry->rmx_head);
}

/*
 * Sysctl function: prints the list and values of all hostcache entries in
 * unsorted order.
 */
static int
sysctl_tcp_hc_list(SYSCTL_HANDLER_ARGS)
{
	const int linesize = 128;
	struct sbuf sb;
	int i, error, len;
	struct hc_metrics *hc_entry;
	char ip4buf[INET_ADDRSTRLEN];
#ifdef INET6
	char ip6buf[INET6_ADDRSTRLEN];
#endif

	if (jailed_without_vnet(curthread->td_ucred) != 0)
		return (EPERM);

	/* Optimize Buffer length query by sbin/sysctl */
	if (req->oldptr == NULL) {
		len = (atomic_load_int(&V_tcp_hostcache.cache_count) + 1) *
			linesize;
		return (SYSCTL_OUT(req, NULL, len));
	}

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0) {
		return(error);
	}

	/* Use a buffer sized for one full bucket */
	sbuf_new_for_sysctl(&sb, NULL, V_tcp_hostcache.bucket_limit *
		linesize, req);

	sbuf_printf(&sb,
		"\nIP address        MTU  SSTRESH      RTT   RTTVAR "
		"    CWND SENDPIPE RECVPIPE "
#ifdef	TCP_HC_COUNTERS
		"HITS  UPD  "
#endif
		"EXP\n");
	sbuf_drain(&sb);

#define msec(u) (((u) + 500) / 1000)
	for (i = 0; i < V_tcp_hostcache.hashsize; i++) {
		THC_LOCK(&V_tcp_hostcache.hashbase[i]);
		TAILQ_FOREACH(hc_entry, &V_tcp_hostcache.hashbase[i].hch_bucket,
		    rmx_q) {
			sbuf_printf(&sb,
			    "%-15s %5u %8u %6lums %6lums %8u %8u %8u "
#ifdef	TCP_HC_COUNTERS
			    "%4lu %4lu "
#endif
			    "%4i\n",
			    hc_entry->ip4.s_addr ?
			        inet_ntoa_r(hc_entry->ip4, ip4buf) :
#ifdef INET6
				ip6_sprintf(ip6buf, &hc_entry->ip6),
#else
				"IPv6?",
#endif
			    hc_entry->rmx_mtu,
			    hc_entry->rmx_ssthresh,
			    msec((u_long)hc_entry->rmx_rtt *
				(RTM_RTTUNIT / (hz * TCP_RTT_SCALE))),
			    msec((u_long)hc_entry->rmx_rttvar *
				(RTM_RTTUNIT / (hz * TCP_RTTVAR_SCALE))),
			    hc_entry->rmx_cwnd,
			    hc_entry->rmx_sendpipe,
			    hc_entry->rmx_recvpipe,
#ifdef	TCP_HC_COUNTERS
			    hc_entry->rmx_hits,
			    hc_entry->rmx_updates,
#endif
			    hc_entry->rmx_expire);
		}
		THC_UNLOCK(&V_tcp_hostcache.hashbase[i]);
		sbuf_drain(&sb);
	}
#undef msec
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return(error);
}

/*
 * Sysctl function: prints a histogram of the hostcache hashbucket
 * utilization.
 */
static int
sysctl_tcp_hc_histo(SYSCTL_HANDLER_ARGS)
{
	const int linesize = 50;
	struct sbuf sb;
	int i, error;
	int *histo;
	u_int hch_length;

	if (jailed_without_vnet(curthread->td_ucred) != 0)
		return (EPERM);

	histo = (int *)malloc(sizeof(int) * (V_tcp_hostcache.bucket_limit + 1),
			M_TEMP, M_NOWAIT|M_ZERO);
	if (histo == NULL)
		return(ENOMEM);

	for (i = 0; i < V_tcp_hostcache.hashsize; i++) {
		hch_length = V_tcp_hostcache.hashbase[i].hch_length;
		KASSERT(hch_length <= V_tcp_hostcache.bucket_limit,
		    ("tcp_hostcache: bucket limit exceeded at %u: %u",
		    i, hch_length));
		histo[hch_length]++;
	}

	/* Use a buffer for 16 lines */
	sbuf_new_for_sysctl(&sb, NULL, 16 * linesize, req);

	sbuf_printf(&sb, "\nLength\tCount\n");
	for (i = 0; i <= V_tcp_hostcache.bucket_limit; i++) {
		sbuf_printf(&sb, "%u\t%u\n", i, histo[i]);
	}
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	free(histo, M_TEMP);
	return(error);
}

/*
 * Caller has to make sure the curvnet is set properly.
 */
static void
tcp_hc_purge_internal(int all)
{
	struct hc_metrics *hc_entry, *hc_next;
	int i;

	for (i = 0; i < V_tcp_hostcache.hashsize; i++) {
		THC_LOCK(&V_tcp_hostcache.hashbase[i]);
		TAILQ_FOREACH_SAFE(hc_entry,
		    &V_tcp_hostcache.hashbase[i].hch_bucket, rmx_q, hc_next) {
			KASSERT(V_tcp_hostcache.hashbase[i].hch_length > 0 &&
			    V_tcp_hostcache.hashbase[i].hch_length <=
			    V_tcp_hostcache.bucket_limit, ("tcp_hostcache: "
			    "bucket length out of range at %u: %u",
			    i, V_tcp_hostcache.hashbase[i].hch_length));
			if (all || hc_entry->rmx_expire <= 0) {
				TAILQ_REMOVE(
				    &V_tcp_hostcache.hashbase[i].hch_bucket,
				    hc_entry, rmx_q);
				uma_zfree(V_tcp_hostcache.zone, hc_entry);
				V_tcp_hostcache.hashbase[i].hch_length--;
				atomic_subtract_int(&V_tcp_hostcache.cache_count, 1);
			} else
				hc_entry->rmx_expire -= V_tcp_hostcache.prune;
		}
		THC_UNLOCK(&V_tcp_hostcache.hashbase[i]);
	}
}

/*
 * Expire and purge (old|all) entries in the tcp_hostcache.  Runs
 * periodically from the callout.
 */
static void
tcp_hc_purge(void *arg)
{
	CURVNET_SET((struct vnet *) arg);
	int all = 0;

	if (V_tcp_hostcache.purgeall) {
		if (V_tcp_hostcache.purgeall == 2)
			V_tcp_hostcache.hashsalt = arc4random();
		all = 1;
		V_tcp_hostcache.purgeall = 0;
	}

	tcp_hc_purge_internal(all);

	callout_reset(&V_tcp_hc_callout, V_tcp_hostcache.prune * hz,
	    tcp_hc_purge, arg);
	CURVNET_RESTORE();
}

/*
 * Expire and purge all entries in hostcache immediately.
 */
static int
sysctl_tcp_hc_purgenow(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return (error);

	if (val == 2)
		V_tcp_hostcache.hashsalt = arc4random();
	tcp_hc_purge_internal(1);

	callout_reset(&V_tcp_hc_callout, V_tcp_hostcache.prune * hz,
	    tcp_hc_purge, curvnet);

	return (0);
}
