/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002 Luigi Rizzo, Universita` di Pisa
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#define        DEB(x)
#define        DDB(x) x

/*
 * Dynamic rule support for ipfw
 */

#include "opt_ipfw.h"
#include "opt_inet.h"
#ifndef INET
#error IPFIREWALL requires INET.
#endif /* INET */
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/rmlock.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <net/ethernet.h> /* for ETHERTYPE_IP */
#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>	/* ip_defttl */
#include <netinet/ip_fw.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>

#include <netinet/ip6.h>	/* IN6_ARE_ADDR_EQUAL */
#ifdef INET6
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#endif

#include <netpfil/ipfw/ip_fw_private.h>

#include <machine/in_cksum.h>	/* XXX for in_cksum */

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

/*
 * Description of dynamic rules.
 *
 * Dynamic rules are stored in lists accessed through a hash table
 * (ipfw_dyn_v) whose size is curr_dyn_buckets. This value can
 * be modified through the sysctl variable dyn_buckets which is
 * updated when the table becomes empty.
 *
 * XXX currently there is only one list, ipfw_dyn.
 *
 * When a packet is received, its address fields are first masked
 * with the mask defined for the rule, then hashed, then matched
 * against the entries in the corresponding list.
 * Dynamic rules can be used for different purposes:
 *  + stateful rules;
 *  + enforcing limits on the number of sessions;
 *  + in-kernel NAT (not implemented yet)
 *
 * The lifetime of dynamic rules is regulated by dyn_*_lifetime,
 * measured in seconds and depending on the flags.
 *
 * The total number of dynamic rules is equal to UMA zone items count.
 * The max number of dynamic rules is dyn_max. When we reach
 * the maximum number of rules we do not create anymore. This is
 * done to avoid consuming too much memory, but also too much
 * time when searching on each packet (ideally, we should try instead
 * to put a limit on the length of the list on each bucket...).
 *
 * Each dynamic rule holds a pointer to the parent ipfw rule so
 * we know what action to perform. Dynamic rules are removed when
 * the parent rule is deleted. This can be changed by dyn_keep_states
 * sysctl.
 *
 * There are some limitations with dynamic rules -- we do not
 * obey the 'randomized match', and we do not do multiple
 * passes through the firewall. XXX check the latter!!!
 */

struct ipfw_dyn_bucket {
	struct mtx	mtx;		/* Bucket protecting lock */
	ipfw_dyn_rule	*head;		/* Pointer to first rule */
};

/*
 * Static variables followed by global ones
 */
static VNET_DEFINE(struct ipfw_dyn_bucket *, ipfw_dyn_v);
static VNET_DEFINE(u_int32_t, dyn_buckets_max);
static VNET_DEFINE(u_int32_t, curr_dyn_buckets);
static VNET_DEFINE(struct callout, ipfw_timeout);
#define	V_ipfw_dyn_v			VNET(ipfw_dyn_v)
#define	V_dyn_buckets_max		VNET(dyn_buckets_max)
#define	V_curr_dyn_buckets		VNET(curr_dyn_buckets)
#define V_ipfw_timeout                  VNET(ipfw_timeout)

static VNET_DEFINE(uma_zone_t, ipfw_dyn_rule_zone);
#define	V_ipfw_dyn_rule_zone		VNET(ipfw_dyn_rule_zone)

#define	IPFW_BUCK_LOCK_INIT(b)	\
	mtx_init(&(b)->mtx, "IPFW dynamic bucket", NULL, MTX_DEF)
#define	IPFW_BUCK_LOCK_DESTROY(b)	\
	mtx_destroy(&(b)->mtx)
#define	IPFW_BUCK_LOCK(i)	mtx_lock(&V_ipfw_dyn_v[(i)].mtx)
#define	IPFW_BUCK_UNLOCK(i)	mtx_unlock(&V_ipfw_dyn_v[(i)].mtx)
#define	IPFW_BUCK_ASSERT(i)	mtx_assert(&V_ipfw_dyn_v[(i)].mtx, MA_OWNED)


static VNET_DEFINE(int, dyn_keep_states);
#define	V_dyn_keep_states		VNET(dyn_keep_states)

/*
 * Timeouts for various events in handing dynamic rules.
 */
static VNET_DEFINE(u_int32_t, dyn_ack_lifetime);
static VNET_DEFINE(u_int32_t, dyn_syn_lifetime);
static VNET_DEFINE(u_int32_t, dyn_fin_lifetime);
static VNET_DEFINE(u_int32_t, dyn_rst_lifetime);
static VNET_DEFINE(u_int32_t, dyn_udp_lifetime);
static VNET_DEFINE(u_int32_t, dyn_short_lifetime);

#define	V_dyn_ack_lifetime		VNET(dyn_ack_lifetime)
#define	V_dyn_syn_lifetime		VNET(dyn_syn_lifetime)
#define	V_dyn_fin_lifetime		VNET(dyn_fin_lifetime)
#define	V_dyn_rst_lifetime		VNET(dyn_rst_lifetime)
#define	V_dyn_udp_lifetime		VNET(dyn_udp_lifetime)
#define	V_dyn_short_lifetime		VNET(dyn_short_lifetime)

/*
 * Keepalives are sent if dyn_keepalive is set. They are sent every
 * dyn_keepalive_period seconds, in the last dyn_keepalive_interval
 * seconds of lifetime of a rule.
 * dyn_rst_lifetime and dyn_fin_lifetime should be strictly lower
 * than dyn_keepalive_period.
 */

static VNET_DEFINE(u_int32_t, dyn_keepalive_interval);
static VNET_DEFINE(u_int32_t, dyn_keepalive_period);
static VNET_DEFINE(u_int32_t, dyn_keepalive);
static VNET_DEFINE(time_t, dyn_keepalive_last);

#define	V_dyn_keepalive_interval	VNET(dyn_keepalive_interval)
#define	V_dyn_keepalive_period		VNET(dyn_keepalive_period)
#define	V_dyn_keepalive			VNET(dyn_keepalive)
#define	V_dyn_keepalive_last		VNET(dyn_keepalive_last)

static VNET_DEFINE(u_int32_t, dyn_max);		/* max # of dynamic rules */

#define	DYN_COUNT			uma_zone_get_cur(V_ipfw_dyn_rule_zone)
#define	V_dyn_max			VNET(dyn_max)

/* for userspace, we emulate the uma_zone_counter with ipfw_dyn_count */
static int ipfw_dyn_count;	/* number of objects */

#ifdef USERSPACE /* emulation of UMA object counters for userspace */
#define uma_zone_get_cur(x)	ipfw_dyn_count
#endif /* USERSPACE */

static int last_log;	/* Log ratelimiting */

static void ipfw_dyn_tick(void *vnetx);
static void check_dyn_rules(struct ip_fw_chain *, ipfw_range_tlv *, int, int);
#ifdef SYSCTL_NODE

static int sysctl_ipfw_dyn_count(SYSCTL_HANDLER_ARGS);
static int sysctl_ipfw_dyn_max(SYSCTL_HANDLER_ARGS);

SYSBEGIN(f2)

SYSCTL_DECL(_net_inet_ip_fw);
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_buckets,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_buckets_max), 0,
    "Max number of dyn. buckets");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, curr_dyn_buckets,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(curr_dyn_buckets), 0,
    "Current Number of dyn. buckets");
SYSCTL_PROC(_net_inet_ip_fw, OID_AUTO, dyn_count,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RD, 0, 0, sysctl_ipfw_dyn_count, "IU",
    "Number of dyn. rules");
SYSCTL_PROC(_net_inet_ip_fw, OID_AUTO, dyn_max,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RW, 0, 0, sysctl_ipfw_dyn_max, "IU",
    "Max number of dyn. rules");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_ack_lifetime,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_ack_lifetime), 0,
    "Lifetime of dyn. rules for acks");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_syn_lifetime,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_syn_lifetime), 0,
    "Lifetime of dyn. rules for syn");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_fin_lifetime,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_fin_lifetime), 0,
    "Lifetime of dyn. rules for fin");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_rst_lifetime,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_rst_lifetime), 0,
    "Lifetime of dyn. rules for rst");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_udp_lifetime,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_udp_lifetime), 0,
    "Lifetime of dyn. rules for UDP");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_short_lifetime,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_short_lifetime), 0,
    "Lifetime of dyn. rules for other situations");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_keepalive,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_keepalive), 0,
    "Enable keepalives for dyn. rules");
SYSCTL_UINT(_net_inet_ip_fw, OID_AUTO, dyn_keep_states,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(dyn_keep_states), 0,
    "Do not flush dynamic states on rule deletion");

SYSEND

#endif /* SYSCTL_NODE */


#ifdef INET6
static __inline int
hash_packet6(const struct ipfw_flow_id *id)
{
	u_int32_t i;
	i = (id->dst_ip6.__u6_addr.__u6_addr32[2]) ^
	    (id->dst_ip6.__u6_addr.__u6_addr32[3]) ^
	    (id->src_ip6.__u6_addr.__u6_addr32[2]) ^
	    (id->src_ip6.__u6_addr.__u6_addr32[3]);
	return ntohl(i);
}
#endif

/*
 * IMPORTANT: the hash function for dynamic rules must be commutative
 * in source and destination (ip,port), because rules are bidirectional
 * and we want to find both in the same bucket.
 */
static __inline int
hash_packet(const struct ipfw_flow_id *id, int buckets)
{
	u_int32_t i;

#ifdef INET6
	if (IS_IP6_FLOW_ID(id)) 
		i = hash_packet6(id);
	else
#endif /* INET6 */
	i = (id->dst_ip) ^ (id->src_ip);
	i ^= (id->dst_port) ^ (id->src_port);
	return (i & (buckets - 1));
}

#if 0
#define	DYN_DEBUG(fmt, ...)	do {			\
	printf("%s: " fmt "\n", __func__, __VA_ARGS__);	\
} while (0)
#else
#define	DYN_DEBUG(fmt, ...)
#endif

static char *default_state_name = "default";
struct dyn_state_obj {
	struct named_object	no;
	char			name[64];
};

#define	DYN_STATE_OBJ(ch, cmd)	\
    ((struct dyn_state_obj *)SRV_OBJECT(ch, (cmd)->arg1))
/*
 * Classifier callback.
 * Return 0 if opcode contains object that should be referenced
 * or rewritten.
 */
static int
dyn_classify(ipfw_insn *cmd, uint16_t *puidx, uint8_t *ptype)
{

	DYN_DEBUG("opcode %d, arg1 %d", cmd->opcode, cmd->arg1);
	/* Don't rewrite "check-state any" */
	if (cmd->arg1 == 0 &&
	    cmd->opcode == O_CHECK_STATE)
		return (1);

	*puidx = cmd->arg1;
	*ptype = 0;
	return (0);
}

static void
dyn_update(ipfw_insn *cmd, uint16_t idx)
{

	cmd->arg1 = idx;
	DYN_DEBUG("opcode %d, arg1 %d", cmd->opcode, cmd->arg1);
}

static int
dyn_findbyname(struct ip_fw_chain *ch, struct tid_info *ti,
    struct named_object **pno)
{
	ipfw_obj_ntlv *ntlv;
	const char *name;

	DYN_DEBUG("uidx %d", ti->uidx);
	if (ti->uidx != 0) {
		if (ti->tlvs == NULL)
			return (EINVAL);
		/* Search ntlv in the buffer provided by user */
		ntlv = ipfw_find_name_tlv_type(ti->tlvs, ti->tlen, ti->uidx,
		    IPFW_TLV_STATE_NAME);
		if (ntlv == NULL)
			return (EINVAL);
		name = ntlv->name;
	} else
		name = default_state_name;
	/*
	 * Search named object with corresponding name.
	 * Since states objects are global - ignore the set value
	 * and use zero instead.
	 */
	*pno = ipfw_objhash_lookup_name_type(CHAIN_TO_SRV(ch), 0,
	    IPFW_TLV_STATE_NAME, name);
	/*
	 * We always return success here.
	 * The caller will check *pno and mark object as unresolved,
	 * then it will automatically create "default" object.
	 */
	return (0);
}

static struct named_object *
dyn_findbykidx(struct ip_fw_chain *ch, uint16_t idx)
{

	DYN_DEBUG("kidx %d", idx);
	return (ipfw_objhash_lookup_kidx(CHAIN_TO_SRV(ch), idx));
}

static int
dyn_create(struct ip_fw_chain *ch, struct tid_info *ti,
    uint16_t *pkidx)
{
	struct namedobj_instance *ni;
	struct dyn_state_obj *obj;
	struct named_object *no;
	ipfw_obj_ntlv *ntlv;
	char *name;

	DYN_DEBUG("uidx %d", ti->uidx);
	if (ti->uidx != 0) {
		if (ti->tlvs == NULL)
			return (EINVAL);
		ntlv = ipfw_find_name_tlv_type(ti->tlvs, ti->tlen, ti->uidx,
		    IPFW_TLV_STATE_NAME);
		if (ntlv == NULL)
			return (EINVAL);
		name = ntlv->name;
	} else
		name = default_state_name;

	ni = CHAIN_TO_SRV(ch);
	obj = malloc(sizeof(*obj), M_IPFW, M_WAITOK | M_ZERO);
	obj->no.name = obj->name;
	obj->no.etlv = IPFW_TLV_STATE_NAME;
	strlcpy(obj->name, name, sizeof(obj->name));

	IPFW_UH_WLOCK(ch);
	no = ipfw_objhash_lookup_name_type(ni, 0,
	    IPFW_TLV_STATE_NAME, name);
	if (no != NULL) {
		/*
		 * Object is already created.
		 * Just return its kidx and bump refcount.
		 */
		*pkidx = no->kidx;
		no->refcnt++;
		IPFW_UH_WUNLOCK(ch);
		free(obj, M_IPFW);
		DYN_DEBUG("\tfound kidx %d", *pkidx);
		return (0);
	}
	if (ipfw_objhash_alloc_idx(ni, &obj->no.kidx) != 0) {
		DYN_DEBUG("\talloc_idx failed for %s", name);
		IPFW_UH_WUNLOCK(ch);
		free(obj, M_IPFW);
		return (ENOSPC);
	}
	ipfw_objhash_add(ni, &obj->no);
	SRV_OBJECT(ch, obj->no.kidx) = obj;
	obj->no.refcnt++;
	*pkidx = obj->no.kidx;
	IPFW_UH_WUNLOCK(ch);
	DYN_DEBUG("\tcreated kidx %d", *pkidx);
	return (0);
}

static void
dyn_destroy(struct ip_fw_chain *ch, struct named_object *no)
{
	struct dyn_state_obj *obj;

	IPFW_UH_WLOCK_ASSERT(ch);

	KASSERT(no->refcnt == 1,
	    ("Destroying object '%s' (type %u, idx %u) with refcnt %u",
	    no->name, no->etlv, no->kidx, no->refcnt));

	DYN_DEBUG("kidx %d", no->kidx);
	obj = SRV_OBJECT(ch, no->kidx);
	SRV_OBJECT(ch, no->kidx) = NULL;
	ipfw_objhash_del(CHAIN_TO_SRV(ch), no);
	ipfw_objhash_free_idx(CHAIN_TO_SRV(ch), no->kidx);

	free(obj, M_IPFW);
}

static struct opcode_obj_rewrite dyn_opcodes[] = {
	{
		O_KEEP_STATE, IPFW_TLV_STATE_NAME,
		dyn_classify, dyn_update,
		dyn_findbyname, dyn_findbykidx,
		dyn_create, dyn_destroy
	},
	{
		O_CHECK_STATE, IPFW_TLV_STATE_NAME,
		dyn_classify, dyn_update,
		dyn_findbyname, dyn_findbykidx,
		dyn_create, dyn_destroy
	},
	{
		O_PROBE_STATE, IPFW_TLV_STATE_NAME,
		dyn_classify, dyn_update,
		dyn_findbyname, dyn_findbykidx,
		dyn_create, dyn_destroy
	},
	{
		O_LIMIT, IPFW_TLV_STATE_NAME,
		dyn_classify, dyn_update,
		dyn_findbyname, dyn_findbykidx,
		dyn_create, dyn_destroy
	},
};
/**
 * Print customizable flow id description via log(9) facility.
 */
static void
print_dyn_rule_flags(const struct ipfw_flow_id *id, int dyn_type,
    int log_flags, char *prefix, char *postfix)
{
	struct in_addr da;
#ifdef INET6
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
#else
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
#endif

#ifdef INET6
	if (IS_IP6_FLOW_ID(id)) {
		ip6_sprintf(src, &id->src_ip6);
		ip6_sprintf(dst, &id->dst_ip6);
	} else
#endif
	{
		da.s_addr = htonl(id->src_ip);
		inet_ntop(AF_INET, &da, src, sizeof(src));
		da.s_addr = htonl(id->dst_ip);
		inet_ntop(AF_INET, &da, dst, sizeof(dst));
	}
	log(log_flags, "ipfw: %s type %d %s %d -> %s %d, %d %s\n",
	    prefix, dyn_type, src, id->src_port, dst,
	    id->dst_port, DYN_COUNT, postfix);
}

#define	print_dyn_rule(id, dtype, prefix, postfix)	\
	print_dyn_rule_flags(id, dtype, LOG_DEBUG, prefix, postfix)

#define TIME_LEQ(a,b)       ((int)((a)-(b)) <= 0)
#define TIME_LE(a,b)       ((int)((a)-(b)) < 0)

static void
dyn_update_proto_state(ipfw_dyn_rule *q, const struct ipfw_flow_id *id,
    const void *ulp, int dir)
{
	const struct tcphdr *tcp;
	uint32_t ack;
	u_char flags;

	if (id->proto == IPPROTO_TCP) {
		tcp = (const struct tcphdr *)ulp;
		flags = id->_flags & (TH_FIN | TH_SYN | TH_RST);
#define BOTH_SYN	(TH_SYN | (TH_SYN << 8))
#define BOTH_FIN	(TH_FIN | (TH_FIN << 8))
#define	TCP_FLAGS	(TH_FLAGS | (TH_FLAGS << 8))
#define	ACK_FWD		0x10000			/* fwd ack seen */
#define	ACK_REV		0x20000			/* rev ack seen */

		q->state |= (dir == MATCH_FORWARD) ? flags : (flags << 8);
		switch (q->state & TCP_FLAGS) {
		case TH_SYN:			/* opening */
			q->expire = time_uptime + V_dyn_syn_lifetime;
			break;

		case BOTH_SYN:			/* move to established */
		case BOTH_SYN | TH_FIN:		/* one side tries to close */
		case BOTH_SYN | (TH_FIN << 8):
#define _SEQ_GE(a,b) ((int)(a) - (int)(b) >= 0)
			if (tcp == NULL)
				break;

			ack = ntohl(tcp->th_ack);
			if (dir == MATCH_FORWARD) {
				if (q->ack_fwd == 0 ||
				    _SEQ_GE(ack, q->ack_fwd)) {
					q->ack_fwd = ack;
					q->state |= ACK_FWD;
				}
			} else {
				if (q->ack_rev == 0 ||
				    _SEQ_GE(ack, q->ack_rev)) {
					q->ack_rev = ack;
					q->state |= ACK_REV;
				}
			}
			if ((q->state & (ACK_FWD | ACK_REV)) ==
			    (ACK_FWD | ACK_REV)) {
				q->expire = time_uptime + V_dyn_ack_lifetime;
				q->state &= ~(ACK_FWD | ACK_REV);
			}
			break;

		case BOTH_SYN | BOTH_FIN:	/* both sides closed */
			if (V_dyn_fin_lifetime >= V_dyn_keepalive_period)
				V_dyn_fin_lifetime =
				    V_dyn_keepalive_period - 1;
			q->expire = time_uptime + V_dyn_fin_lifetime;
			break;

		default:
#if 0
			/*
			 * reset or some invalid combination, but can also
			 * occur if we use keep-state the wrong way.
			 */
			if ( (q->state & ((TH_RST << 8)|TH_RST)) == 0)
				printf("invalid state: 0x%x\n", q->state);
#endif
			if (V_dyn_rst_lifetime >= V_dyn_keepalive_period)
				V_dyn_rst_lifetime =
				    V_dyn_keepalive_period - 1;
			q->expire = time_uptime + V_dyn_rst_lifetime;
			break;
		}
	} else if (id->proto == IPPROTO_UDP ||
	    id->proto == IPPROTO_UDPLITE) {
		q->expire = time_uptime + V_dyn_udp_lifetime;
	} else {
		/* other protocols */
		q->expire = time_uptime + V_dyn_short_lifetime;
	}
}

/*
 * Lookup a dynamic rule, locked version.
 */
static ipfw_dyn_rule *
lookup_dyn_rule_locked(const struct ipfw_flow_id *pkt, const void *ulp,
    int i, int *match_direction, uint16_t kidx)
{
	/*
	 * Stateful ipfw extensions.
	 * Lookup into dynamic session queue.
	 */
	ipfw_dyn_rule *prev, *q = NULL;
	int dir;

	IPFW_BUCK_ASSERT(i);

	dir = MATCH_NONE;
	for (prev = NULL, q = V_ipfw_dyn_v[i].head; q; prev = q, q = q->next) {
		if (q->dyn_type == O_LIMIT_PARENT)
			continue;

		if (pkt->addr_type != q->id.addr_type)
			continue;

		if (pkt->proto != q->id.proto)
			continue;

		if (kidx != 0 && kidx != q->kidx)
			continue;

		if (IS_IP6_FLOW_ID(pkt)) {
			if (IN6_ARE_ADDR_EQUAL(&pkt->src_ip6, &q->id.src_ip6) &&
			    IN6_ARE_ADDR_EQUAL(&pkt->dst_ip6, &q->id.dst_ip6) &&
			    pkt->src_port == q->id.src_port &&
			    pkt->dst_port == q->id.dst_port) {
				dir = MATCH_FORWARD;
				break;
			}
			if (IN6_ARE_ADDR_EQUAL(&pkt->src_ip6, &q->id.dst_ip6) &&
			    IN6_ARE_ADDR_EQUAL(&pkt->dst_ip6, &q->id.src_ip6) &&
			    pkt->src_port == q->id.dst_port &&
			    pkt->dst_port == q->id.src_port) {
				dir = MATCH_REVERSE;
				break;
			}
		} else {
			if (pkt->src_ip == q->id.src_ip &&
			    pkt->dst_ip == q->id.dst_ip &&
			    pkt->src_port == q->id.src_port &&
			    pkt->dst_port == q->id.dst_port) {
				dir = MATCH_FORWARD;
				break;
			}
			if (pkt->src_ip == q->id.dst_ip &&
			    pkt->dst_ip == q->id.src_ip &&
			    pkt->src_port == q->id.dst_port &&
			    pkt->dst_port == q->id.src_port) {
				dir = MATCH_REVERSE;
				break;
			}
		}
	}
	if (q == NULL)
		goto done;	/* q = NULL, not found */

	if (prev != NULL) {	/* found and not in front */
		prev->next = q->next;
		q->next = V_ipfw_dyn_v[i].head;
		V_ipfw_dyn_v[i].head = q;
	}

	/* update state according to flags */
	dyn_update_proto_state(q, pkt, ulp, dir);
done:
	if (match_direction != NULL)
		*match_direction = dir;
	return (q);
}

struct ip_fw *
ipfw_dyn_lookup_state(const struct ipfw_flow_id *pkt, const void *ulp,
    int pktlen, int *match_direction, uint16_t kidx)
{
	struct ip_fw *rule;
	ipfw_dyn_rule *q;
	int i;

	i = hash_packet(pkt, V_curr_dyn_buckets);

	IPFW_BUCK_LOCK(i);
	q = lookup_dyn_rule_locked(pkt, ulp, i, match_direction, kidx);
	if (q == NULL)
		rule = NULL;
	else {
		rule = q->rule;
		IPFW_INC_DYN_COUNTER(q, pktlen);
	}
	IPFW_BUCK_UNLOCK(i);
	return (rule);
}

static int
resize_dynamic_table(struct ip_fw_chain *chain, int nbuckets)
{
	int i, k, nbuckets_old;
	ipfw_dyn_rule *q;
	struct ipfw_dyn_bucket *dyn_v, *dyn_v_old;

	/* Check if given number is power of 2 and less than 64k */
	if ((nbuckets > 65536) || (!powerof2(nbuckets)))
		return 1;

	CTR3(KTR_NET, "%s: resize dynamic hash: %d -> %d", __func__,
	    V_curr_dyn_buckets, nbuckets);

	/* Allocate and initialize new hash */
	dyn_v = malloc(nbuckets * sizeof(*dyn_v), M_IPFW,
	    M_WAITOK | M_ZERO);

	for (i = 0 ; i < nbuckets; i++)
		IPFW_BUCK_LOCK_INIT(&dyn_v[i]);

	/*
	 * Call upper half lock, as get_map() do to ease
	 * read-only access to dynamic rules hash from sysctl
	 */
	IPFW_UH_WLOCK(chain);

	/*
	 * Acquire chain write lock to permit hash access
	 * for main traffic path without additional locks
	 */
	IPFW_WLOCK(chain);

	/* Save old values */
	nbuckets_old = V_curr_dyn_buckets;
	dyn_v_old = V_ipfw_dyn_v;

	/* Skip relinking if array is not set up */
	if (V_ipfw_dyn_v == NULL)
		V_curr_dyn_buckets = 0;

	/* Re-link all dynamic states */
	for (i = 0 ; i < V_curr_dyn_buckets ; i++) {
		while (V_ipfw_dyn_v[i].head != NULL) {
			/* Remove from current chain */
			q = V_ipfw_dyn_v[i].head;
			V_ipfw_dyn_v[i].head = q->next;

			/* Get new hash value */
			k = hash_packet(&q->id, nbuckets);
			q->bucket = k;
			/* Add to the new head */
			q->next = dyn_v[k].head;
			dyn_v[k].head = q;
             }
	}

	/* Update current pointers/buckets values */
	V_curr_dyn_buckets = nbuckets;
	V_ipfw_dyn_v = dyn_v;

	IPFW_WUNLOCK(chain);

	IPFW_UH_WUNLOCK(chain);

	/* Start periodic callout on initial creation */
	if (dyn_v_old == NULL) {
        	callout_reset_on(&V_ipfw_timeout, hz, ipfw_dyn_tick, curvnet, 0);
		return (0);
	}

	/* Destroy all mutexes */
	for (i = 0 ; i < nbuckets_old ; i++)
		IPFW_BUCK_LOCK_DESTROY(&dyn_v_old[i]);

	/* Free old hash */
	free(dyn_v_old, M_IPFW);

	return 0;
}

/**
 * Install state of type 'type' for a dynamic session.
 * The hash table contains two type of rules:
 * - regular rules (O_KEEP_STATE)
 * - rules for sessions with limited number of sess per user
 *   (O_LIMIT). When they are created, the parent is
 *   increased by 1, and decreased on delete. In this case,
 *   the third parameter is the parent rule and not the chain.
 * - "parent" rules for the above (O_LIMIT_PARENT).
 */
static ipfw_dyn_rule *
add_dyn_rule(const struct ipfw_flow_id *id, int i, uint8_t dyn_type,
    struct ip_fw *rule, uint16_t kidx)
{
	ipfw_dyn_rule *r;

	IPFW_BUCK_ASSERT(i);

	r = uma_zalloc(V_ipfw_dyn_rule_zone, M_NOWAIT | M_ZERO);
	if (r == NULL) {
		if (last_log != time_uptime) {
			last_log = time_uptime;
			log(LOG_DEBUG,
			    "ipfw: Cannot allocate dynamic state, "
			    "consider increasing net.inet.ip.fw.dyn_max\n");
		}
		return NULL;
	}
	ipfw_dyn_count++;

	/*
	 * refcount on parent is already incremented, so
	 * it is safe to use parent unlocked.
	 */
	if (dyn_type == O_LIMIT) {
		ipfw_dyn_rule *parent = (ipfw_dyn_rule *)rule;
		if ( parent->dyn_type != O_LIMIT_PARENT)
			panic("invalid parent");
		r->parent = parent;
		rule = parent->rule;
	}

	r->id = *id;
	r->expire = time_uptime + V_dyn_syn_lifetime;
	r->rule = rule;
	r->dyn_type = dyn_type;
	IPFW_ZERO_DYN_COUNTER(r);
	r->count = 0;
	r->kidx = kidx;
	r->bucket = i;
	r->next = V_ipfw_dyn_v[i].head;
	V_ipfw_dyn_v[i].head = r;
	DEB(print_dyn_rule(id, dyn_type, "add dyn entry", "total");)
	return r;
}

/**
 * lookup dynamic parent rule using pkt and rule as search keys.
 * If the lookup fails, then install one.
 */
static ipfw_dyn_rule *
lookup_dyn_parent(const struct ipfw_flow_id *pkt, int *pindex,
    struct ip_fw *rule, uint16_t kidx)
{
	ipfw_dyn_rule *q;
	int i, is_v6;

	is_v6 = IS_IP6_FLOW_ID(pkt);
	i = hash_packet( pkt, V_curr_dyn_buckets );
	*pindex = i;
	IPFW_BUCK_LOCK(i);
	for (q = V_ipfw_dyn_v[i].head ; q != NULL ; q=q->next)
		if (q->dyn_type == O_LIMIT_PARENT &&
		    kidx == q->kidx &&
		    rule == q->rule &&
		    pkt->proto == q->id.proto &&
		    pkt->src_port == q->id.src_port &&
		    pkt->dst_port == q->id.dst_port &&
		    (
			(is_v6 &&
			 IN6_ARE_ADDR_EQUAL(&(pkt->src_ip6),
				&(q->id.src_ip6)) &&
			 IN6_ARE_ADDR_EQUAL(&(pkt->dst_ip6),
				&(q->id.dst_ip6))) ||
			(!is_v6 &&
			 pkt->src_ip == q->id.src_ip &&
			 pkt->dst_ip == q->id.dst_ip)
		    )
		) {
			q->expire = time_uptime + V_dyn_short_lifetime;
			DEB(print_dyn_rule(pkt, q->dyn_type,
			    "lookup_dyn_parent found", "");)
			return q;
		}

	/* Add virtual limiting rule */
	return add_dyn_rule(pkt, i, O_LIMIT_PARENT, rule, kidx);
}

/**
 * Install dynamic state for rule type cmd->o.opcode
 *
 * Returns 1 (failure) if state is not installed because of errors or because
 * session limitations are enforced.
 */
int
ipfw_dyn_install_state(struct ip_fw_chain *chain, struct ip_fw *rule,
    ipfw_insn_limit *cmd, struct ip_fw_args *args, uint32_t tablearg)
{
	ipfw_dyn_rule *q;
	int i;

	DEB(print_dyn_rule(&args->f_id, cmd->o.opcode, "install_state",
	    (cmd->o.arg1 == 0 ? "": DYN_STATE_OBJ(chain, &cmd->o)->name));)

	i = hash_packet(&args->f_id, V_curr_dyn_buckets);

	IPFW_BUCK_LOCK(i);

	q = lookup_dyn_rule_locked(&args->f_id, NULL, i, NULL, cmd->o.arg1);
	if (q != NULL) {	/* should never occur */
		DEB(
		if (last_log != time_uptime) {
			last_log = time_uptime;
			printf("ipfw: %s: entry already present, done\n",
			    __func__);
		})
		IPFW_BUCK_UNLOCK(i);
		return (0);
	}

	/*
	 * State limiting is done via uma(9) zone limiting.
	 * Save pointer to newly-installed rule and reject
	 * packet if add_dyn_rule() returned NULL.
	 * Note q is currently set to NULL.
	 */

	switch (cmd->o.opcode) {
	case O_KEEP_STATE:	/* bidir rule */
		q = add_dyn_rule(&args->f_id, i, O_KEEP_STATE, rule,
		    cmd->o.arg1);
		break;

	case O_LIMIT: {		/* limit number of sessions */
		struct ipfw_flow_id id;
		ipfw_dyn_rule *parent;
		uint32_t conn_limit;
		uint16_t limit_mask = cmd->limit_mask;
		int pindex;

		conn_limit = IP_FW_ARG_TABLEARG(chain, cmd->conn_limit, limit);
		  
		DEB(
		if (cmd->conn_limit == IP_FW_TARG)
			printf("ipfw: %s: O_LIMIT rule, conn_limit: %u "
			    "(tablearg)\n", __func__, conn_limit);
		else
			printf("ipfw: %s: O_LIMIT rule, conn_limit: %u\n",
			    __func__, conn_limit);
		)

		id.dst_ip = id.src_ip = id.dst_port = id.src_port = 0;
		id.proto = args->f_id.proto;
		id.addr_type = args->f_id.addr_type;
		id.fib = M_GETFIB(args->m);

		if (IS_IP6_FLOW_ID (&(args->f_id))) {
			bzero(&id.src_ip6, sizeof(id.src_ip6));
			bzero(&id.dst_ip6, sizeof(id.dst_ip6));

			if (limit_mask & DYN_SRC_ADDR)
				id.src_ip6 = args->f_id.src_ip6;
			if (limit_mask & DYN_DST_ADDR)
				id.dst_ip6 = args->f_id.dst_ip6;
		} else {
			if (limit_mask & DYN_SRC_ADDR)
				id.src_ip = args->f_id.src_ip;
			if (limit_mask & DYN_DST_ADDR)
				id.dst_ip = args->f_id.dst_ip;
		}
		if (limit_mask & DYN_SRC_PORT)
			id.src_port = args->f_id.src_port;
		if (limit_mask & DYN_DST_PORT)
			id.dst_port = args->f_id.dst_port;

		/*
		 * We have to release lock for previous bucket to
		 * avoid possible deadlock
		 */
		IPFW_BUCK_UNLOCK(i);

		parent = lookup_dyn_parent(&id, &pindex, rule, cmd->o.arg1);
		if (parent == NULL) {
			printf("ipfw: %s: add parent failed\n", __func__);
			IPFW_BUCK_UNLOCK(pindex);
			return (1);
		}

		if (parent->count >= conn_limit) {
			if (V_fw_verbose && last_log != time_uptime) {
				char sbuf[24];
				last_log = time_uptime;
				snprintf(sbuf, sizeof(sbuf),
				    "%d drop session",
				    parent->rule->rulenum);
				print_dyn_rule_flags(&args->f_id,
				    cmd->o.opcode,
				    LOG_SECURITY | LOG_DEBUG,
				    sbuf, "too many entries");
			}
			IPFW_BUCK_UNLOCK(pindex);
			return (1);
		}
		/* Increment counter on parent */
		parent->count++;
		IPFW_BUCK_UNLOCK(pindex);

		IPFW_BUCK_LOCK(i);
		q = add_dyn_rule(&args->f_id, i, O_LIMIT,
		    (struct ip_fw *)parent, cmd->o.arg1);
		if (q == NULL) {
			/* Decrement index and notify caller */
			IPFW_BUCK_UNLOCK(i);
			IPFW_BUCK_LOCK(pindex);
			parent->count--;
			IPFW_BUCK_UNLOCK(pindex);
			return (1);
		}
		break;
	}
	default:
		printf("ipfw: %s: unknown dynamic rule type %u\n",
		    __func__, cmd->o.opcode);
	}

	if (q == NULL) {
		IPFW_BUCK_UNLOCK(i);
		return (1);	/* Notify caller about failure */
	}

	dyn_update_proto_state(q, &args->f_id, NULL, MATCH_FORWARD);
	IPFW_BUCK_UNLOCK(i);
	return (0);
}

/*
 * Queue keepalive packets for given dynamic rule
 */
static struct mbuf **
ipfw_dyn_send_ka(struct mbuf **mtailp, ipfw_dyn_rule *q)
{
	struct mbuf *m_rev, *m_fwd;

	m_rev = (q->state & ACK_REV) ? NULL :
	    ipfw_send_pkt(NULL, &(q->id), q->ack_rev - 1, q->ack_fwd, TH_SYN);
	m_fwd = (q->state & ACK_FWD) ? NULL :
	    ipfw_send_pkt(NULL, &(q->id), q->ack_fwd - 1, q->ack_rev, 0);

	if (m_rev != NULL) {
		*mtailp = m_rev;
		mtailp = &(*mtailp)->m_nextpkt;
	}
	if (m_fwd != NULL) {
		*mtailp = m_fwd;
		mtailp = &(*mtailp)->m_nextpkt;
	}

	return (mtailp);
}

/*
 * This procedure is used to perform various maintenance
 * on dynamic hash list. Currently it is called every second.
 */
static void
ipfw_dyn_tick(void * vnetx) 
{
	struct ip_fw_chain *chain;
	int check_ka = 0;
#ifdef VIMAGE
	struct vnet *vp = vnetx;
#endif

	CURVNET_SET(vp);

	chain = &V_layer3_chain;

	/* Run keepalive checks every keepalive_period iff ka is enabled */
	if ((V_dyn_keepalive_last + V_dyn_keepalive_period <= time_uptime) &&
	    (V_dyn_keepalive != 0)) {
		V_dyn_keepalive_last = time_uptime;
		check_ka = 1;
	}

	check_dyn_rules(chain, NULL, check_ka, 1);

	callout_reset_on(&V_ipfw_timeout, hz, ipfw_dyn_tick, vnetx, 0);

	CURVNET_RESTORE();
}


/*
 * Walk through all dynamic states doing generic maintenance:
 * 1) free expired states
 * 2) free all states based on deleted rule / set
 * 3) send keepalives for states if needed
 *
 * @chain - pointer to current ipfw rules chain
 * @rule - delete all states originated by given rule if != NULL
 * @set - delete all states originated by any rule in set @set if != RESVD_SET
 * @check_ka - perform checking/sending keepalives
 * @timer - indicate call from timer routine.
 *
 * Timer routine must call this function unlocked to permit
 * sending keepalives/resizing table.
 *
 * Others has to call function with IPFW_UH_WLOCK held.
 * Additionally, function assume that dynamic rule/set is
 * ALREADY deleted so no new states can be generated by
 * 'deleted' rules.
 *
 * Write lock is needed to ensure that unused parent rules
 * are not freed by other instance (see stage 2, 3)
 */
static void
check_dyn_rules(struct ip_fw_chain *chain, ipfw_range_tlv *rt,
    int check_ka, int timer)
{
	struct mbuf *m0, *m, *mnext, **mtailp;
	struct ip *h;
	int i, dyn_count, new_buckets = 0, max_buckets;
	int expired = 0, expired_limits = 0, parents = 0, total = 0;
	ipfw_dyn_rule *q, *q_prev, *q_next;
	ipfw_dyn_rule *exp_head, **exptailp;
	ipfw_dyn_rule *exp_lhead, **expltailp;

	KASSERT(V_ipfw_dyn_v != NULL, ("%s: dynamic table not allocated",
	    __func__));

	/* Avoid possible LOR */
	KASSERT(!check_ka || timer, ("%s: keepalive check with lock held",
	    __func__));

	/*
	 * Do not perform any checks if we currently have no dynamic states
	 */
	if (DYN_COUNT == 0)
		return;

	/* Expired states */
	exp_head = NULL;
	exptailp = &exp_head;

	/* Expired limit states */
	exp_lhead = NULL;
	expltailp = &exp_lhead;

	/*
	 * We make a chain of packets to go out here -- not deferring
	 * until after we drop the IPFW dynamic rule lock would result
	 * in a lock order reversal with the normal packet input -> ipfw
	 * call stack.
	 */
	m0 = NULL;
	mtailp = &m0;

	/* Protect from hash resizing */
	if (timer != 0)
		IPFW_UH_WLOCK(chain);
	else
		IPFW_UH_WLOCK_ASSERT(chain);

#define	NEXT_RULE()	{ q_prev = q; q = q->next ; continue; }

	/* Stage 1: perform requested deletion */
	for (i = 0 ; i < V_curr_dyn_buckets ; i++) {
		IPFW_BUCK_LOCK(i);
		for (q = V_ipfw_dyn_v[i].head, q_prev = q; q ; ) {
			/* account every rule */
			total++;

			/* Skip parent rules at all */
			if (q->dyn_type == O_LIMIT_PARENT) {
				parents++;
				NEXT_RULE();
			}

			/*
			 * Remove rules which are:
			 * 1) expired
			 * 2) matches deletion range
			 */
			if ((TIME_LEQ(q->expire, time_uptime)) ||
			    (rt != NULL && ipfw_match_range(q->rule, rt))) {
				if (TIME_LE(time_uptime, q->expire) &&
				    q->dyn_type == O_KEEP_STATE &&
				    V_dyn_keep_states != 0) {
					/*
					 * Do not delete state if
					 * it is not expired and
					 * dyn_keep_states is ON.
					 * However we need to re-link it
					 * to any other stable rule
					 */
					q->rule = chain->default_rule;
					NEXT_RULE();
				}

				/* Unlink q from current list */
				q_next = q->next;
				if (q == V_ipfw_dyn_v[i].head)
					V_ipfw_dyn_v[i].head = q_next;
				else
					q_prev->next = q_next;

				q->next = NULL;

				/* queue q to expire list */
				if (q->dyn_type != O_LIMIT) {
					*exptailp = q;
					exptailp = &(*exptailp)->next;
					DEB(print_dyn_rule(&q->id, q->dyn_type,
					    "unlink entry", "left");
					)
				} else {
					/* Separate list for limit rules */
					*expltailp = q;
					expltailp = &(*expltailp)->next;
					expired_limits++;
					DEB(print_dyn_rule(&q->id, q->dyn_type,
					    "unlink limit entry", "left");
					)
				}

				q = q_next;
				expired++;
				continue;
			}

			/*
			 * Check if we need to send keepalive:
			 * we need to ensure if is time to do KA,
			 * this is established TCP session, and
			 * expire time is within keepalive interval
			 */
			if ((check_ka != 0) && (q->id.proto == IPPROTO_TCP) &&
			    ((q->state & BOTH_SYN) == BOTH_SYN) &&
			    (TIME_LEQ(q->expire, time_uptime +
			      V_dyn_keepalive_interval)))
				mtailp = ipfw_dyn_send_ka(mtailp, q);

			NEXT_RULE();
		}
		IPFW_BUCK_UNLOCK(i);
	}

	/* Stage 2: decrement counters from O_LIMIT parents */
	if (expired_limits != 0) {
		/*
		 * XXX: Note that deleting set with more than one
		 * heavily-used LIMIT rules can result in overwhelming
		 * locking due to lack of per-hash value sorting
		 *
		 * We should probably think about:
		 * 1) pre-allocating hash of size, say,
		 * MAX(16, V_curr_dyn_buckets / 1024)
		 * 2) checking if expired_limits is large enough
		 * 3) If yes, init hash (or its part), re-link
		 * current list and start decrementing procedure in
		 * each bucket separately
		 */

		/*
		 * Small optimization: do not unlock bucket until
		 * we see the next item resides in different bucket
		 */
		if (exp_lhead != NULL) {
			i = exp_lhead->parent->bucket;
			IPFW_BUCK_LOCK(i);
		}
		for (q = exp_lhead; q != NULL; q = q->next) {
			if (i != q->parent->bucket) {
				IPFW_BUCK_UNLOCK(i);
				i = q->parent->bucket;
				IPFW_BUCK_LOCK(i);
			}

			/* Decrease parent refcount */
			q->parent->count--;
		}
		if (exp_lhead != NULL)
			IPFW_BUCK_UNLOCK(i);
	}

	/*
	 * We protectet ourselves from unused parent deletion
	 * (from the timer function) by holding UH write lock.
	 */

	/* Stage 3: remove unused parent rules */
	if ((parents != 0) && (expired != 0)) {
		for (i = 0 ; i < V_curr_dyn_buckets ; i++) {
			IPFW_BUCK_LOCK(i);
			for (q = V_ipfw_dyn_v[i].head, q_prev = q ; q ; ) {
				if (q->dyn_type != O_LIMIT_PARENT)
					NEXT_RULE();

				if (q->count != 0)
					NEXT_RULE();

				/* Parent rule without consumers */

				/* Unlink q from current list */
				q_next = q->next;
				if (q == V_ipfw_dyn_v[i].head)
					V_ipfw_dyn_v[i].head = q_next;
				else
					q_prev->next = q_next;

				q->next = NULL;

				/* Add to expired list */
				*exptailp = q;
				exptailp = &(*exptailp)->next;

				DEB(print_dyn_rule(&q->id, q->dyn_type,
				    "unlink parent entry", "left");
				)

				expired++;

				q = q_next;
			}
			IPFW_BUCK_UNLOCK(i);
		}
	}

#undef NEXT_RULE

	if (timer != 0) {
		/*
		 * Check if we need to resize hash:
		 * if current number of states exceeds number of buckes in hash,
		 * grow hash size to the minimum power of 2 which is bigger than
		 * current states count. Limit hash size by 64k.
		 */
		max_buckets = (V_dyn_buckets_max > 65536) ?
		    65536 : V_dyn_buckets_max;
	
		dyn_count = DYN_COUNT;
	
		if ((dyn_count > V_curr_dyn_buckets * 2) &&
		    (dyn_count < max_buckets)) {
			new_buckets = V_curr_dyn_buckets;
			while (new_buckets < dyn_count) {
				new_buckets *= 2;
	
				if (new_buckets >= max_buckets)
					break;
			}
		}

		IPFW_UH_WUNLOCK(chain);
	}

	/* Finally delete old states ad limits if any */
	for (q = exp_head; q != NULL; q = q_next) {
		q_next = q->next;
		uma_zfree(V_ipfw_dyn_rule_zone, q);
		ipfw_dyn_count--;
	}

	for (q = exp_lhead; q != NULL; q = q_next) {
		q_next = q->next;
		uma_zfree(V_ipfw_dyn_rule_zone, q);
		ipfw_dyn_count--;
	}

	/*
	 * The rest code MUST be called from timer routine only
	 * without holding any locks
	 */
	if (timer == 0)
		return;

	/* Send keepalive packets if any */
	for (m = m0; m != NULL; m = mnext) {
		mnext = m->m_nextpkt;
		m->m_nextpkt = NULL;
		h = mtod(m, struct ip *);
		if (h->ip_v == 4)
			ip_output(m, NULL, NULL, 0, NULL, NULL);
#ifdef INET6
		else
			ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
#endif
	}

	/* Run table resize without holding any locks */
	if (new_buckets != 0)
		resize_dynamic_table(chain, new_buckets);
}

/*
 * Deletes all dynamic rules originated by given rule or all rules in
 * given set. Specify RESVD_SET to indicate set should not be used.
 * @chain - pointer to current ipfw rules chain
 * @rr - delete all states originated by rules in matched range.
 *
 * Function has to be called with IPFW_UH_WLOCK held.
 * Additionally, function assume that dynamic rule/set is
 * ALREADY deleted so no new states can be generated by
 * 'deleted' rules.
 */
void
ipfw_expire_dyn_rules(struct ip_fw_chain *chain, ipfw_range_tlv *rt)
{

	check_dyn_rules(chain, rt, 0, 0);
}

/*
 * Check if rule contains at least one dynamic opcode.
 *
 * Returns 1 if such opcode is found, 0 otherwise.
 */
int
ipfw_is_dyn_rule(struct ip_fw *rule)
{
	int cmdlen, l;
	ipfw_insn *cmd;

	l = rule->cmd_len;
	cmd = rule->cmd;
	cmdlen = 0;
	for ( ;	l > 0 ; l -= cmdlen, cmd += cmdlen) {
		cmdlen = F_LEN(cmd);

		switch (cmd->opcode) {
		case O_LIMIT:
		case O_KEEP_STATE:
		case O_PROBE_STATE:
		case O_CHECK_STATE:
			return (1);
		}
	}

	return (0);
}

void
ipfw_dyn_init(struct ip_fw_chain *chain)
{

        V_ipfw_dyn_v = NULL;
        V_dyn_buckets_max = 256; /* must be power of 2 */
        V_curr_dyn_buckets = 256; /* must be power of 2 */
 
        V_dyn_ack_lifetime = 300;
        V_dyn_syn_lifetime = 20;
        V_dyn_fin_lifetime = 1;
        V_dyn_rst_lifetime = 1;
        V_dyn_udp_lifetime = 10;
        V_dyn_short_lifetime = 5;

        V_dyn_keepalive_interval = 20;
        V_dyn_keepalive_period = 5;
        V_dyn_keepalive = 1;    /* do send keepalives */
	V_dyn_keepalive_last = time_uptime;
        
        V_dyn_max = 16384; /* max # of dynamic rules */

	V_ipfw_dyn_rule_zone = uma_zcreate("IPFW dynamic rule",
	    sizeof(ipfw_dyn_rule), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	/* Enforce limit on dynamic rules */
	uma_zone_set_max(V_ipfw_dyn_rule_zone, V_dyn_max);

        callout_init(&V_ipfw_timeout, 1);

	/*
	 * This can potentially be done on first dynamic rule
	 * being added to chain.
	 */
	resize_dynamic_table(chain, V_curr_dyn_buckets);
	IPFW_ADD_OBJ_REWRITER(IS_DEFAULT_VNET(curvnet), dyn_opcodes);
}

void
ipfw_dyn_uninit(int pass)
{
	int i;

	if (pass == 0) {
		callout_drain(&V_ipfw_timeout);
		return;
	}
	IPFW_DEL_OBJ_REWRITER(IS_DEFAULT_VNET(curvnet), dyn_opcodes);

	if (V_ipfw_dyn_v != NULL) {
		/*
		 * Skip deleting all dynamic states -
		 * uma_zdestroy() does this more efficiently;
		 */

		/* Destroy all mutexes */
		for (i = 0 ; i < V_curr_dyn_buckets ; i++)
			IPFW_BUCK_LOCK_DESTROY(&V_ipfw_dyn_v[i]);
		free(V_ipfw_dyn_v, M_IPFW);
		V_ipfw_dyn_v = NULL;
	}

        uma_zdestroy(V_ipfw_dyn_rule_zone);
}

#ifdef SYSCTL_NODE
/*
 * Get/set maximum number of dynamic states in given VNET instance.
 */
static int
sysctl_ipfw_dyn_max(SYSCTL_HANDLER_ARGS)
{
	int error;
	unsigned int nstates;

	nstates = V_dyn_max;

	error = sysctl_handle_int(oidp, &nstates, 0, req);
	/* Read operation or some error */
	if ((error != 0) || (req->newptr == NULL))
		return (error);

	V_dyn_max = nstates;
	uma_zone_set_max(V_ipfw_dyn_rule_zone, V_dyn_max);

	return (0);
}

/*
 * Get current number of dynamic states in given VNET instance.
 */
static int
sysctl_ipfw_dyn_count(SYSCTL_HANDLER_ARGS)
{
	int error;
	unsigned int nstates;

	nstates = DYN_COUNT;

	error = sysctl_handle_int(oidp, &nstates, 0, req);

	return (error);
}
#endif

/*
 * Returns size of dynamic states in legacy format
 */
int
ipfw_dyn_len(void)
{

	return (V_ipfw_dyn_v == NULL) ? 0 :
		(DYN_COUNT * sizeof(ipfw_dyn_rule));
}

/*
 * Returns number of dynamic states.
 * Used by dump format v1 (current).
 */
int
ipfw_dyn_get_count(void)
{

	return (V_ipfw_dyn_v == NULL) ? 0 : DYN_COUNT;
}

static void
export_dyn_rule(ipfw_dyn_rule *src, ipfw_dyn_rule *dst)
{
	uint16_t rulenum;

	rulenum = (uint16_t)src->rule->rulenum;
	memcpy(dst, src, sizeof(*src));
	memcpy(&dst->rule, &rulenum, sizeof(rulenum));
	/*
	 * store set number into high word of
	 * dst->rule pointer.
	 */
	memcpy((char *)&dst->rule + sizeof(rulenum), &src->rule->set,
	    sizeof(src->rule->set));
	/*
	 * store a non-null value in "next".
	 * The userland code will interpret a
	 * NULL here as a marker
	 * for the last dynamic rule.
	 */
	memcpy(&dst->next, &dst, sizeof(dst));
	dst->expire = TIME_LEQ(dst->expire, time_uptime) ?  0:
	    dst->expire - time_uptime;
}

/*
 * Fills int buffer given by @sd with dynamic states.
 * Used by dump format v1 (current).
 *
 * Returns 0 on success.
 */
int
ipfw_dump_states(struct ip_fw_chain *chain, struct sockopt_data *sd)
{
	ipfw_dyn_rule *p;
	ipfw_obj_dyntlv *dst, *last;
	ipfw_obj_ctlv *ctlv;
	int i;
	size_t sz;

	if (V_ipfw_dyn_v == NULL)
		return (0);

	IPFW_UH_RLOCK_ASSERT(chain);

	ctlv = (ipfw_obj_ctlv *)ipfw_get_sopt_space(sd, sizeof(*ctlv));
	if (ctlv == NULL)
		return (ENOMEM);
	sz = sizeof(ipfw_obj_dyntlv);
	ctlv->head.type = IPFW_TLV_DYNSTATE_LIST;
	ctlv->objsize = sz;
	last = NULL;

	for (i = 0 ; i < V_curr_dyn_buckets; i++) {
		IPFW_BUCK_LOCK(i);
		for (p = V_ipfw_dyn_v[i].head ; p != NULL; p = p->next) {
			dst = (ipfw_obj_dyntlv *)ipfw_get_sopt_space(sd, sz);
			if (dst == NULL) {
				IPFW_BUCK_UNLOCK(i);
				return (ENOMEM);
			}

			export_dyn_rule(p, &dst->state);
			dst->head.length = sz;
			dst->head.type = IPFW_TLV_DYN_ENT;
			last = dst;
		}
		IPFW_BUCK_UNLOCK(i);
	}

	if (last != NULL) /* mark last dynamic rule */
		last->head.flags = IPFW_DF_LAST;

	return (0);
}

/*
 * Fill given buffer with dynamic states (legacy format).
 * IPFW_UH_RLOCK has to be held while calling.
 */
void
ipfw_get_dynamic(struct ip_fw_chain *chain, char **pbp, const char *ep)
{
	ipfw_dyn_rule *p, *last = NULL;
	char *bp;
	int i;

	if (V_ipfw_dyn_v == NULL)
		return;
	bp = *pbp;

	IPFW_UH_RLOCK_ASSERT(chain);

	for (i = 0 ; i < V_curr_dyn_buckets; i++) {
		IPFW_BUCK_LOCK(i);
		for (p = V_ipfw_dyn_v[i].head ; p != NULL; p = p->next) {
			if (bp + sizeof *p <= ep) {
				ipfw_dyn_rule *dst =
					(ipfw_dyn_rule *)bp;

				export_dyn_rule(p, dst);
				last = dst;
				bp += sizeof(ipfw_dyn_rule);
			}
		}
		IPFW_BUCK_UNLOCK(i);
	}

	if (last != NULL) /* mark last dynamic rule */
		bzero(&last->next, sizeof(last));
	*pbp = bp;
}
/* end of file */
