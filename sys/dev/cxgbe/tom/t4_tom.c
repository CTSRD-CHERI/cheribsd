/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: Navdeep Parhar <np@FreeBSD.org>
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

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ratelimit.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/limits.h>
#include <sys/module.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/refcount.h>
#include <sys/rmlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/taskqueue.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet6/scope6_var.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <netinet/toecore.h>

#ifdef TCP_OFFLOAD
#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"
#include "common/t4_tcb.h"
#include "tom/t4_tom_l2t.h"
#include "tom/t4_tom.h"

static struct protosw toe_protosw;
static struct pr_usrreqs toe_usrreqs;

static struct protosw toe6_protosw;
static struct pr_usrreqs toe6_usrreqs;

/* Module ops */
static int t4_tom_mod_load(void);
static int t4_tom_mod_unload(void);
static int t4_tom_modevent(module_t, int, void *);

/* ULD ops and helpers */
static int t4_tom_activate(struct adapter *);
static int t4_tom_deactivate(struct adapter *);

static struct uld_info tom_uld_info = {
	.uld_id = ULD_TOM,
	.activate = t4_tom_activate,
	.deactivate = t4_tom_deactivate,
};

static void queue_tid_release(struct adapter *, int);
static void release_offload_resources(struct toepcb *);
static int alloc_tid_tabs(struct tid_info *);
static void free_tid_tabs(struct tid_info *);
static int add_lip(struct adapter *, struct in6_addr *);
static int delete_lip(struct adapter *, struct in6_addr *);
static struct clip_entry *search_lip(struct tom_data *, struct in6_addr *);
static void init_clip_table(struct adapter *, struct tom_data *);
static void update_clip(struct adapter *, void *);
static void t4_clip_task(void *, int);
static void update_clip_table(struct adapter *, struct tom_data *);
static void destroy_clip_table(struct adapter *, struct tom_data *);
static void free_tom_data(struct adapter *, struct tom_data *);
static void reclaim_wr_resources(void *, int);

static int in6_ifaddr_gen;
static eventhandler_tag ifaddr_evhandler;
static struct timeout_task clip_task;

struct toepcb *
alloc_toepcb(struct vi_info *vi, int txqid, int rxqid, int flags)
{
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	struct toepcb *toep;
	int tx_credits, txsd_total, len;

	/*
	 * The firmware counts tx work request credits in units of 16 bytes
	 * each.  Reserve room for an ABORT_REQ so the driver never has to worry
	 * about tx credits if it wants to abort a connection.
	 */
	tx_credits = sc->params.ofldq_wr_cred;
	tx_credits -= howmany(sizeof(struct cpl_abort_req), 16);

	/*
	 * Shortest possible tx work request is a fw_ofld_tx_data_wr + 1 byte
	 * immediate payload, and firmware counts tx work request credits in
	 * units of 16 byte.  Calculate the maximum work requests possible.
	 */
	txsd_total = tx_credits /
	    howmany(sizeof(struct fw_ofld_tx_data_wr) + 1, 16);

	if (txqid < 0)
		txqid = (arc4random() % vi->nofldtxq) + vi->first_ofld_txq;
	KASSERT(txqid >= vi->first_ofld_txq &&
	    txqid < vi->first_ofld_txq + vi->nofldtxq,
	    ("%s: txqid %d for vi %p (first %d, n %d)", __func__, txqid, vi,
		vi->first_ofld_txq, vi->nofldtxq));

	if (rxqid < 0)
		rxqid = (arc4random() % vi->nofldrxq) + vi->first_ofld_rxq;
	KASSERT(rxqid >= vi->first_ofld_rxq &&
	    rxqid < vi->first_ofld_rxq + vi->nofldrxq,
	    ("%s: rxqid %d for vi %p (first %d, n %d)", __func__, rxqid, vi,
		vi->first_ofld_rxq, vi->nofldrxq));

	len = offsetof(struct toepcb, txsd) +
	    txsd_total * sizeof(struct ofld_tx_sdesc);

	toep = malloc(len, M_CXGBE, M_ZERO | flags);
	if (toep == NULL)
		return (NULL);

	refcount_init(&toep->refcount, 1);
	toep->td = sc->tom_softc;
	toep->vi = vi;
	toep->tc_idx = -1;
	toep->tx_total = tx_credits;
	toep->tx_credits = tx_credits;
	toep->ofld_txq = &sc->sge.ofld_txq[txqid];
	toep->ofld_rxq = &sc->sge.ofld_rxq[rxqid];
	toep->ctrlq = &sc->sge.ctrlq[pi->port_id];
	mbufq_init(&toep->ulp_pduq, INT_MAX);
	mbufq_init(&toep->ulp_pdu_reclaimq, INT_MAX);
	toep->txsd_total = txsd_total;
	toep->txsd_avail = txsd_total;
	toep->txsd_pidx = 0;
	toep->txsd_cidx = 0;
	aiotx_init_toep(toep);
	ddp_init_toep(toep);

	return (toep);
}

struct toepcb *
hold_toepcb(struct toepcb *toep)
{

	refcount_acquire(&toep->refcount);
	return (toep);
}

void
free_toepcb(struct toepcb *toep)
{

	if (refcount_release(&toep->refcount) == 0)
		return;

	KASSERT(!(toep->flags & TPF_ATTACHED),
	    ("%s: attached to an inpcb", __func__));
	KASSERT(!(toep->flags & TPF_CPL_PENDING),
	    ("%s: CPL pending", __func__));

	ddp_uninit_toep(toep);
	free(toep, M_CXGBE);
}

/*
 * Set up the socket for TCP offload.
 */
void
offload_socket(struct socket *so, struct toepcb *toep)
{
	struct tom_data *td = toep->td;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = intotcpcb(inp);
	struct sockbuf *sb;

	INP_WLOCK_ASSERT(inp);

	/* Update socket */
	sb = &so->so_snd;
	SOCKBUF_LOCK(sb);
	sb->sb_flags |= SB_NOCOALESCE;
	SOCKBUF_UNLOCK(sb);
	sb = &so->so_rcv;
	SOCKBUF_LOCK(sb);
	sb->sb_flags |= SB_NOCOALESCE;
	if (inp->inp_vflag & INP_IPV6)
		so->so_proto = &toe6_protosw;
	else
		so->so_proto = &toe_protosw;
	SOCKBUF_UNLOCK(sb);

	/* Update TCP PCB */
	tp->tod = &td->tod;
	tp->t_toe = toep;
	tp->t_flags |= TF_TOE;

	/* Install an extra hold on inp */
	toep->inp = inp;
	toep->flags |= TPF_ATTACHED;
	in_pcbref(inp);

	/* Add the TOE PCB to the active list */
	mtx_lock(&td->toep_list_lock);
	TAILQ_INSERT_HEAD(&td->toep_list, toep, link);
	mtx_unlock(&td->toep_list_lock);
}

/* This is _not_ the normal way to "unoffload" a socket. */
void
undo_offload_socket(struct socket *so)
{
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = intotcpcb(inp);
	struct toepcb *toep = tp->t_toe;
	struct tom_data *td = toep->td;
	struct sockbuf *sb;

	INP_WLOCK_ASSERT(inp);

	sb = &so->so_snd;
	SOCKBUF_LOCK(sb);
	sb->sb_flags &= ~SB_NOCOALESCE;
	SOCKBUF_UNLOCK(sb);
	sb = &so->so_rcv;
	SOCKBUF_LOCK(sb);
	sb->sb_flags &= ~SB_NOCOALESCE;
	SOCKBUF_UNLOCK(sb);

	tp->tod = NULL;
	tp->t_toe = NULL;
	tp->t_flags &= ~TF_TOE;

	toep->inp = NULL;
	toep->flags &= ~TPF_ATTACHED;
	if (in_pcbrele_wlocked(inp))
		panic("%s: inp freed.", __func__);

	mtx_lock(&td->toep_list_lock);
	TAILQ_REMOVE(&td->toep_list, toep, link);
	mtx_unlock(&td->toep_list_lock);
}

static void
release_offload_resources(struct toepcb *toep)
{
	struct tom_data *td = toep->td;
	struct adapter *sc = td_adapter(td);
	int tid = toep->tid;

	KASSERT(!(toep->flags & TPF_CPL_PENDING),
	    ("%s: %p has CPL pending.", __func__, toep));
	KASSERT(!(toep->flags & TPF_ATTACHED),
	    ("%s: %p is still attached.", __func__, toep));

	CTR5(KTR_CXGBE, "%s: toep %p (tid %d, l2te %p, ce %p)",
	    __func__, toep, tid, toep->l2te, toep->ce);

	/*
	 * These queues should have been emptied at approximately the same time
	 * that a normal connection's socket's so_snd would have been purged or
	 * drained.  Do _not_ clean up here.
	 */
	MPASS(mbufq_len(&toep->ulp_pduq) == 0);
	MPASS(mbufq_len(&toep->ulp_pdu_reclaimq) == 0);
#ifdef INVARIANTS
	ddp_assert_empty(toep);
#endif

	if (toep->l2te)
		t4_l2t_release(toep->l2te);

	if (tid >= 0) {
		remove_tid(sc, tid, toep->ce ? 2 : 1);
		release_tid(sc, tid, toep->ctrlq);
	}

	if (toep->ce)
		release_lip(td, toep->ce);

#ifdef RATELIMIT
	if (toep->tc_idx != -1)
		t4_release_cl_rl_kbps(sc, toep->vi->pi->port_id, toep->tc_idx);
#endif
	mtx_lock(&td->toep_list_lock);
	TAILQ_REMOVE(&td->toep_list, toep, link);
	mtx_unlock(&td->toep_list_lock);

	free_toepcb(toep);
}

/*
 * The kernel is done with the TCP PCB and this is our opportunity to unhook the
 * toepcb hanging off of it.  If the TOE driver is also done with the toepcb (no
 * pending CPL) then it is time to release all resources tied to the toepcb.
 *
 * Also gets called when an offloaded active open fails and the TOM wants the
 * kernel to take the TCP PCB back.
 */
static void
t4_pcb_detach(struct toedev *tod __unused, struct tcpcb *tp)
{
#if defined(KTR) || defined(INVARIANTS)
	struct inpcb *inp = tp->t_inpcb;
#endif
	struct toepcb *toep = tp->t_toe;

	INP_WLOCK_ASSERT(inp);

	KASSERT(toep != NULL, ("%s: toep is NULL", __func__));
	KASSERT(toep->flags & TPF_ATTACHED,
	    ("%s: not attached", __func__));

#ifdef KTR
	if (tp->t_state == TCPS_SYN_SENT) {
		CTR6(KTR_CXGBE, "%s: atid %d, toep %p (0x%x), inp %p (0x%x)",
		    __func__, toep->tid, toep, toep->flags, inp,
		    inp->inp_flags);
	} else {
		CTR6(KTR_CXGBE,
		    "t4_pcb_detach: tid %d (%s), toep %p (0x%x), inp %p (0x%x)",
		    toep->tid, tcpstates[tp->t_state], toep, toep->flags, inp,
		    inp->inp_flags);
	}
#endif

	tp->t_toe = NULL;
	tp->t_flags &= ~TF_TOE;
	toep->flags &= ~TPF_ATTACHED;

	if (!(toep->flags & TPF_CPL_PENDING))
		release_offload_resources(toep);
}

/*
 * setsockopt handler.
 */
static void
t4_ctloutput(struct toedev *tod, struct tcpcb *tp, int dir, int name)
{
	struct adapter *sc = tod->tod_softc;
	struct toepcb *toep = tp->t_toe;

	if (dir == SOPT_GET)
		return;

	CTR4(KTR_CXGBE, "%s: tp %p, dir %u, name %u", __func__, tp, dir, name);

	switch (name) {
	case TCP_NODELAY:
		if (tp->t_state != TCPS_ESTABLISHED)
			break;
		t4_set_tcb_field(sc, toep->ctrlq, toep->tid, W_TCB_T_FLAGS,
		    V_TF_NAGLE(1), V_TF_NAGLE(tp->t_flags & TF_NODELAY ? 0 : 1),
		    0, 0, toep->ofld_rxq->iq.abs_id);
		break;
	default:
		break;
	}
}

/*
 * The TOE driver will not receive any more CPLs for the tid associated with the
 * toepcb; release the hold on the inpcb.
 */
void
final_cpl_received(struct toepcb *toep)
{
	struct inpcb *inp = toep->inp;

	KASSERT(inp != NULL, ("%s: inp is NULL", __func__));
	INP_WLOCK_ASSERT(inp);
	KASSERT(toep->flags & TPF_CPL_PENDING,
	    ("%s: CPL not pending already?", __func__));

	CTR6(KTR_CXGBE, "%s: tid %d, toep %p (0x%x), inp %p (0x%x)",
	    __func__, toep->tid, toep, toep->flags, inp, inp->inp_flags);

	if (toep->ulp_mode == ULP_MODE_TCPDDP)
		release_ddp_resources(toep);
	toep->inp = NULL;
	toep->flags &= ~TPF_CPL_PENDING;
	mbufq_drain(&toep->ulp_pdu_reclaimq);

	if (!(toep->flags & TPF_ATTACHED))
		release_offload_resources(toep);

	if (!in_pcbrele_wlocked(inp))
		INP_WUNLOCK(inp);
}

void
insert_tid(struct adapter *sc, int tid, void *ctx, int ntids)
{
	struct tid_info *t = &sc->tids;

	t->tid_tab[tid] = ctx;
	atomic_add_int(&t->tids_in_use, ntids);
}

void *
lookup_tid(struct adapter *sc, int tid)
{
	struct tid_info *t = &sc->tids;

	return (t->tid_tab[tid]);
}

void
update_tid(struct adapter *sc, int tid, void *ctx)
{
	struct tid_info *t = &sc->tids;

	t->tid_tab[tid] = ctx;
}

void
remove_tid(struct adapter *sc, int tid, int ntids)
{
	struct tid_info *t = &sc->tids;

	t->tid_tab[tid] = NULL;
	atomic_subtract_int(&t->tids_in_use, ntids);
}

void
release_tid(struct adapter *sc, int tid, struct sge_wrq *ctrlq)
{
	struct wrqe *wr;
	struct cpl_tid_release *req;

	wr = alloc_wrqe(sizeof(*req), ctrlq);
	if (wr == NULL) {
		queue_tid_release(sc, tid);	/* defer */
		return;
	}
	req = wrtod(wr);

	INIT_TP_WR_MIT_CPL(req, CPL_TID_RELEASE, tid);

	t4_wrq_tx(sc, wr);
}

static void
queue_tid_release(struct adapter *sc, int tid)
{

	CXGBE_UNIMPLEMENTED("deferred tid release");
}

/*
 * What mtu_idx to use, given a 4-tuple and/or an MSS cap
 */
int
find_best_mtu_idx(struct adapter *sc, struct in_conninfo *inc, int pmss)
{
	unsigned short *mtus = &sc->params.mtus[0];
	int i, mss, n;

	KASSERT(inc != NULL || pmss > 0,
	    ("%s: at least one of inc/pmss must be specified", __func__));

	mss = inc ? tcp_mssopt(inc) : pmss;
	if (pmss > 0 && mss > pmss)
		mss = pmss;

	if (inc->inc_flags & INC_ISIPV6)
		n = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	else
		n = sizeof(struct ip) + sizeof(struct tcphdr);

	for (i = 0; i < NMTUS - 1 && mtus[i + 1] <= mss + n; i++)
		continue;

	return (i);
}

/*
 * Determine the receive window size for a socket.
 */
u_long
select_rcv_wnd(struct socket *so)
{
	unsigned long wnd;

	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	wnd = sbspace(&so->so_rcv);
	if (wnd < MIN_RCV_WND)
		wnd = MIN_RCV_WND;

	return min(wnd, MAX_RCV_WND);
}

int
select_rcv_wscale(void)
{
	int wscale = 0;
	unsigned long space = sb_max;

	if (space > MAX_RCV_WND)
		space = MAX_RCV_WND;

	while (wscale < TCP_MAX_WINSHIFT && (TCP_MAXWIN << wscale) < space)
		wscale++;

	return (wscale);
}

extern int always_keepalive;

/*
 * socket so could be a listening socket too.
 */
uint64_t
calc_opt0(struct socket *so, struct vi_info *vi, struct l2t_entry *e,
    int mtu_idx, int rscale, int rx_credits, int ulp_mode)
{
	uint64_t opt0;

	KASSERT(rx_credits <= M_RCV_BUFSIZ,
	    ("%s: rcv_bufsiz too high", __func__));

	opt0 = F_TCAM_BYPASS | V_WND_SCALE(rscale) | V_MSS_IDX(mtu_idx) |
	    V_ULP_MODE(ulp_mode) | V_RCV_BUFSIZ(rx_credits);

	if (so != NULL) {
		struct inpcb *inp = sotoinpcb(so);
		struct tcpcb *tp = intotcpcb(inp);
		int keepalive = always_keepalive ||
		    so_options_get(so) & SO_KEEPALIVE;

		opt0 |= V_NAGLE((tp->t_flags & TF_NODELAY) == 0);
		opt0 |= V_KEEP_ALIVE(keepalive != 0);
	}

	if (e != NULL)
		opt0 |= V_L2T_IDX(e->idx);

	if (vi != NULL) {
		opt0 |= V_SMAC_SEL(vi->smt_idx);
		opt0 |= V_TX_CHAN(vi->pi->tx_chan);
	}

	return htobe64(opt0);
}

uint64_t
select_ntuple(struct vi_info *vi, struct l2t_entry *e)
{
	struct adapter *sc = vi->pi->adapter;
	struct tp_params *tp = &sc->params.tp;
	uint16_t viid = vi->viid;
	uint64_t ntuple = 0;

	/*
	 * Initialize each of the fields which we care about which are present
	 * in the Compressed Filter Tuple.
	 */
	if (tp->vlan_shift >= 0 && e->vlan != CPL_L2T_VLAN_NONE)
		ntuple |= (uint64_t)(F_FT_VLAN_VLD | e->vlan) << tp->vlan_shift;

	if (tp->port_shift >= 0)
		ntuple |= (uint64_t)e->lport << tp->port_shift;

	if (tp->protocol_shift >= 0)
		ntuple |= (uint64_t)IPPROTO_TCP << tp->protocol_shift;

	if (tp->vnic_shift >= 0) {
		uint32_t vf = G_FW_VIID_VIN(viid);
		uint32_t pf = G_FW_VIID_PFN(viid);
		uint32_t vld = G_FW_VIID_VIVLD(viid);

		ntuple |= (uint64_t)(V_FT_VNID_ID_VF(vf) | V_FT_VNID_ID_PF(pf) |
		    V_FT_VNID_ID_VLD(vld)) << tp->vnic_shift;
	}

	if (is_t4(sc))
		return (htobe32((uint32_t)ntuple));
	else
		return (htobe64(V_FILTER_TUPLE(ntuple)));
}

void
set_tcpddp_ulp_mode(struct toepcb *toep)
{

	toep->ulp_mode = ULP_MODE_TCPDDP;
	toep->ddp_flags = DDP_OK;
}

int
negative_advice(int status)
{

	return (status == CPL_ERR_RTX_NEG_ADVICE ||
	    status == CPL_ERR_PERSIST_NEG_ADVICE ||
	    status == CPL_ERR_KEEPALV_NEG_ADVICE);
}

static int
alloc_tid_tabs(struct tid_info *t)
{
	size_t size;
	unsigned int i;

	size = t->ntids * sizeof(*t->tid_tab) +
	    t->natids * sizeof(*t->atid_tab) +
	    t->nstids * sizeof(*t->stid_tab);

	t->tid_tab = malloc(size, M_CXGBE, M_ZERO | M_NOWAIT);
	if (t->tid_tab == NULL)
		return (ENOMEM);

	mtx_init(&t->atid_lock, "atid lock", NULL, MTX_DEF);
	t->atid_tab = (union aopen_entry *)&t->tid_tab[t->ntids];
	t->afree = t->atid_tab;
	t->atids_in_use = 0;
	for (i = 1; i < t->natids; i++)
		t->atid_tab[i - 1].next = &t->atid_tab[i];
	t->atid_tab[t->natids - 1].next = NULL;

	mtx_init(&t->stid_lock, "stid lock", NULL, MTX_DEF);
	t->stid_tab = (struct listen_ctx **)&t->atid_tab[t->natids];
	t->stids_in_use = 0;
	TAILQ_INIT(&t->stids);
	t->nstids_free_head = t->nstids;

	atomic_store_rel_int(&t->tids_in_use, 0);

	return (0);
}

static void
free_tid_tabs(struct tid_info *t)
{
	KASSERT(t->tids_in_use == 0,
	    ("%s: %d tids still in use.", __func__, t->tids_in_use));
	KASSERT(t->atids_in_use == 0,
	    ("%s: %d atids still in use.", __func__, t->atids_in_use));
	KASSERT(t->stids_in_use == 0,
	    ("%s: %d tids still in use.", __func__, t->stids_in_use));

	free(t->tid_tab, M_CXGBE);
	t->tid_tab = NULL;

	if (mtx_initialized(&t->atid_lock))
		mtx_destroy(&t->atid_lock);
	if (mtx_initialized(&t->stid_lock))
		mtx_destroy(&t->stid_lock);
}

static int
add_lip(struct adapter *sc, struct in6_addr *lip)
{
        struct fw_clip_cmd c;

	ASSERT_SYNCHRONIZED_OP(sc);
	/* mtx_assert(&td->clip_table_lock, MA_OWNED); */

        memset(&c, 0, sizeof(c));
	c.op_to_write = htonl(V_FW_CMD_OP(FW_CLIP_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE);
        c.alloc_to_len16 = htonl(F_FW_CLIP_CMD_ALLOC | FW_LEN16(c));
        c.ip_hi = *(uint64_t *)&lip->s6_addr[0];
        c.ip_lo = *(uint64_t *)&lip->s6_addr[8];

	return (-t4_wr_mbox_ns(sc, sc->mbox, &c, sizeof(c), &c));
}

static int
delete_lip(struct adapter *sc, struct in6_addr *lip)
{
	struct fw_clip_cmd c;

	ASSERT_SYNCHRONIZED_OP(sc);
	/* mtx_assert(&td->clip_table_lock, MA_OWNED); */

	memset(&c, 0, sizeof(c));
	c.op_to_write = htonl(V_FW_CMD_OP(FW_CLIP_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_READ);
        c.alloc_to_len16 = htonl(F_FW_CLIP_CMD_FREE | FW_LEN16(c));
        c.ip_hi = *(uint64_t *)&lip->s6_addr[0];
        c.ip_lo = *(uint64_t *)&lip->s6_addr[8];

	return (-t4_wr_mbox_ns(sc, sc->mbox, &c, sizeof(c), &c));
}

static struct clip_entry *
search_lip(struct tom_data *td, struct in6_addr *lip)
{
	struct clip_entry *ce;

	mtx_assert(&td->clip_table_lock, MA_OWNED);

	TAILQ_FOREACH(ce, &td->clip_table, link) {
		if (IN6_ARE_ADDR_EQUAL(&ce->lip, lip))
			return (ce);
	}

	return (NULL);
}

struct clip_entry *
hold_lip(struct tom_data *td, struct in6_addr *lip, struct clip_entry *ce)
{

	mtx_lock(&td->clip_table_lock);
	if (ce == NULL)
		ce = search_lip(td, lip);
	if (ce != NULL)
		ce->refcount++;
	mtx_unlock(&td->clip_table_lock);

	return (ce);
}

void
release_lip(struct tom_data *td, struct clip_entry *ce)
{

	mtx_lock(&td->clip_table_lock);
	KASSERT(search_lip(td, &ce->lip) == ce,
	    ("%s: CLIP entry %p p not in CLIP table.", __func__, ce));
	KASSERT(ce->refcount > 0,
	    ("%s: CLIP entry %p has refcount 0", __func__, ce));
	--ce->refcount;
	mtx_unlock(&td->clip_table_lock);
}

static void
init_clip_table(struct adapter *sc, struct tom_data *td)
{

	ASSERT_SYNCHRONIZED_OP(sc);

	mtx_init(&td->clip_table_lock, "CLIP table lock", NULL, MTX_DEF);
	TAILQ_INIT(&td->clip_table);
	td->clip_gen = -1;

	update_clip_table(sc, td);
}

static void
update_clip(struct adapter *sc, void *arg __unused)
{

	if (begin_synchronized_op(sc, NULL, HOLD_LOCK, "t4tomuc"))
		return;

	if (uld_active(sc, ULD_TOM))
		update_clip_table(sc, sc->tom_softc);

	end_synchronized_op(sc, LOCK_HELD);
}

static void
t4_clip_task(void *arg, int count)
{

	t4_iterate(update_clip, NULL);
}

static void
update_clip_table(struct adapter *sc, struct tom_data *td)
{
	struct rm_priotracker in6_ifa_tracker;
	struct in6_ifaddr *ia;
	struct in6_addr *lip, tlip;
	struct clip_head stale;
	struct clip_entry *ce, *ce_temp;
	struct vi_info *vi;
	int rc, gen, i, j;
	uintptr_t last_vnet;

	ASSERT_SYNCHRONIZED_OP(sc);

	IN6_IFADDR_RLOCK(&in6_ifa_tracker);
	mtx_lock(&td->clip_table_lock);

	gen = atomic_load_acq_int(&in6_ifaddr_gen);
	if (gen == td->clip_gen)
		goto done;

	TAILQ_INIT(&stale);
	TAILQ_CONCAT(&stale, &td->clip_table, link);

	/*
	 * last_vnet optimizes the common cases where all if_vnet = NULL (no
	 * VIMAGE) or all if_vnet = vnet0.
	 */
	last_vnet = (uintptr_t)(-1);
	for_each_port(sc, i)
	for_each_vi(sc->port[i], j, vi) {
		if (last_vnet == (uintptr_t)vi->ifp->if_vnet)
			continue;

		/* XXX: races with if_vmove */
		CURVNET_SET(vi->ifp->if_vnet);
		TAILQ_FOREACH(ia, &V_in6_ifaddrhead, ia_link) {
			lip = &ia->ia_addr.sin6_addr;

			KASSERT(!IN6_IS_ADDR_MULTICAST(lip),
			    ("%s: mcast address in in6_ifaddr list", __func__));

			if (IN6_IS_ADDR_LOOPBACK(lip))
				continue;
			if (IN6_IS_SCOPE_EMBED(lip)) {
				/* Remove the embedded scope */
				tlip = *lip;
				lip = &tlip;
				in6_clearscope(lip);
			}
			/*
			 * XXX: how to weed out the link local address for the
			 * loopback interface?  It's fe80::1 usually (always?).
			 */

			/*
			 * If it's in the main list then we already know it's
			 * not stale.
			 */
			TAILQ_FOREACH(ce, &td->clip_table, link) {
				if (IN6_ARE_ADDR_EQUAL(&ce->lip, lip))
					goto next;
			}

			/*
			 * If it's in the stale list we should move it to the
			 * main list.
			 */
			TAILQ_FOREACH(ce, &stale, link) {
				if (IN6_ARE_ADDR_EQUAL(&ce->lip, lip)) {
					TAILQ_REMOVE(&stale, ce, link);
					TAILQ_INSERT_TAIL(&td->clip_table, ce,
					    link);
					goto next;
				}
			}

			/* A new IP6 address; add it to the CLIP table */
			ce = malloc(sizeof(*ce), M_CXGBE, M_NOWAIT);
			memcpy(&ce->lip, lip, sizeof(ce->lip));
			ce->refcount = 0;
			rc = add_lip(sc, lip);
			if (rc == 0)
				TAILQ_INSERT_TAIL(&td->clip_table, ce, link);
			else {
				char ip[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, &ce->lip, &ip[0],
				    sizeof(ip));
				log(LOG_ERR, "%s: could not add %s (%d)\n",
				    __func__, ip, rc);
				free(ce, M_CXGBE);
			}
next:
			continue;
		}
		CURVNET_RESTORE();
		last_vnet = (uintptr_t)vi->ifp->if_vnet;
	}

	/*
	 * Remove stale addresses (those no longer in V_in6_ifaddrhead) that are
	 * no longer referenced by the driver.
	 */
	TAILQ_FOREACH_SAFE(ce, &stale, link, ce_temp) {
		if (ce->refcount == 0) {
			rc = delete_lip(sc, &ce->lip);
			if (rc == 0) {
				TAILQ_REMOVE(&stale, ce, link);
				free(ce, M_CXGBE);
			} else {
				char ip[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, &ce->lip, &ip[0],
				    sizeof(ip));
				log(LOG_ERR, "%s: could not delete %s (%d)\n",
				    __func__, ip, rc);
			}
		}
	}
	/* The ones that are still referenced need to stay in the CLIP table */
	TAILQ_CONCAT(&td->clip_table, &stale, link);

	td->clip_gen = gen;
done:
	mtx_unlock(&td->clip_table_lock);
	IN6_IFADDR_RUNLOCK(&in6_ifa_tracker);
}

static void
destroy_clip_table(struct adapter *sc, struct tom_data *td)
{
	struct clip_entry *ce, *ce_temp;

	if (mtx_initialized(&td->clip_table_lock)) {
		mtx_lock(&td->clip_table_lock);
		TAILQ_FOREACH_SAFE(ce, &td->clip_table, link, ce_temp) {
			KASSERT(ce->refcount == 0,
			    ("%s: CLIP entry %p still in use (%d)", __func__,
			    ce, ce->refcount));
			TAILQ_REMOVE(&td->clip_table, ce, link);
			delete_lip(sc, &ce->lip);
			free(ce, M_CXGBE);
		}
		mtx_unlock(&td->clip_table_lock);
		mtx_destroy(&td->clip_table_lock);
	}
}

static void
free_tom_data(struct adapter *sc, struct tom_data *td)
{

	ASSERT_SYNCHRONIZED_OP(sc);

	KASSERT(TAILQ_EMPTY(&td->toep_list),
	    ("%s: TOE PCB list is not empty.", __func__));
	KASSERT(td->lctx_count == 0,
	    ("%s: lctx hash table is not empty.", __func__));

	t4_free_ppod_region(&td->pr);
	destroy_clip_table(sc, td);

	if (td->listen_mask != 0)
		hashdestroy(td->listen_hash, M_CXGBE, td->listen_mask);

	if (mtx_initialized(&td->unsent_wr_lock))
		mtx_destroy(&td->unsent_wr_lock);
	if (mtx_initialized(&td->lctx_hash_lock))
		mtx_destroy(&td->lctx_hash_lock);
	if (mtx_initialized(&td->toep_list_lock))
		mtx_destroy(&td->toep_list_lock);

	free_tid_tabs(&sc->tids);
	free(td, M_CXGBE);
}

static void
reclaim_wr_resources(void *arg, int count)
{
	struct tom_data *td = arg;
	STAILQ_HEAD(, wrqe) twr_list = STAILQ_HEAD_INITIALIZER(twr_list);
	struct cpl_act_open_req *cpl;
	u_int opcode, atid;
	struct wrqe *wr;
	struct adapter *sc;

	mtx_lock(&td->unsent_wr_lock);
	STAILQ_SWAP(&td->unsent_wr_list, &twr_list, wrqe);
	mtx_unlock(&td->unsent_wr_lock);

	while ((wr = STAILQ_FIRST(&twr_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&twr_list, link);

		cpl = wrtod(wr);
		opcode = GET_OPCODE(cpl);

		switch (opcode) {
		case CPL_ACT_OPEN_REQ:
		case CPL_ACT_OPEN_REQ6:
			atid = G_TID_TID(be32toh(OPCODE_TID(cpl)));
			sc = td_adapter(td);

			CTR2(KTR_CXGBE, "%s: atid %u ", __func__, atid);
			act_open_failure_cleanup(sc, atid, EHOSTUNREACH);
			free(wr, M_CXGBE);
			break;
		default:
			log(LOG_ERR, "%s: leaked work request %p, wr_len %d, "
			    "opcode %x\n", __func__, wr, wr->wr_len, opcode);
			/* WR not freed here; go look at it with a debugger.  */
		}
	}
}

/*
 * Ground control to Major TOM
 * Commencing countdown, engines on
 */
static int
t4_tom_activate(struct adapter *sc)
{
	struct tom_data *td;
	struct toedev *tod;
	struct vi_info *vi;
	struct sge_ofld_rxq *ofld_rxq;
	int i, j, rc, v;

	ASSERT_SYNCHRONIZED_OP(sc);

	/* per-adapter softc for TOM */
	td = malloc(sizeof(*td), M_CXGBE, M_ZERO | M_NOWAIT);
	if (td == NULL)
		return (ENOMEM);

	/* List of TOE PCBs and associated lock */
	mtx_init(&td->toep_list_lock, "PCB list lock", NULL, MTX_DEF);
	TAILQ_INIT(&td->toep_list);

	/* Listen context */
	mtx_init(&td->lctx_hash_lock, "lctx hash lock", NULL, MTX_DEF);
	td->listen_hash = hashinit_flags(LISTEN_HASH_SIZE, M_CXGBE,
	    &td->listen_mask, HASH_NOWAIT);

	/* List of WRs for which L2 resolution failed */
	mtx_init(&td->unsent_wr_lock, "Unsent WR list lock", NULL, MTX_DEF);
	STAILQ_INIT(&td->unsent_wr_list);
	TASK_INIT(&td->reclaim_wr_resources, 0, reclaim_wr_resources, td);

	/* TID tables */
	rc = alloc_tid_tabs(&sc->tids);
	if (rc != 0)
		goto done;

	rc = t4_init_ppod_region(&td->pr, &sc->vres.ddp,
	    t4_read_reg(sc, A_ULP_RX_TDDP_PSZ), "TDDP page pods");
	if (rc != 0)
		goto done;
	t4_set_reg_field(sc, A_ULP_RX_TDDP_TAGMASK,
	    V_TDDPTAGMASK(M_TDDPTAGMASK), td->pr.pr_tag_mask);

	/* CLIP table for IPv6 offload */
	init_clip_table(sc, td);

	/* toedev ops */
	tod = &td->tod;
	init_toedev(tod);
	tod->tod_softc = sc;
	tod->tod_connect = t4_connect;
	tod->tod_listen_start = t4_listen_start;
	tod->tod_listen_stop = t4_listen_stop;
	tod->tod_rcvd = t4_rcvd;
	tod->tod_output = t4_tod_output;
	tod->tod_send_rst = t4_send_rst;
	tod->tod_send_fin = t4_send_fin;
	tod->tod_pcb_detach = t4_pcb_detach;
	tod->tod_l2_update = t4_l2_update;
	tod->tod_syncache_added = t4_syncache_added;
	tod->tod_syncache_removed = t4_syncache_removed;
	tod->tod_syncache_respond = t4_syncache_respond;
	tod->tod_offload_socket = t4_offload_socket;
	tod->tod_ctloutput = t4_ctloutput;

	for_each_port(sc, i) {
		for_each_vi(sc->port[i], v, vi) {
			TOEDEV(vi->ifp) = &td->tod;
			for_each_ofld_rxq(vi, j, ofld_rxq) {
				ofld_rxq->iq.set_tcb_rpl = do_set_tcb_rpl;
				ofld_rxq->iq.l2t_write_rpl = do_l2t_write_rpl2;
			}
		}
	}

	sc->tom_softc = td;
	register_toedev(sc->tom_softc);

done:
	if (rc != 0)
		free_tom_data(sc, td);
	return (rc);
}

static int
t4_tom_deactivate(struct adapter *sc)
{
	int rc = 0;
	struct tom_data *td = sc->tom_softc;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (td == NULL)
		return (0);	/* XXX. KASSERT? */

	if (sc->offload_map != 0)
		return (EBUSY);	/* at least one port has IFCAP_TOE enabled */

	if (uld_active(sc, ULD_IWARP) || uld_active(sc, ULD_ISCSI))
		return (EBUSY);	/* both iWARP and iSCSI rely on the TOE. */

	mtx_lock(&td->toep_list_lock);
	if (!TAILQ_EMPTY(&td->toep_list))
		rc = EBUSY;
	mtx_unlock(&td->toep_list_lock);

	mtx_lock(&td->lctx_hash_lock);
	if (td->lctx_count > 0)
		rc = EBUSY;
	mtx_unlock(&td->lctx_hash_lock);

	taskqueue_drain(taskqueue_thread, &td->reclaim_wr_resources);
	mtx_lock(&td->unsent_wr_lock);
	if (!STAILQ_EMPTY(&td->unsent_wr_list))
		rc = EBUSY;
	mtx_unlock(&td->unsent_wr_lock);

	if (rc == 0) {
		unregister_toedev(sc->tom_softc);
		free_tom_data(sc, td);
		sc->tom_softc = NULL;
	}

	return (rc);
}

static void
t4_tom_ifaddr_event(void *arg __unused, struct ifnet *ifp)
{

	atomic_add_rel_int(&in6_ifaddr_gen, 1);
	taskqueue_enqueue_timeout(taskqueue_thread, &clip_task, -hz / 4);
}

static int
t4_aio_queue_tom(struct socket *so, struct kaiocb *job)
{
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	int error;

	if (toep->ulp_mode == ULP_MODE_TCPDDP) {
		error = t4_aio_queue_ddp(so, job);
		if (error != EOPNOTSUPP)
			return (error);
	}

	return (t4_aio_queue_aiotx(so, job));
}

static int
t4_tom_mod_load(void)
{
	int rc;
	struct protosw *tcp_protosw, *tcp6_protosw;

	/* CPL handlers */
	t4_init_connect_cpl_handlers();
	t4_init_listen_cpl_handlers();
	t4_init_cpl_io_handlers();

	rc = t4_ddp_mod_load();
	if (rc != 0)
		return (rc);

	tcp_protosw = pffindproto(PF_INET, IPPROTO_TCP, SOCK_STREAM);
	if (tcp_protosw == NULL)
		return (ENOPROTOOPT);
	bcopy(tcp_protosw, &toe_protosw, sizeof(toe_protosw));
	bcopy(tcp_protosw->pr_usrreqs, &toe_usrreqs, sizeof(toe_usrreqs));
	toe_usrreqs.pru_aio_queue = t4_aio_queue_tom;
	toe_protosw.pr_usrreqs = &toe_usrreqs;

	tcp6_protosw = pffindproto(PF_INET6, IPPROTO_TCP, SOCK_STREAM);
	if (tcp6_protosw == NULL)
		return (ENOPROTOOPT);
	bcopy(tcp6_protosw, &toe6_protosw, sizeof(toe6_protosw));
	bcopy(tcp6_protosw->pr_usrreqs, &toe6_usrreqs, sizeof(toe6_usrreqs));
	toe6_usrreqs.pru_aio_queue = t4_aio_queue_tom;
	toe6_protosw.pr_usrreqs = &toe6_usrreqs;

	TIMEOUT_TASK_INIT(taskqueue_thread, &clip_task, 0, t4_clip_task, NULL);
	ifaddr_evhandler = EVENTHANDLER_REGISTER(ifaddr_event,
	    t4_tom_ifaddr_event, NULL, EVENTHANDLER_PRI_ANY);

	rc = t4_register_uld(&tom_uld_info);
	if (rc != 0)
		t4_tom_mod_unload();

	return (rc);
}

static void
tom_uninit(struct adapter *sc, void *arg __unused)
{
	if (begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4tomun"))
		return;

	/* Try to free resources (works only if no port has IFCAP_TOE) */
	if (uld_active(sc, ULD_TOM))
		t4_deactivate_uld(sc, ULD_TOM);

	end_synchronized_op(sc, 0);
}

static int
t4_tom_mod_unload(void)
{
	t4_iterate(tom_uninit, NULL);

	if (t4_unregister_uld(&tom_uld_info) == EBUSY)
		return (EBUSY);

	if (ifaddr_evhandler) {
		EVENTHANDLER_DEREGISTER(ifaddr_event, ifaddr_evhandler);
		taskqueue_cancel_timeout(taskqueue_thread, &clip_task, NULL);
	}

	t4_ddp_mod_unload();

	t4_uninit_connect_cpl_handlers();
	t4_uninit_listen_cpl_handlers();
	t4_uninit_cpl_io_handlers();

	return (0);
}
#endif	/* TCP_OFFLOAD */

static int
t4_tom_modevent(module_t mod, int cmd, void *arg)
{
	int rc = 0;

#ifdef TCP_OFFLOAD
	switch (cmd) {
	case MOD_LOAD:
		rc = t4_tom_mod_load();
		break;

	case MOD_UNLOAD:
		rc = t4_tom_mod_unload();
		break;

	default:
		rc = EINVAL;
	}
#else
	printf("t4_tom: compiled without TCP_OFFLOAD support.\n");
	rc = EOPNOTSUPP;
#endif
	return (rc);
}

static moduledata_t t4_tom_moddata= {
	"t4_tom",
	t4_tom_modevent,
	0
};

MODULE_VERSION(t4_tom, 1);
MODULE_DEPEND(t4_tom, toecore, 1, 1, 1);
MODULE_DEPEND(t4_tom, t4nex, 1, 1, 1);
DECLARE_MODULE(t4_tom, t4_tom_moddata, SI_SUB_EXEC, SI_ORDER_ANY);
