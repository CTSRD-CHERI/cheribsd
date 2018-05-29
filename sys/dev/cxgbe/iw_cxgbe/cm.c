/*
 * Copyright (c) 2009-2013, 2016 Chelsio, Inc. All rights reserved.
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
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"

#ifdef TCP_OFFLOAD
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/taskqueue.h>
#include <netinet/in.h>
#include <net/route.h>

#include <netinet/in_systm.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/in_fib.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>

#include <netinet/toecore.h>

struct sge_iq;
struct rss_header;
struct cpl_set_tcb_rpl;
#include <linux/types.h>
#include "offload.h"
#include "tom/t4_tom.h"

#define TOEPCB(so)  ((struct toepcb *)(so_sototcpcb((so))->t_toe))

#include "iw_cxgbe.h"
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>
#include <net/netevent.h>

static spinlock_t req_lock;
static TAILQ_HEAD(c4iw_ep_list, c4iw_ep_common) req_list;
static struct work_struct c4iw_task;
static struct workqueue_struct *c4iw_taskq;
static LIST_HEAD(err_cqe_list);
static spinlock_t err_cqe_lock;

static void process_req(struct work_struct *ctx);
static void start_ep_timer(struct c4iw_ep *ep);
static int stop_ep_timer(struct c4iw_ep *ep);
static int set_tcpinfo(struct c4iw_ep *ep);
static void process_timeout(struct c4iw_ep *ep);
static void process_err_cqes(void);
static enum c4iw_ep_state state_read(struct c4iw_ep_common *epc);
static void __state_set(struct c4iw_ep_common *epc, enum c4iw_ep_state tostate);
static void state_set(struct c4iw_ep_common *epc, enum c4iw_ep_state tostate);
static void *alloc_ep(int size, gfp_t flags);
static int find_route(__be32 local_ip, __be32 peer_ip, __be16 local_port,
		__be16 peer_port, u8 tos, struct nhop4_extended *pnh4);
static void close_socket(struct socket *so);
static int send_mpa_req(struct c4iw_ep *ep);
static int send_mpa_reject(struct c4iw_ep *ep, const void *pdata, u8 plen);
static int send_mpa_reply(struct c4iw_ep *ep, const void *pdata, u8 plen);
static void close_complete_upcall(struct c4iw_ep *ep, int status);
static int send_abort(struct c4iw_ep *ep);
static void peer_close_upcall(struct c4iw_ep *ep);
static void peer_abort_upcall(struct c4iw_ep *ep);
static void connect_reply_upcall(struct c4iw_ep *ep, int status);
static int connect_request_upcall(struct c4iw_ep *ep);
static void established_upcall(struct c4iw_ep *ep);
static int process_mpa_reply(struct c4iw_ep *ep);
static int process_mpa_request(struct c4iw_ep *ep);
static void process_peer_close(struct c4iw_ep *ep);
static void process_conn_error(struct c4iw_ep *ep);
static void process_close_complete(struct c4iw_ep *ep);
static void ep_timeout(unsigned long arg);
static void init_iwarp_socket(struct socket *so, void *arg);
static void uninit_iwarp_socket(struct socket *so);
static void process_data(struct c4iw_ep *ep);
static void process_connected(struct c4iw_ep *ep);
static int c4iw_so_upcall(struct socket *so, void *arg, int waitflag);
static void process_socket_event(struct c4iw_ep *ep);
static void release_ep_resources(struct c4iw_ep *ep);
static int process_terminate(struct c4iw_ep *ep);
static int terminate(struct sge_iq *iq, const struct rss_header *rss,
    struct mbuf *m);
static int add_ep_to_req_list(struct c4iw_ep *ep, int ep_events);
#define START_EP_TIMER(ep) \
    do { \
	    CTR3(KTR_IW_CXGBE, "start_ep_timer (%s:%d) ep %p", \
		__func__, __LINE__, (ep)); \
	    start_ep_timer(ep); \
    } while (0)

#define STOP_EP_TIMER(ep) \
    ({ \
	    CTR3(KTR_IW_CXGBE, "stop_ep_timer (%s:%d) ep %p", \
		__func__, __LINE__, (ep)); \
	    stop_ep_timer(ep); \
    })

#ifdef KTR
static char *states[] = {
	"idle",
	"listen",
	"connecting",
	"mpa_wait_req",
	"mpa_req_sent",
	"mpa_req_rcvd",
	"mpa_rep_sent",
	"fpdu_mode",
	"aborting",
	"closing",
	"moribund",
	"dead",
	NULL,
};
#endif


static void deref_cm_id(struct c4iw_ep_common *epc)
{
      epc->cm_id->rem_ref(epc->cm_id);
      epc->cm_id = NULL;
      set_bit(CM_ID_DEREFED, &epc->history);
}

static void ref_cm_id(struct c4iw_ep_common *epc)
{
      set_bit(CM_ID_REFED, &epc->history);
      epc->cm_id->add_ref(epc->cm_id);
}

static void deref_qp(struct c4iw_ep *ep)
{
	c4iw_qp_rem_ref(&ep->com.qp->ibqp);
	clear_bit(QP_REFERENCED, &ep->com.flags);
	set_bit(QP_DEREFED, &ep->com.history);
}

static void ref_qp(struct c4iw_ep *ep)
{
	set_bit(QP_REFERENCED, &ep->com.flags);
	set_bit(QP_REFED, &ep->com.history);
	c4iw_qp_add_ref(&ep->com.qp->ibqp);
}

static void process_timeout(struct c4iw_ep *ep)
{
	struct c4iw_qp_attributes attrs;
	int abort = 1;

	mutex_lock(&ep->com.mutex);
	CTR4(KTR_IW_CXGBE, "%s ep :%p, tid:%u, state %d", __func__,
			ep, ep->hwtid, ep->com.state);
	set_bit(TIMEDOUT, &ep->com.history);
	switch (ep->com.state) {
	case MPA_REQ_SENT:
		connect_reply_upcall(ep, -ETIMEDOUT);
		break;
	case MPA_REQ_WAIT:
	case MPA_REQ_RCVD:
	case MPA_REP_SENT:
	case FPDU_MODE:
		break;
	case CLOSING:
	case MORIBUND:
		if (ep->com.cm_id && ep->com.qp) {
			attrs.next_state = C4IW_QP_STATE_ERROR;
			c4iw_modify_qp(ep->com.dev, ep->com.qp,
					C4IW_QP_ATTR_NEXT_STATE, &attrs, 1);
		}
		close_complete_upcall(ep, -ETIMEDOUT);
		break;
	case ABORTING:
	case DEAD:
		/*
		 * These states are expected if the ep timed out at the same
		 * time as another thread was calling stop_ep_timer().
		 * So we silently do nothing for these states.
		 */
		abort = 0;
		break;
	default:
		CTR4(KTR_IW_CXGBE, "%s unexpected state ep %p tid %u state %u\n"
				, __func__, ep, ep->hwtid, ep->com.state);
		abort = 0;
	}
	mutex_unlock(&ep->com.mutex);
	if (abort)
		c4iw_ep_disconnect(ep, 1, GFP_KERNEL);
	c4iw_put_ep(&ep->com);
	return;
}

struct cqe_list_entry {
	struct list_head entry;
	struct c4iw_dev *rhp;
	struct t4_cqe err_cqe;
};

static void
process_err_cqes(void)
{
	unsigned long flag;
	struct cqe_list_entry *cle;

	spin_lock_irqsave(&err_cqe_lock, flag);
	while (!list_empty(&err_cqe_list)) {
		struct list_head *tmp;
		tmp = err_cqe_list.next;
		list_del(tmp);
		tmp->next = tmp->prev = NULL;
		spin_unlock_irqrestore(&err_cqe_lock, flag);
		cle = list_entry(tmp, struct cqe_list_entry, entry);
		c4iw_ev_dispatch(cle->rhp, &cle->err_cqe);
		free(cle, M_CXGBE);
		spin_lock_irqsave(&err_cqe_lock, flag);
	}
	spin_unlock_irqrestore(&err_cqe_lock, flag);

	return;
}

static void
process_req(struct work_struct *ctx)
{
	struct c4iw_ep_common *epc;
	unsigned long flag;
	int ep_events;

	process_err_cqes();
	spin_lock_irqsave(&req_lock, flag);
	while (!TAILQ_EMPTY(&req_list)) {
		epc = TAILQ_FIRST(&req_list);
		TAILQ_REMOVE(&req_list, epc, entry);
		epc->entry.tqe_prev = NULL;
		ep_events = epc->ep_events;
		epc->ep_events = 0;
		spin_unlock_irqrestore(&req_lock, flag);
		CTR4(KTR_IW_CXGBE, "%s: so %p, ep %p, events 0x%x", __func__,
		    epc->so, epc, ep_events);
		if (ep_events & C4IW_EVENT_TERM)
			process_terminate((struct c4iw_ep *)epc);
		if (ep_events & C4IW_EVENT_TIMEOUT)
			process_timeout((struct c4iw_ep *)epc);
		if (ep_events & C4IW_EVENT_SOCKET)
			process_socket_event((struct c4iw_ep *)epc);
		c4iw_put_ep(epc);
		process_err_cqes();
		spin_lock_irqsave(&req_lock, flag);
	}
	spin_unlock_irqrestore(&req_lock, flag);
}

/*
 * XXX: doesn't belong here in the iWARP driver.
 * XXX: assumes that the connection was offloaded by cxgbe/t4_tom if TF_TOE is
 *      set.  Is this a valid assumption for active open?
 */
static int
set_tcpinfo(struct c4iw_ep *ep)
{
	struct socket *so = ep->com.so;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp;
	struct toepcb *toep;
	int rc = 0;

	INP_WLOCK(inp);
	tp = intotcpcb(inp);
	if ((tp->t_flags & TF_TOE) == 0) {
		rc = EINVAL;
		log(LOG_ERR, "%s: connection not offloaded (so %p, ep %p)\n",
		    __func__, so, ep);
		goto done;
	}
	toep = TOEPCB(so);

	ep->hwtid = toep->tid;
	ep->snd_seq = tp->snd_nxt;
	ep->rcv_seq = tp->rcv_nxt;
	ep->emss = max(tp->t_maxseg, 128);
done:
	INP_WUNLOCK(inp);
	return (rc);

}

static int
find_route(__be32 local_ip, __be32 peer_ip, __be16 local_port,
		__be16 peer_port, u8 tos, struct nhop4_extended *pnh4)
{
	struct in_addr addr;
	int err;

	CTR5(KTR_IW_CXGBE, "%s:frtB %x, %x, %d, %d", __func__, local_ip,
	    peer_ip, ntohs(local_port), ntohs(peer_port));

	addr.s_addr = peer_ip;
	err = fib4_lookup_nh_ext(RT_DEFAULT_FIB, addr, NHR_REF, 0, pnh4);

	CTR2(KTR_IW_CXGBE, "%s:frtE %d", __func__, err);
	return err;
}

static void
close_socket(struct socket *so)
{

	uninit_iwarp_socket(so);
	sodisconnect(so);
}

static void
process_peer_close(struct c4iw_ep *ep)
{
	struct c4iw_qp_attributes attrs;
	int disconnect = 1;
	int release = 0;

	CTR4(KTR_IW_CXGBE, "%s:ppcB ep %p so %p state %s", __func__, ep,
	    ep->com.so, states[ep->com.state]);

	mutex_lock(&ep->com.mutex);
	switch (ep->com.state) {

		case MPA_REQ_WAIT:
			CTR2(KTR_IW_CXGBE, "%s:ppc1 %p MPA_REQ_WAIT CLOSING",
			    __func__, ep);
			__state_set(&ep->com, CLOSING);
			break;

		case MPA_REQ_SENT:
			CTR2(KTR_IW_CXGBE, "%s:ppc2 %p MPA_REQ_SENT CLOSING",
			    __func__, ep);
			__state_set(&ep->com, DEAD);
			connect_reply_upcall(ep, -ECONNABORTED);

			disconnect = 0;
			STOP_EP_TIMER(ep);
			close_socket(ep->com.so);
			deref_cm_id(&ep->com);
			release = 1;
			break;

		case MPA_REQ_RCVD:

			/*
			 * We're gonna mark this puppy DEAD, but keep
			 * the reference on it until the ULP accepts or
			 * rejects the CR.
			 */
			CTR2(KTR_IW_CXGBE, "%s:ppc3 %p MPA_REQ_RCVD CLOSING",
			    __func__, ep);
			__state_set(&ep->com, CLOSING);
			c4iw_get_ep(&ep->com);
			break;

		case MPA_REP_SENT:
			CTR2(KTR_IW_CXGBE, "%s:ppc4 %p MPA_REP_SENT CLOSING",
			    __func__, ep);
			__state_set(&ep->com, CLOSING);
			break;

		case FPDU_MODE:
			CTR2(KTR_IW_CXGBE, "%s:ppc5 %p FPDU_MODE CLOSING",
			    __func__, ep);
			START_EP_TIMER(ep);
			__state_set(&ep->com, CLOSING);
			attrs.next_state = C4IW_QP_STATE_CLOSING;
			c4iw_modify_qp(ep->com.dev, ep->com.qp,
					C4IW_QP_ATTR_NEXT_STATE, &attrs, 1);
			peer_close_upcall(ep);
			break;

		case ABORTING:
			CTR2(KTR_IW_CXGBE, "%s:ppc6 %p ABORTING (disconn)",
			    __func__, ep);
			disconnect = 0;
			break;

		case CLOSING:
			CTR2(KTR_IW_CXGBE, "%s:ppc7 %p CLOSING MORIBUND",
			    __func__, ep);
			__state_set(&ep->com, MORIBUND);
			disconnect = 0;
			break;

		case MORIBUND:
			CTR2(KTR_IW_CXGBE, "%s:ppc8 %p MORIBUND DEAD", __func__,
			    ep);
			STOP_EP_TIMER(ep);
			if (ep->com.cm_id && ep->com.qp) {
				attrs.next_state = C4IW_QP_STATE_IDLE;
				c4iw_modify_qp(ep->com.qp->rhp, ep->com.qp,
						C4IW_QP_ATTR_NEXT_STATE, &attrs, 1);
			}
			close_socket(ep->com.so);
			close_complete_upcall(ep, 0);
			__state_set(&ep->com, DEAD);
			release = 1;
			disconnect = 0;
			break;

		case DEAD:
			CTR2(KTR_IW_CXGBE, "%s:ppc9 %p DEAD (disconn)",
			    __func__, ep);
			disconnect = 0;
			break;

		default:
			panic("%s: ep %p state %d", __func__, ep,
			    ep->com.state);
			break;
	}

	mutex_unlock(&ep->com.mutex);

	if (disconnect) {

		CTR2(KTR_IW_CXGBE, "%s:ppca %p", __func__, ep);
		c4iw_ep_disconnect(ep, 0, M_NOWAIT);
	}
	if (release) {

		CTR2(KTR_IW_CXGBE, "%s:ppcb %p", __func__, ep);
		c4iw_put_ep(&ep->com);
	}
	CTR2(KTR_IW_CXGBE, "%s:ppcE %p", __func__, ep);
	return;
}

static void
process_conn_error(struct c4iw_ep *ep)
{
	struct c4iw_qp_attributes attrs;
	int ret;
	int state;

	mutex_lock(&ep->com.mutex);
	state = ep->com.state;
	CTR5(KTR_IW_CXGBE, "%s:pceB ep %p so %p so->so_error %u state %s",
	    __func__, ep, ep->com.so, ep->com.so->so_error,
	    states[ep->com.state]);

	switch (state) {

		case MPA_REQ_WAIT:
			STOP_EP_TIMER(ep);
			break;

		case MPA_REQ_SENT:
			STOP_EP_TIMER(ep);
			connect_reply_upcall(ep, -ECONNRESET);
			break;

		case MPA_REP_SENT:
			ep->com.rpl_err = ECONNRESET;
			CTR1(KTR_IW_CXGBE, "waking up ep %p", ep);
			break;

		case MPA_REQ_RCVD:

			/*
			 * We're gonna mark this puppy DEAD, but keep
			 * the reference on it until the ULP accepts or
			 * rejects the CR.
			 */
			c4iw_get_ep(&ep->com);
			break;

		case MORIBUND:
		case CLOSING:
			STOP_EP_TIMER(ep);
			/*FALLTHROUGH*/
		case FPDU_MODE:

			if (ep->com.cm_id && ep->com.qp) {

				attrs.next_state = C4IW_QP_STATE_ERROR;
				ret = c4iw_modify_qp(ep->com.qp->rhp,
					ep->com.qp, C4IW_QP_ATTR_NEXT_STATE,
					&attrs, 1);
				if (ret)
					log(LOG_ERR,
							"%s - qp <- error failed!\n",
							__func__);
			}
			peer_abort_upcall(ep);
			break;

		case ABORTING:
			break;

		case DEAD:
			CTR2(KTR_IW_CXGBE, "%s so_error %d IN DEAD STATE!!!!",
			    __func__, ep->com.so->so_error);
			mutex_unlock(&ep->com.mutex);
			return;

		default:
			panic("%s: ep %p state %d", __func__, ep, state);
			break;
	}

	if (state != ABORTING) {
		close_socket(ep->com.so);
		__state_set(&ep->com, DEAD);
		c4iw_put_ep(&ep->com);
	}
	mutex_unlock(&ep->com.mutex);
	CTR2(KTR_IW_CXGBE, "%s:pceE %p", __func__, ep);
	return;
}

static void
process_close_complete(struct c4iw_ep *ep)
{
	struct c4iw_qp_attributes attrs;
	int release = 0;

	CTR4(KTR_IW_CXGBE, "%s:pccB ep %p so %p state %s", __func__, ep,
	    ep->com.so, states[ep->com.state]);

	/* The cm_id may be null if we failed to connect */
	mutex_lock(&ep->com.mutex);
	set_bit(CLOSE_CON_RPL, &ep->com.history);

	switch (ep->com.state) {

		case CLOSING:
			CTR2(KTR_IW_CXGBE, "%s:pcc1 %p CLOSING MORIBUND",
			    __func__, ep);
			__state_set(&ep->com, MORIBUND);
			break;

		case MORIBUND:
			CTR2(KTR_IW_CXGBE, "%s:pcc1 %p MORIBUND DEAD", __func__,
			    ep);
			STOP_EP_TIMER(ep);

			if ((ep->com.cm_id) && (ep->com.qp)) {

				CTR2(KTR_IW_CXGBE, "%s:pcc2 %p QP_STATE_IDLE",
				    __func__, ep);
				attrs.next_state = C4IW_QP_STATE_IDLE;
				c4iw_modify_qp(ep->com.dev,
						ep->com.qp,
						C4IW_QP_ATTR_NEXT_STATE,
						&attrs, 1);
			}

			close_socket(ep->com.so);
			close_complete_upcall(ep, 0);
			__state_set(&ep->com, DEAD);
			release = 1;
			break;

		case ABORTING:
			CTR2(KTR_IW_CXGBE, "%s:pcc5 %p ABORTING", __func__, ep);
			break;

		case DEAD:
			CTR2(KTR_IW_CXGBE, "%s:pcc6 %p DEAD", __func__, ep);
			break;
		default:
			CTR2(KTR_IW_CXGBE, "%s:pcc7 %p unknown ep state",
					__func__, ep);
			panic("%s:pcc6 %p unknown ep state", __func__, ep);
			break;
	}
	mutex_unlock(&ep->com.mutex);

	if (release) {

		CTR2(KTR_IW_CXGBE, "%s:pcc8 %p", __func__, ep);
		c4iw_put_ep(&ep->com);
	}
	CTR2(KTR_IW_CXGBE, "%s:pccE %p", __func__, ep);
	return;
}

static void
init_iwarp_socket(struct socket *so, void *arg)
{
	int rc;
	struct sockopt sopt;
	int on = 1;

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, c4iw_so_upcall, arg);
	so->so_state |= SS_NBIO;
	SOCKBUF_UNLOCK(&so->so_rcv);
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = IPPROTO_TCP;
	sopt.sopt_name = TCP_NODELAY;
	sopt.sopt_val = &on;
	sopt.sopt_valsize = sizeof on;
	sopt.sopt_td = NULL;
	rc = sosetopt(so, &sopt);
	if (rc) {
		log(LOG_ERR, "%s: can't set TCP_NODELAY on so %p (%d)\n",
		    __func__, so, rc);
	}
}

static void
uninit_iwarp_socket(struct socket *so)
{

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_clear(so, SO_RCV);
	SOCKBUF_UNLOCK(&so->so_rcv);
}

static void
process_data(struct c4iw_ep *ep)
{
	struct sockaddr_in *local, *remote;
	int disconnect = 0;

	CTR5(KTR_IW_CXGBE, "%s: so %p, ep %p, state %s, sbused %d", __func__,
	    ep->com.so, ep, states[ep->com.state], sbused(&ep->com.so->so_rcv));

	switch (state_read(&ep->com)) {
	case MPA_REQ_SENT:
		disconnect = process_mpa_reply(ep);
		break;
	case MPA_REQ_WAIT:
		in_getsockaddr(ep->com.so, (struct sockaddr **)&local);
		in_getpeeraddr(ep->com.so, (struct sockaddr **)&remote);
		ep->com.local_addr = *local;
		ep->com.remote_addr = *remote;
		free(local, M_SONAME);
		free(remote, M_SONAME);
		disconnect = process_mpa_request(ep);
		break;
	default:
		if (sbused(&ep->com.so->so_rcv))
			log(LOG_ERR, "%s: Unexpected streaming data. ep %p, "
			    "state %d, so %p, so_state 0x%x, sbused %u\n",
			    __func__, ep, state_read(&ep->com), ep->com.so,
			    ep->com.so->so_state, sbused(&ep->com.so->so_rcv));
		break;
	}
	if (disconnect)
		c4iw_ep_disconnect(ep, disconnect == 2, GFP_KERNEL);

}

static void
process_connected(struct c4iw_ep *ep)
{
	struct socket *so = ep->com.so;

	if ((so->so_state & SS_ISCONNECTED) && !so->so_error) {
		if (send_mpa_req(ep))
			goto err;
	} else {
		connect_reply_upcall(ep, -so->so_error);
		goto err;
	}
	return;
err:
	close_socket(so);
	state_set(&ep->com, DEAD);
	c4iw_put_ep(&ep->com);
	return;
}

void
process_newconn(struct iw_cm_id *parent_cm_id, struct socket *child_so)
{
	struct c4iw_ep *child_ep;
	struct sockaddr_in *local;
	struct sockaddr_in *remote;
	struct c4iw_ep *parent_ep = parent_cm_id->provider_data;
	int ret = 0;

	MPASS(child_so != NULL);

	child_ep = alloc_ep(sizeof(*child_ep), GFP_KERNEL);

	CTR5(KTR_IW_CXGBE,
	    "%s: parent so %p, parent ep %p, child so %p, child ep %p",
	     __func__, parent_ep->com.so, parent_ep, child_so, child_ep);

	in_getsockaddr(child_so, (struct sockaddr **)&local);
	in_getpeeraddr(child_so, (struct sockaddr **)&remote);

	child_ep->com.local_addr = *local;
	child_ep->com.remote_addr = *remote;
	child_ep->com.dev = parent_ep->com.dev;
	child_ep->com.so = child_so;
	child_ep->com.cm_id = NULL;
	child_ep->com.thread = parent_ep->com.thread;
	child_ep->parent_ep = parent_ep;

	free(local, M_SONAME);
	free(remote, M_SONAME);

	init_iwarp_socket(child_so, &child_ep->com);
	c4iw_get_ep(&parent_ep->com);
	init_timer(&child_ep->timer);
	state_set(&child_ep->com, MPA_REQ_WAIT);
	START_EP_TIMER(child_ep);

	/* maybe the request has already been queued up on the socket... */
	ret = process_mpa_request(child_ep);
	if (ret == 2)
		/* ABORT */
		c4iw_ep_disconnect(child_ep, 1, GFP_KERNEL);
	else if (ret == 1)
		/* CLOSE */
		c4iw_ep_disconnect(child_ep, 0, GFP_KERNEL);

	return;
}

static int
add_ep_to_req_list(struct c4iw_ep *ep, int new_ep_event)
{
	unsigned long flag;

	spin_lock_irqsave(&req_lock, flag);
	if (ep && ep->com.so) {
		ep->com.ep_events |= new_ep_event;
		if (!ep->com.entry.tqe_prev) {
			c4iw_get_ep(&ep->com);
			TAILQ_INSERT_TAIL(&req_list, &ep->com, entry);
			queue_work(c4iw_taskq, &c4iw_task);
		}
	}
	spin_unlock_irqrestore(&req_lock, flag);

	return (0);
}

static int
c4iw_so_upcall(struct socket *so, void *arg, int waitflag)
{
	struct c4iw_ep *ep = arg;

	CTR6(KTR_IW_CXGBE,
	    "%s: so %p, so_state 0x%x, ep %p, ep_state %s, tqe_prev %p",
	    __func__, so, so->so_state, ep, states[ep->com.state],
	    ep->com.entry.tqe_prev);

	MPASS(ep->com.so == so);
	add_ep_to_req_list(ep, C4IW_EVENT_SOCKET);

	return (SU_OK);
}


static int
terminate(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_rdma_terminate *cpl = mtod(m, const void *);
	unsigned int tid = GET_TID(cpl);
	struct toepcb *toep = lookup_tid(sc, tid);
	struct socket *so;
	struct c4iw_ep *ep;

	INP_WLOCK(toep->inp);
	so = inp_inpcbtosocket(toep->inp);
	ep = so->so_rcv.sb_upcallarg;
	INP_WUNLOCK(toep->inp);

	CTR3(KTR_IW_CXGBE, "%s: so %p, ep %p", __func__, so, ep);
	add_ep_to_req_list(ep, C4IW_EVENT_TERM);

	return 0;
}

static void
process_socket_event(struct c4iw_ep *ep)
{
	int state = state_read(&ep->com);
	struct socket *so = ep->com.so;

	CTR6(KTR_IW_CXGBE, "process_socket_event: so %p, so_state 0x%x, "
	    "so_err %d, sb_state 0x%x, ep %p, ep_state %s", so, so->so_state,
	    so->so_error, so->so_rcv.sb_state, ep, states[state]);

	if (state == CONNECTING) {
		process_connected(ep);
		return;
	}

	if (state == LISTEN) {
		/* socket listening events are handled at IWCM */
		CTR3(KTR_IW_CXGBE, "%s Invalid ep state:%u, ep:%p", __func__,
			    ep->com.state, ep);
		BUG();
		return;
	}

	/* connection error */
	if (so->so_error) {
		process_conn_error(ep);
		return;
	}

	/* peer close */
	if ((so->so_rcv.sb_state & SBS_CANTRCVMORE) && state <= CLOSING) {
		process_peer_close(ep);
		/*
		 * check whether socket disconnect event is pending before
		 * returning. Fallthrough if yes.
		 */
		if (!(so->so_state & SS_ISDISCONNECTED))
			return;
	}

	/* close complete */
	if (so->so_state & SS_ISDISCONNECTED) {
		process_close_complete(ep);
		return;
	}

	/* rx data */
	process_data(ep);
}

SYSCTL_NODE(_hw, OID_AUTO, iw_cxgbe, CTLFLAG_RD, 0, "iw_cxgbe driver parameters");

static int dack_mode = 0;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, dack_mode, CTLFLAG_RWTUN, &dack_mode, 0,
		"Delayed ack mode (default = 0)");

int c4iw_max_read_depth = 8;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, c4iw_max_read_depth, CTLFLAG_RWTUN, &c4iw_max_read_depth, 0,
		"Per-connection max ORD/IRD (default = 8)");

static int enable_tcp_timestamps;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, enable_tcp_timestamps, CTLFLAG_RWTUN, &enable_tcp_timestamps, 0,
		"Enable tcp timestamps (default = 0)");

static int enable_tcp_sack;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, enable_tcp_sack, CTLFLAG_RWTUN, &enable_tcp_sack, 0,
		"Enable tcp SACK (default = 0)");

static int enable_tcp_window_scaling = 1;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, enable_tcp_window_scaling, CTLFLAG_RWTUN, &enable_tcp_window_scaling, 0,
		"Enable tcp window scaling (default = 1)");

int c4iw_debug = 0;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, c4iw_debug, CTLFLAG_RWTUN, &c4iw_debug, 0,
		"Enable debug logging (default = 0)");

static int peer2peer = 1;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, peer2peer, CTLFLAG_RWTUN, &peer2peer, 0,
		"Support peer2peer ULPs (default = 1)");

static int p2p_type = FW_RI_INIT_P2PTYPE_READ_REQ;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, p2p_type, CTLFLAG_RWTUN, &p2p_type, 0,
		"RDMAP opcode to use for the RTR message: 1 = RDMA_READ 0 = RDMA_WRITE (default 1)");

static int ep_timeout_secs = 60;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, ep_timeout_secs, CTLFLAG_RWTUN, &ep_timeout_secs, 0,
		"CM Endpoint operation timeout in seconds (default = 60)");

static int mpa_rev = 1;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, mpa_rev, CTLFLAG_RWTUN, &mpa_rev, 0,
		"MPA Revision, 0 supports amso1100, 1 is RFC5044 spec compliant, 2 is IETF MPA Peer Connect Draft compliant (default = 1)");

static int markers_enabled;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, markers_enabled, CTLFLAG_RWTUN, &markers_enabled, 0,
		"Enable MPA MARKERS (default(0) = disabled)");

static int crc_enabled = 1;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, crc_enabled, CTLFLAG_RWTUN, &crc_enabled, 0,
		"Enable MPA CRC (default(1) = enabled)");

static int rcv_win = 256 * 1024;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, rcv_win, CTLFLAG_RWTUN, &rcv_win, 0,
		"TCP receive window in bytes (default = 256KB)");

static int snd_win = 128 * 1024;
SYSCTL_INT(_hw_iw_cxgbe, OID_AUTO, snd_win, CTLFLAG_RWTUN, &snd_win, 0,
		"TCP send window in bytes (default = 128KB)");

static void
start_ep_timer(struct c4iw_ep *ep)
{

	if (timer_pending(&ep->timer)) {
		CTR2(KTR_IW_CXGBE, "%s: ep %p, already started", __func__, ep);
		printk(KERN_ERR "%s timer already started! ep %p\n", __func__,
		    ep);
		return;
	}
	clear_bit(TIMEOUT, &ep->com.flags);
	c4iw_get_ep(&ep->com);
	ep->timer.expires = jiffies + ep_timeout_secs * HZ;
	ep->timer.data = (unsigned long)ep;
	ep->timer.function = ep_timeout;
	add_timer(&ep->timer);
}

static int
stop_ep_timer(struct c4iw_ep *ep)
{

	del_timer_sync(&ep->timer);
	if (!test_and_set_bit(TIMEOUT, &ep->com.flags)) {
		c4iw_put_ep(&ep->com);
		return 0;
	}
	return 1;
}

static enum
c4iw_ep_state state_read(struct c4iw_ep_common *epc)
{
	enum c4iw_ep_state state;

	mutex_lock(&epc->mutex);
	state = epc->state;
	mutex_unlock(&epc->mutex);

	return (state);
}

static void
__state_set(struct c4iw_ep_common *epc, enum c4iw_ep_state new)
{

	epc->state = new;
}

static void
state_set(struct c4iw_ep_common *epc, enum c4iw_ep_state new)
{

	mutex_lock(&epc->mutex);
	__state_set(epc, new);
	mutex_unlock(&epc->mutex);
}

static void *
alloc_ep(int size, gfp_t gfp)
{
	struct c4iw_ep_common *epc;

	epc = kzalloc(size, gfp);
	if (epc == NULL)
		return (NULL);

	kref_init(&epc->kref);
	mutex_init(&epc->mutex);
	c4iw_init_wr_wait(&epc->wr_wait);

	return (epc);
}

void _c4iw_free_ep(struct kref *kref)
{
	struct c4iw_ep *ep;
	struct c4iw_ep_common *epc;

	ep = container_of(kref, struct c4iw_ep, com.kref);
	epc = &ep->com;
	KASSERT(!epc->entry.tqe_prev, ("%s epc %p still on req list",
	    __func__, epc));
	if (test_bit(QP_REFERENCED, &ep->com.flags))
		deref_qp(ep);
	kfree(ep);
}

static void release_ep_resources(struct c4iw_ep *ep)
{
	CTR2(KTR_IW_CXGBE, "%s:rerB %p", __func__, ep);
	set_bit(RELEASE_RESOURCES, &ep->com.flags);
	c4iw_put_ep(&ep->com);
	CTR2(KTR_IW_CXGBE, "%s:rerE %p", __func__, ep);
}

static int
send_mpa_req(struct c4iw_ep *ep)
{
	int mpalen;
	struct mpa_message *mpa;
	struct mpa_v2_conn_params mpa_v2_params;
	struct mbuf *m;
	char mpa_rev_to_use = mpa_rev;
	int err = 0;

	if (ep->retry_with_mpa_v1)
		mpa_rev_to_use = 1;
	mpalen = sizeof(*mpa) + ep->plen;
	if (mpa_rev_to_use == 2)
		mpalen += sizeof(struct mpa_v2_conn_params);

	mpa = malloc(mpalen, M_CXGBE, M_NOWAIT);
	if (mpa == NULL) {
		err = -ENOMEM;
		CTR3(KTR_IW_CXGBE, "%s:smr1 ep: %p , error: %d",
				__func__, ep, err);
		goto err;
	}

	memset(mpa, 0, mpalen);
	memcpy(mpa->key, MPA_KEY_REQ, sizeof(mpa->key));
	mpa->flags = (crc_enabled ? MPA_CRC : 0) |
		(markers_enabled ? MPA_MARKERS : 0) |
		(mpa_rev_to_use == 2 ? MPA_ENHANCED_RDMA_CONN : 0);
	mpa->private_data_size = htons(ep->plen);
	mpa->revision = mpa_rev_to_use;

	if (mpa_rev_to_use == 1) {
		ep->tried_with_mpa_v1 = 1;
		ep->retry_with_mpa_v1 = 0;
	}

	if (mpa_rev_to_use == 2) {
		mpa->private_data_size +=
			htons(sizeof(struct mpa_v2_conn_params));
		mpa_v2_params.ird = htons((u16)ep->ird);
		mpa_v2_params.ord = htons((u16)ep->ord);

		if (peer2peer) {
			mpa_v2_params.ird |= htons(MPA_V2_PEER2PEER_MODEL);

			if (p2p_type == FW_RI_INIT_P2PTYPE_RDMA_WRITE) {
				mpa_v2_params.ord |=
				    htons(MPA_V2_RDMA_WRITE_RTR);
			} else if (p2p_type == FW_RI_INIT_P2PTYPE_READ_REQ) {
				mpa_v2_params.ord |=
					htons(MPA_V2_RDMA_READ_RTR);
			}
		}
		memcpy(mpa->private_data, &mpa_v2_params,
			sizeof(struct mpa_v2_conn_params));

		if (ep->plen) {

			memcpy(mpa->private_data +
				sizeof(struct mpa_v2_conn_params),
				ep->mpa_pkt + sizeof(*mpa), ep->plen);
		}
	} else {

		if (ep->plen)
			memcpy(mpa->private_data,
					ep->mpa_pkt + sizeof(*mpa), ep->plen);
		CTR2(KTR_IW_CXGBE, "%s:smr7 %p", __func__, ep);
	}

	m = m_getm(NULL, mpalen, M_NOWAIT, MT_DATA);
	if (m == NULL) {
		err = -ENOMEM;
		CTR3(KTR_IW_CXGBE, "%s:smr2 ep: %p , error: %d",
				__func__, ep, err);
		free(mpa, M_CXGBE);
		goto err;
	}
	m_copyback(m, 0, mpalen, (void *)mpa);
	free(mpa, M_CXGBE);

	err = -sosend(ep->com.so, NULL, NULL, m, NULL, MSG_DONTWAIT,
			ep->com.thread);
	if (err) {
		CTR3(KTR_IW_CXGBE, "%s:smr3 ep: %p , error: %d",
				__func__, ep, err);
		goto err;
	}

	START_EP_TIMER(ep);
	state_set(&ep->com, MPA_REQ_SENT);
	ep->mpa_attr.initiator = 1;
	CTR3(KTR_IW_CXGBE, "%s:smrE %p, error: %d", __func__, ep, err);
	return 0;
err:
	connect_reply_upcall(ep, err);
	CTR3(KTR_IW_CXGBE, "%s:smrE %p, error: %d", __func__, ep, err);
	return err;
}

static int send_mpa_reject(struct c4iw_ep *ep, const void *pdata, u8 plen)
{
	int mpalen ;
	struct mpa_message *mpa;
	struct mpa_v2_conn_params mpa_v2_params;
	struct mbuf *m;
	int err;

	CTR4(KTR_IW_CXGBE, "%s:smrejB %p %u %d", __func__, ep, ep->hwtid,
	    ep->plen);

	mpalen = sizeof(*mpa) + plen;

	if (ep->mpa_attr.version == 2 && ep->mpa_attr.enhanced_rdma_conn) {

		mpalen += sizeof(struct mpa_v2_conn_params);
		CTR4(KTR_IW_CXGBE, "%s:smrej1 %p %u %d", __func__, ep,
		    ep->mpa_attr.version, mpalen);
	}

	mpa = malloc(mpalen, M_CXGBE, M_NOWAIT);
	if (mpa == NULL)
		return (-ENOMEM);

	memset(mpa, 0, mpalen);
	memcpy(mpa->key, MPA_KEY_REP, sizeof(mpa->key));
	mpa->flags = MPA_REJECT;
	mpa->revision = mpa_rev;
	mpa->private_data_size = htons(plen);

	if (ep->mpa_attr.version == 2 && ep->mpa_attr.enhanced_rdma_conn) {

		mpa->flags |= MPA_ENHANCED_RDMA_CONN;
		mpa->private_data_size +=
			htons(sizeof(struct mpa_v2_conn_params));
		mpa_v2_params.ird = htons(((u16)ep->ird) |
				(peer2peer ? MPA_V2_PEER2PEER_MODEL :
				 0));
		mpa_v2_params.ord = htons(((u16)ep->ord) | (peer2peer ?
					(p2p_type ==
					 FW_RI_INIT_P2PTYPE_RDMA_WRITE ?
					 MPA_V2_RDMA_WRITE_RTR : p2p_type ==
					 FW_RI_INIT_P2PTYPE_READ_REQ ?
					 MPA_V2_RDMA_READ_RTR : 0) : 0));
		memcpy(mpa->private_data, &mpa_v2_params,
				sizeof(struct mpa_v2_conn_params));

		if (ep->plen)
			memcpy(mpa->private_data +
					sizeof(struct mpa_v2_conn_params), pdata, plen);
		CTR5(KTR_IW_CXGBE, "%s:smrej3 %p %d %d %d", __func__, ep,
		    mpa_v2_params.ird, mpa_v2_params.ord, ep->plen);
	} else
		if (plen)
			memcpy(mpa->private_data, pdata, plen);

	m = m_getm(NULL, mpalen, M_NOWAIT, MT_DATA);
	if (m == NULL) {
		free(mpa, M_CXGBE);
		return (-ENOMEM);
	}
	m_copyback(m, 0, mpalen, (void *)mpa);
	free(mpa, M_CXGBE);

	err = -sosend(ep->com.so, NULL, NULL, m, NULL, MSG_DONTWAIT, ep->com.thread);
	if (!err)
		ep->snd_seq += mpalen;
	CTR4(KTR_IW_CXGBE, "%s:smrejE %p %u %d", __func__, ep, ep->hwtid, err);
	return err;
}

static int send_mpa_reply(struct c4iw_ep *ep, const void *pdata, u8 plen)
{
	int mpalen;
	struct mpa_message *mpa;
	struct mbuf *m;
	struct mpa_v2_conn_params mpa_v2_params;
	int err;

	CTR2(KTR_IW_CXGBE, "%s:smrepB %p", __func__, ep);

	mpalen = sizeof(*mpa) + plen;

	if (ep->mpa_attr.version == 2 && ep->mpa_attr.enhanced_rdma_conn) {

		CTR3(KTR_IW_CXGBE, "%s:smrep1 %p %d", __func__, ep,
		    ep->mpa_attr.version);
		mpalen += sizeof(struct mpa_v2_conn_params);
	}

	mpa = malloc(mpalen, M_CXGBE, M_NOWAIT);
	if (mpa == NULL)
		return (-ENOMEM);

	memset(mpa, 0, sizeof(*mpa));
	memcpy(mpa->key, MPA_KEY_REP, sizeof(mpa->key));
	mpa->flags = (ep->mpa_attr.crc_enabled ? MPA_CRC : 0) |
		(markers_enabled ? MPA_MARKERS : 0);
	mpa->revision = ep->mpa_attr.version;
	mpa->private_data_size = htons(plen);

	if (ep->mpa_attr.version == 2 && ep->mpa_attr.enhanced_rdma_conn) {

		mpa->flags |= MPA_ENHANCED_RDMA_CONN;
		mpa->private_data_size +=
			htons(sizeof(struct mpa_v2_conn_params));
		mpa_v2_params.ird = htons((u16)ep->ird);
		mpa_v2_params.ord = htons((u16)ep->ord);
		CTR5(KTR_IW_CXGBE, "%s:smrep3 %p %d %d %d", __func__, ep,
		    ep->mpa_attr.version, mpa_v2_params.ird, mpa_v2_params.ord);

		if (peer2peer && (ep->mpa_attr.p2p_type !=
			FW_RI_INIT_P2PTYPE_DISABLED)) {

			mpa_v2_params.ird |= htons(MPA_V2_PEER2PEER_MODEL);

			if (p2p_type == FW_RI_INIT_P2PTYPE_RDMA_WRITE) {

				mpa_v2_params.ord |=
					htons(MPA_V2_RDMA_WRITE_RTR);
				CTR5(KTR_IW_CXGBE, "%s:smrep4 %p %d %d %d",
				    __func__, ep, p2p_type, mpa_v2_params.ird,
				    mpa_v2_params.ord);
			}
			else if (p2p_type == FW_RI_INIT_P2PTYPE_READ_REQ) {

				mpa_v2_params.ord |=
					htons(MPA_V2_RDMA_READ_RTR);
				CTR5(KTR_IW_CXGBE, "%s:smrep5 %p %d %d %d",
				    __func__, ep, p2p_type, mpa_v2_params.ird,
				    mpa_v2_params.ord);
			}
		}

		memcpy(mpa->private_data, &mpa_v2_params,
			sizeof(struct mpa_v2_conn_params));

		if (ep->plen)
			memcpy(mpa->private_data +
				sizeof(struct mpa_v2_conn_params), pdata, plen);
	} else
		if (plen)
			memcpy(mpa->private_data, pdata, plen);

	m = m_getm(NULL, mpalen, M_NOWAIT, MT_DATA);
	if (m == NULL) {
		free(mpa, M_CXGBE);
		return (-ENOMEM);
	}
	m_copyback(m, 0, mpalen, (void *)mpa);
	free(mpa, M_CXGBE);


	state_set(&ep->com, MPA_REP_SENT);
	ep->snd_seq += mpalen;
	err = -sosend(ep->com.so, NULL, NULL, m, NULL, MSG_DONTWAIT,
			ep->com.thread);
	CTR3(KTR_IW_CXGBE, "%s:smrepE %p %d", __func__, ep, err);
	return err;
}



static void close_complete_upcall(struct c4iw_ep *ep, int status)
{
	struct iw_cm_event event;

	CTR2(KTR_IW_CXGBE, "%s:ccuB %p", __func__, ep);
	memset(&event, 0, sizeof(event));
	event.event = IW_CM_EVENT_CLOSE;
	event.status = status;

	if (ep->com.cm_id) {

		CTR2(KTR_IW_CXGBE, "%s:ccu1 %1", __func__, ep);
		ep->com.cm_id->event_handler(ep->com.cm_id, &event);
		deref_cm_id(&ep->com);
		set_bit(CLOSE_UPCALL, &ep->com.history);
	}
	CTR2(KTR_IW_CXGBE, "%s:ccuE %p", __func__, ep);
}

static int
send_abort(struct c4iw_ep *ep)
{
	struct socket *so = ep->com.so;
	struct sockopt sopt;
	int rc;
	struct linger l;

	CTR5(KTR_IW_CXGBE, "%s ep %p so %p state %s tid %d", __func__, ep, so,
	    states[ep->com.state], ep->hwtid);

	l.l_onoff = 1;
	l.l_linger = 0;

	/* linger_time of 0 forces RST to be sent */
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_LINGER;
	sopt.sopt_val = &l;
	sopt.sopt_valsize = sizeof l;
	sopt.sopt_td = NULL;
	rc = sosetopt(so, &sopt);
	if (rc != 0) {
		log(LOG_ERR, "%s: sosetopt(%p, linger = 0) failed with %d.\n",
		    __func__, so, rc);
	}

	uninit_iwarp_socket(so);
	sodisconnect(so);
	set_bit(ABORT_CONN, &ep->com.history);

	/*
	 * TBD: iw_cxgbe driver should receive ABORT reply for every ABORT
	 * request it has sent. But the current TOE driver is not propagating
	 * this ABORT reply event (via do_abort_rpl) to iw_cxgbe. So as a work-
	 * around de-refer 'ep' (which was refered before sending ABORT request)
	 * here instead of doing it in abort_rpl() handler of iw_cxgbe driver.
	 */
	c4iw_put_ep(&ep->com);

	return (0);
}

static void peer_close_upcall(struct c4iw_ep *ep)
{
	struct iw_cm_event event;

	CTR2(KTR_IW_CXGBE, "%s:pcuB %p", __func__, ep);
	memset(&event, 0, sizeof(event));
	event.event = IW_CM_EVENT_DISCONNECT;

	if (ep->com.cm_id) {

		CTR2(KTR_IW_CXGBE, "%s:pcu1 %p", __func__, ep);
		ep->com.cm_id->event_handler(ep->com.cm_id, &event);
		set_bit(DISCONN_UPCALL, &ep->com.history);
	}
	CTR2(KTR_IW_CXGBE, "%s:pcuE %p", __func__, ep);
}

static void peer_abort_upcall(struct c4iw_ep *ep)
{
	struct iw_cm_event event;

	CTR2(KTR_IW_CXGBE, "%s:pauB %p", __func__, ep);
	memset(&event, 0, sizeof(event));
	event.event = IW_CM_EVENT_CLOSE;
	event.status = -ECONNRESET;

	if (ep->com.cm_id) {

		CTR2(KTR_IW_CXGBE, "%s:pau1 %p", __func__, ep);
		ep->com.cm_id->event_handler(ep->com.cm_id, &event);
		deref_cm_id(&ep->com);
		set_bit(ABORT_UPCALL, &ep->com.history);
	}
	CTR2(KTR_IW_CXGBE, "%s:pauE %p", __func__, ep);
}

static void connect_reply_upcall(struct c4iw_ep *ep, int status)
{
	struct iw_cm_event event;

	CTR3(KTR_IW_CXGBE, "%s:cruB %p, status: %d", __func__, ep, status);
	memset(&event, 0, sizeof(event));
	event.event = IW_CM_EVENT_CONNECT_REPLY;
	event.status = ((status == -ECONNABORTED) || (status == -EPIPE)) ?
					-ECONNRESET : status;
	event.local_addr = ep->com.local_addr;
	event.remote_addr = ep->com.remote_addr;

	if ((status == 0) || (status == -ECONNREFUSED)) {

		if (!ep->tried_with_mpa_v1) {

			CTR2(KTR_IW_CXGBE, "%s:cru1 %p", __func__, ep);
			/* this means MPA_v2 is used */
			event.private_data_len = ep->plen -
				sizeof(struct mpa_v2_conn_params);
			event.private_data = ep->mpa_pkt +
				sizeof(struct mpa_message) +
				sizeof(struct mpa_v2_conn_params);
		} else {

			CTR2(KTR_IW_CXGBE, "%s:cru2 %p", __func__, ep);
			/* this means MPA_v1 is used */
			event.private_data_len = ep->plen;
			event.private_data = ep->mpa_pkt +
				sizeof(struct mpa_message);
		}
	}

	if (ep->com.cm_id) {

		CTR2(KTR_IW_CXGBE, "%s:cru3 %p", __func__, ep);
		set_bit(CONN_RPL_UPCALL, &ep->com.history);
		ep->com.cm_id->event_handler(ep->com.cm_id, &event);
	}

	if(status == -ECONNABORTED) {

		CTR3(KTR_IW_CXGBE, "%s:cruE %p %d", __func__, ep, status);
		return;
	}

	if (status < 0) {

		CTR3(KTR_IW_CXGBE, "%s:cru4 %p %d", __func__, ep, status);
		deref_cm_id(&ep->com);
	}

	CTR2(KTR_IW_CXGBE, "%s:cruE %p", __func__, ep);
}

static int connect_request_upcall(struct c4iw_ep *ep)
{
	struct iw_cm_event event;
	int ret;

	CTR3(KTR_IW_CXGBE, "%s: ep %p, mpa_v1 %d", __func__, ep,
	    ep->tried_with_mpa_v1);

	memset(&event, 0, sizeof(event));
	event.event = IW_CM_EVENT_CONNECT_REQUEST;
	event.local_addr = ep->com.local_addr;
	event.remote_addr = ep->com.remote_addr;
	event.provider_data = ep;
	event.so = ep->com.so;

	if (!ep->tried_with_mpa_v1) {
		/* this means MPA_v2 is used */
		event.ord = ep->ord;
		event.ird = ep->ird;
		event.private_data_len = ep->plen -
			sizeof(struct mpa_v2_conn_params);
		event.private_data = ep->mpa_pkt + sizeof(struct mpa_message) +
			sizeof(struct mpa_v2_conn_params);
	} else {

		/* this means MPA_v1 is used. Send max supported */
		event.ord = c4iw_max_read_depth;
		event.ird = c4iw_max_read_depth;
		event.private_data_len = ep->plen;
		event.private_data = ep->mpa_pkt + sizeof(struct mpa_message);
	}

	c4iw_get_ep(&ep->com);
	ret = ep->parent_ep->com.cm_id->event_handler(ep->parent_ep->com.cm_id,
	    &event);
	if(ret)
		c4iw_put_ep(&ep->com);

	set_bit(CONNREQ_UPCALL, &ep->com.history);
	c4iw_put_ep(&ep->parent_ep->com);
	return ret;
}

static void established_upcall(struct c4iw_ep *ep)
{
	struct iw_cm_event event;

	CTR2(KTR_IW_CXGBE, "%s:euB %p", __func__, ep);
	memset(&event, 0, sizeof(event));
	event.event = IW_CM_EVENT_ESTABLISHED;
	event.ird = ep->ird;
	event.ord = ep->ord;

	if (ep->com.cm_id) {

		CTR2(KTR_IW_CXGBE, "%s:eu1 %p", __func__, ep);
		ep->com.cm_id->event_handler(ep->com.cm_id, &event);
		set_bit(ESTAB_UPCALL, &ep->com.history);
	}
	CTR2(KTR_IW_CXGBE, "%s:euE %p", __func__, ep);
}


/*
 * process_mpa_reply - process streaming mode MPA reply
 *
 * Returns:
 *
 * 0 upon success indicating a connect request was delivered to the ULP
 * or the mpa request is incomplete but valid so far.
 *
 * 1 if a failure requires the caller to close the connection.
 *
 * 2 if a failure requires the caller to abort the connection.
 */
static int process_mpa_reply(struct c4iw_ep *ep)
{
	struct mpa_message *mpa;
	struct mpa_v2_conn_params *mpa_v2_params;
	u16 plen;
	u16 resp_ird, resp_ord;
	u8 rtr_mismatch = 0, insuff_ird = 0;
	struct c4iw_qp_attributes attrs;
	enum c4iw_qp_attr_mask mask;
	int err;
	struct mbuf *top, *m;
	int flags = MSG_DONTWAIT;
	struct uio uio;
	int disconnect = 0;

	CTR2(KTR_IW_CXGBE, "%s:pmrB %p", __func__, ep);

	/*
	 * Stop mpa timer.  If it expired, then
	 * we ignore the MPA reply.  process_timeout()
	 * will abort the connection.
	 */
	if (STOP_EP_TIMER(ep))
		return 0;

	uio.uio_resid = 1000000;
	uio.uio_td = ep->com.thread;
	err = soreceive(ep->com.so, NULL, &uio, &top, NULL, &flags);

	if (err) {

		if (err == EWOULDBLOCK) {

			CTR2(KTR_IW_CXGBE, "%s:pmr1 %p", __func__, ep);
			START_EP_TIMER(ep);
			return 0;
		}
		err = -err;
		CTR2(KTR_IW_CXGBE, "%s:pmr2 %p", __func__, ep);
		goto err;
	}

	if (ep->com.so->so_rcv.sb_mb) {

		CTR2(KTR_IW_CXGBE, "%s:pmr3 %p", __func__, ep);
		printf("%s data after soreceive called! so %p sb_mb %p top %p\n",
		       __func__, ep->com.so, ep->com.so->so_rcv.sb_mb, top);
	}

	m = top;

	do {

		CTR2(KTR_IW_CXGBE, "%s:pmr4 %p", __func__, ep);
		/*
		 * If we get more than the supported amount of private data
		 * then we must fail this connection.
		 */
		if (ep->mpa_pkt_len + m->m_len > sizeof(ep->mpa_pkt)) {

			CTR3(KTR_IW_CXGBE, "%s:pmr5 %p %d", __func__, ep,
			    ep->mpa_pkt_len + m->m_len);
			err = (-EINVAL);
			goto err_stop_timer;
		}

		/*
		 * copy the new data into our accumulation buffer.
		 */
		m_copydata(m, 0, m->m_len, &(ep->mpa_pkt[ep->mpa_pkt_len]));
		ep->mpa_pkt_len += m->m_len;
		if (!m->m_next)
			m = m->m_nextpkt;
		else
			m = m->m_next;
	} while (m);

	m_freem(top);
	/*
	 * if we don't even have the mpa message, then bail.
	 */
	if (ep->mpa_pkt_len < sizeof(*mpa)) {
		return 0;
	}
	mpa = (struct mpa_message *) ep->mpa_pkt;

	/* Validate MPA header. */
	if (mpa->revision > mpa_rev) {

		CTR4(KTR_IW_CXGBE, "%s:pmr6 %p %d %d", __func__, ep,
		    mpa->revision, mpa_rev);
		printk(KERN_ERR MOD "%s MPA version mismatch. Local = %d, "
				" Received = %d\n", __func__, mpa_rev, mpa->revision);
		err = -EPROTO;
		goto err_stop_timer;
	}

	if (memcmp(mpa->key, MPA_KEY_REP, sizeof(mpa->key))) {

		CTR2(KTR_IW_CXGBE, "%s:pmr7 %p", __func__, ep);
		err = -EPROTO;
		goto err_stop_timer;
	}

	plen = ntohs(mpa->private_data_size);

	/*
	 * Fail if there's too much private data.
	 */
	if (plen > MPA_MAX_PRIVATE_DATA) {

		CTR2(KTR_IW_CXGBE, "%s:pmr8 %p", __func__, ep);
		err = -EPROTO;
		goto err_stop_timer;
	}

	/*
	 * If plen does not account for pkt size
	 */
	if (ep->mpa_pkt_len > (sizeof(*mpa) + plen)) {

		CTR2(KTR_IW_CXGBE, "%s:pmr9 %p", __func__, ep);
		STOP_EP_TIMER(ep);
		err = -EPROTO;
		goto err_stop_timer;
	}

	ep->plen = (u8) plen;

	/*
	 * If we don't have all the pdata yet, then bail.
	 * We'll continue process when more data arrives.
	 */
	if (ep->mpa_pkt_len < (sizeof(*mpa) + plen)) {

		CTR2(KTR_IW_CXGBE, "%s:pmra %p", __func__, ep);
		return 0;
	}

	if (mpa->flags & MPA_REJECT) {

		CTR2(KTR_IW_CXGBE, "%s:pmrb %p", __func__, ep);
		err = -ECONNREFUSED;
		goto err_stop_timer;
	}

	/*
	 * If we get here we have accumulated the entire mpa
	 * start reply message including private data. And
	 * the MPA header is valid.
	 */
	state_set(&ep->com, FPDU_MODE);
	ep->mpa_attr.crc_enabled = (mpa->flags & MPA_CRC) | crc_enabled ? 1 : 0;
	ep->mpa_attr.recv_marker_enabled = markers_enabled;
	ep->mpa_attr.xmit_marker_enabled = mpa->flags & MPA_MARKERS ? 1 : 0;
	ep->mpa_attr.version = mpa->revision;
	ep->mpa_attr.p2p_type = FW_RI_INIT_P2PTYPE_DISABLED;

	if (mpa->revision == 2) {

		CTR2(KTR_IW_CXGBE, "%s:pmrc %p", __func__, ep);
		ep->mpa_attr.enhanced_rdma_conn =
			mpa->flags & MPA_ENHANCED_RDMA_CONN ? 1 : 0;

		if (ep->mpa_attr.enhanced_rdma_conn) {

			CTR2(KTR_IW_CXGBE, "%s:pmrd %p", __func__, ep);
			mpa_v2_params = (struct mpa_v2_conn_params *)
				(ep->mpa_pkt + sizeof(*mpa));
			resp_ird = ntohs(mpa_v2_params->ird) &
				MPA_V2_IRD_ORD_MASK;
			resp_ord = ntohs(mpa_v2_params->ord) &
				MPA_V2_IRD_ORD_MASK;

			/*
			 * This is a double-check. Ideally, below checks are
			 * not required since ird/ord stuff has been taken
			 * care of in c4iw_accept_cr
			 */
			if ((ep->ird < resp_ord) || (ep->ord > resp_ird)) {

				CTR2(KTR_IW_CXGBE, "%s:pmre %p", __func__, ep);
				err = -ENOMEM;
				ep->ird = resp_ord;
				ep->ord = resp_ird;
				insuff_ird = 1;
			}

			if (ntohs(mpa_v2_params->ird) &
				MPA_V2_PEER2PEER_MODEL) {

				CTR2(KTR_IW_CXGBE, "%s:pmrf %p", __func__, ep);
				if (ntohs(mpa_v2_params->ord) &
					MPA_V2_RDMA_WRITE_RTR) {

					CTR2(KTR_IW_CXGBE, "%s:pmrg %p", __func__, ep);
					ep->mpa_attr.p2p_type =
						FW_RI_INIT_P2PTYPE_RDMA_WRITE;
				}
				else if (ntohs(mpa_v2_params->ord) &
					MPA_V2_RDMA_READ_RTR) {

					CTR2(KTR_IW_CXGBE, "%s:pmrh %p", __func__, ep);
					ep->mpa_attr.p2p_type =
						FW_RI_INIT_P2PTYPE_READ_REQ;
				}
			}
		}
	} else {

		CTR2(KTR_IW_CXGBE, "%s:pmri %p", __func__, ep);

		if (mpa->revision == 1) {

			CTR2(KTR_IW_CXGBE, "%s:pmrj %p", __func__, ep);

			if (peer2peer) {

				CTR2(KTR_IW_CXGBE, "%s:pmrk %p", __func__, ep);
				ep->mpa_attr.p2p_type = p2p_type;
			}
		}
	}

	if (set_tcpinfo(ep)) {

		CTR2(KTR_IW_CXGBE, "%s:pmrl %p", __func__, ep);
		printf("%s set_tcpinfo error\n", __func__);
		err = -ECONNRESET;
		goto err;
	}

	CTR6(KTR_IW_CXGBE, "%s - crc_enabled = %d, recv_marker_enabled = %d, "
	    "xmit_marker_enabled = %d, version = %d p2p_type = %d", __func__,
	    ep->mpa_attr.crc_enabled, ep->mpa_attr.recv_marker_enabled,
	    ep->mpa_attr.xmit_marker_enabled, ep->mpa_attr.version,
	    ep->mpa_attr.p2p_type);

	/*
	 * If responder's RTR does not match with that of initiator, assign
	 * FW_RI_INIT_P2PTYPE_DISABLED in mpa attributes so that RTR is not
	 * generated when moving QP to RTS state.
	 * A TERM message will be sent after QP has moved to RTS state
	 */
	if ((ep->mpa_attr.version == 2) && peer2peer &&
		(ep->mpa_attr.p2p_type != p2p_type)) {

		CTR2(KTR_IW_CXGBE, "%s:pmrm %p", __func__, ep);
		ep->mpa_attr.p2p_type = FW_RI_INIT_P2PTYPE_DISABLED;
		rtr_mismatch = 1;
	}


	//ep->ofld_txq = TOEPCB(ep->com.so)->ofld_txq;
	attrs.mpa_attr = ep->mpa_attr;
	attrs.max_ird = ep->ird;
	attrs.max_ord = ep->ord;
	attrs.llp_stream_handle = ep;
	attrs.next_state = C4IW_QP_STATE_RTS;

	mask = C4IW_QP_ATTR_NEXT_STATE |
		C4IW_QP_ATTR_LLP_STREAM_HANDLE | C4IW_QP_ATTR_MPA_ATTR |
		C4IW_QP_ATTR_MAX_IRD | C4IW_QP_ATTR_MAX_ORD;

	/* bind QP and TID with INIT_WR */
	err = c4iw_modify_qp(ep->com.qp->rhp, ep->com.qp, mask, &attrs, 1);

	if (err) {

		CTR2(KTR_IW_CXGBE, "%s:pmrn %p", __func__, ep);
		goto err;
	}

	/*
	 * If responder's RTR requirement did not match with what initiator
	 * supports, generate TERM message
	 */
	if (rtr_mismatch) {

		CTR2(KTR_IW_CXGBE, "%s:pmro %p", __func__, ep);
		printk(KERN_ERR "%s: RTR mismatch, sending TERM\n", __func__);
		attrs.layer_etype = LAYER_MPA | DDP_LLP;
		attrs.ecode = MPA_NOMATCH_RTR;
		attrs.next_state = C4IW_QP_STATE_TERMINATE;
		err = c4iw_modify_qp(ep->com.qp->rhp, ep->com.qp,
			C4IW_QP_ATTR_NEXT_STATE, &attrs, 0);
		err = -ENOMEM;
		disconnect = 1;
		goto out;
	}

	/*
	 * Generate TERM if initiator IRD is not sufficient for responder
	 * provided ORD. Currently, we do the same behaviour even when
	 * responder provided IRD is also not sufficient as regards to
	 * initiator ORD.
	 */
	if (insuff_ird) {

		CTR2(KTR_IW_CXGBE, "%s:pmrp %p", __func__, ep);
		printk(KERN_ERR "%s: Insufficient IRD, sending TERM\n",
				__func__);
		attrs.layer_etype = LAYER_MPA | DDP_LLP;
		attrs.ecode = MPA_INSUFF_IRD;
		attrs.next_state = C4IW_QP_STATE_TERMINATE;
		err = c4iw_modify_qp(ep->com.qp->rhp, ep->com.qp,
			C4IW_QP_ATTR_NEXT_STATE, &attrs, 0);
		err = -ENOMEM;
		disconnect = 1;
		goto out;
	}
	goto out;
err_stop_timer:
	STOP_EP_TIMER(ep);
err:
	disconnect = 2;
out:
	connect_reply_upcall(ep, err);
	CTR2(KTR_IW_CXGBE, "%s:pmrE %p", __func__, ep);
	return disconnect;
}

/*
 * process_mpa_request - process streaming mode MPA request
 *
 * Returns:
 *
 * 0 upon success indicating a connect request was delivered to the ULP
 * or the mpa request is incomplete but valid so far.
 *
 * 1 if a failure requires the caller to close the connection.
 *
 * 2 if a failure requires the caller to abort the connection.
 */
static int
process_mpa_request(struct c4iw_ep *ep)
{
	struct mpa_message *mpa;
	u16 plen;
	int flags = MSG_DONTWAIT;
	int rc;
	kiovec_t iov;
	struct uio uio;
	enum c4iw_ep_state state = state_read(&ep->com);

	CTR3(KTR_IW_CXGBE, "%s: ep %p, state %s", __func__, ep, states[state]);

	if (state != MPA_REQ_WAIT)
		return 0;

	IOVEC_INIT(&iov, &ep->mpa_pkt[ep->mpa_pkt_len],
	    sizeof(ep->mpa_pkt) - ep->mpa_pkt_len);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = sizeof(ep->mpa_pkt) - ep->mpa_pkt_len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = NULL; /* uio.uio_td = ep->com.thread; */

	rc = soreceive(ep->com.so, NULL, &uio, NULL, NULL, &flags);
	if (rc == EAGAIN)
		return 0;
	else if (rc)
		goto err_stop_timer;

	KASSERT(uio.uio_offset > 0, ("%s: sorecieve on so %p read no data",
	    __func__, ep->com.so));
	ep->mpa_pkt_len += uio.uio_offset;

	/*
	 * If we get more than the supported amount of private data then we must
	 * fail this connection.  XXX: check so_rcv->sb_cc, or peek with another
	 * soreceive, or increase the size of mpa_pkt by 1 and abort if the last
	 * byte is filled by the soreceive above.
	 */

	/* Don't even have the MPA message.  Wait for more data to arrive. */
	if (ep->mpa_pkt_len < sizeof(*mpa))
		return 0;
	mpa = (struct mpa_message *) ep->mpa_pkt;

	/*
	 * Validate MPA Header.
	 */
	if (mpa->revision > mpa_rev) {
		log(LOG_ERR, "%s: MPA version mismatch. Local = %d,"
		    " Received = %d\n", __func__, mpa_rev, mpa->revision);
		goto err_stop_timer;
	}

	if (memcmp(mpa->key, MPA_KEY_REQ, sizeof(mpa->key)))
		goto err_stop_timer;

	/*
	 * Fail if there's too much private data.
	 */
	plen = ntohs(mpa->private_data_size);
	if (plen > MPA_MAX_PRIVATE_DATA)
		goto err_stop_timer;

	/*
	 * If plen does not account for pkt size
	 */
	if (ep->mpa_pkt_len > (sizeof(*mpa) + plen))
		goto err_stop_timer;

	ep->plen = (u8) plen;

	/*
	 * If we don't have all the pdata yet, then bail.
	 */
	if (ep->mpa_pkt_len < (sizeof(*mpa) + plen))
		return 0;

	/*
	 * If we get here we have accumulated the entire mpa
	 * start reply message including private data.
	 */
	ep->mpa_attr.initiator = 0;
	ep->mpa_attr.crc_enabled = (mpa->flags & MPA_CRC) | crc_enabled ? 1 : 0;
	ep->mpa_attr.recv_marker_enabled = markers_enabled;
	ep->mpa_attr.xmit_marker_enabled = mpa->flags & MPA_MARKERS ? 1 : 0;
	ep->mpa_attr.version = mpa->revision;
	if (mpa->revision == 1)
		ep->tried_with_mpa_v1 = 1;
	ep->mpa_attr.p2p_type = FW_RI_INIT_P2PTYPE_DISABLED;

	if (mpa->revision == 2) {
		ep->mpa_attr.enhanced_rdma_conn =
		    mpa->flags & MPA_ENHANCED_RDMA_CONN ? 1 : 0;
		if (ep->mpa_attr.enhanced_rdma_conn) {
			struct mpa_v2_conn_params *mpa_v2_params;
			u16 ird, ord;

			mpa_v2_params = (void *)&ep->mpa_pkt[sizeof(*mpa)];
			ird = ntohs(mpa_v2_params->ird);
			ord = ntohs(mpa_v2_params->ord);

			ep->ird = ird & MPA_V2_IRD_ORD_MASK;
			ep->ord = ord & MPA_V2_IRD_ORD_MASK;
			if (ird & MPA_V2_PEER2PEER_MODEL && peer2peer) {
				if (ord & MPA_V2_RDMA_WRITE_RTR) {
					ep->mpa_attr.p2p_type =
					    FW_RI_INIT_P2PTYPE_RDMA_WRITE;
				} else if (ord & MPA_V2_RDMA_READ_RTR) {
					ep->mpa_attr.p2p_type =
					    FW_RI_INIT_P2PTYPE_READ_REQ;
				}
			}
		}
	} else if (mpa->revision == 1 && peer2peer)
		ep->mpa_attr.p2p_type = p2p_type;

	if (set_tcpinfo(ep))
		goto err_stop_timer;

	CTR5(KTR_IW_CXGBE, "%s: crc_enabled = %d, recv_marker_enabled = %d, "
	    "xmit_marker_enabled = %d, version = %d", __func__,
	    ep->mpa_attr.crc_enabled, ep->mpa_attr.recv_marker_enabled,
	    ep->mpa_attr.xmit_marker_enabled, ep->mpa_attr.version);

	state_set(&ep->com, MPA_REQ_RCVD);
	STOP_EP_TIMER(ep);

	/* drive upcall */
	mutex_lock(&ep->parent_ep->com.mutex);
	if (ep->parent_ep->com.state != DEAD) {
		if (connect_request_upcall(ep))
			goto err_unlock_parent;
	} else
		goto err_unlock_parent;
	mutex_unlock(&ep->parent_ep->com.mutex);
	return 0;

err_unlock_parent:
	mutex_unlock(&ep->parent_ep->com.mutex);
	goto err_out;
err_stop_timer:
	STOP_EP_TIMER(ep);
err_out:
	return 2;
}

/*
 * Upcall from the adapter indicating data has been transmitted.
 * For us its just the single MPA request or reply.  We can now free
 * the skb holding the mpa message.
 */
int c4iw_reject_cr(struct iw_cm_id *cm_id, const void *pdata, u8 pdata_len)
{
	int err;
	struct c4iw_ep *ep = to_ep(cm_id);
	CTR2(KTR_IW_CXGBE, "%s:crcB %p", __func__, ep);
	int abort = 0;

	if ((state_read(&ep->com) == DEAD) ||
			(state_read(&ep->com) != MPA_REQ_RCVD)) {

		CTR2(KTR_IW_CXGBE, "%s:crc1 %p", __func__, ep);
		c4iw_put_ep(&ep->com);
		return -ECONNRESET;
	}
	set_bit(ULP_REJECT, &ep->com.history);

	if (mpa_rev == 0) {

		CTR2(KTR_IW_CXGBE, "%s:crc2 %p", __func__, ep);
		abort = 1;
	}
	else {

		CTR2(KTR_IW_CXGBE, "%s:crc3 %p", __func__, ep);
		abort = send_mpa_reject(ep, pdata, pdata_len);
	}
	stop_ep_timer(ep);
	err = c4iw_ep_disconnect(ep, abort != 0, GFP_KERNEL);
	c4iw_put_ep(&ep->com);
	CTR3(KTR_IW_CXGBE, "%s:crc4 %p, err: %d", __func__, ep, err);
	return 0;
}

int c4iw_accept_cr(struct iw_cm_id *cm_id, struct iw_cm_conn_param *conn_param)
{
	int err;
	struct c4iw_qp_attributes attrs;
	enum c4iw_qp_attr_mask mask;
	struct c4iw_ep *ep = to_ep(cm_id);
	struct c4iw_dev *h = to_c4iw_dev(cm_id->device);
	struct c4iw_qp *qp = get_qhp(h, conn_param->qpn);
	int abort = 0;

	CTR2(KTR_IW_CXGBE, "%s:cacB %p", __func__, ep);

	if (state_read(&ep->com) == DEAD) {

		CTR2(KTR_IW_CXGBE, "%s:cac1 %p", __func__, ep);
		err = -ECONNRESET;
		goto err_out;
	}

	BUG_ON(state_read(&ep->com) != MPA_REQ_RCVD);
	BUG_ON(!qp);

	set_bit(ULP_ACCEPT, &ep->com.history);

	if ((conn_param->ord > c4iw_max_read_depth) ||
		(conn_param->ird > c4iw_max_read_depth)) {

		CTR2(KTR_IW_CXGBE, "%s:cac2 %p", __func__, ep);
		err = -EINVAL;
		goto err_abort;
	}

	if (ep->mpa_attr.version == 2 && ep->mpa_attr.enhanced_rdma_conn) {

		CTR2(KTR_IW_CXGBE, "%s:cac3 %p", __func__, ep);

		if (conn_param->ord > ep->ird) {

			CTR2(KTR_IW_CXGBE, "%s:cac4 %p", __func__, ep);
			ep->ird = conn_param->ird;
			ep->ord = conn_param->ord;
			send_mpa_reject(ep, conn_param->private_data,
					conn_param->private_data_len);
			err = -ENOMEM;
			goto err_abort;
		}

		if (conn_param->ird > ep->ord) {

			CTR2(KTR_IW_CXGBE, "%s:cac5 %p", __func__, ep);

			if (!ep->ord) {

				CTR2(KTR_IW_CXGBE, "%s:cac6 %p", __func__, ep);
				conn_param->ird = 1;
			}
			else {
				CTR2(KTR_IW_CXGBE, "%s:cac7 %p", __func__, ep);
				err = -ENOMEM;
				goto err_abort;
			}
		}

	}
	ep->ird = conn_param->ird;
	ep->ord = conn_param->ord;

	if (ep->mpa_attr.version != 2) {

		CTR2(KTR_IW_CXGBE, "%s:cac8 %p", __func__, ep);

		if (peer2peer && ep->ird == 0) {

			CTR2(KTR_IW_CXGBE, "%s:cac9 %p", __func__, ep);
			ep->ird = 1;
		}
	}


	ep->com.cm_id = cm_id;
	ref_cm_id(&ep->com);
	ep->com.qp = qp;
	ref_qp(ep);
	//ep->ofld_txq = TOEPCB(ep->com.so)->ofld_txq;

	/* bind QP to EP and move to RTS */
	attrs.mpa_attr = ep->mpa_attr;
	attrs.max_ird = ep->ird;
	attrs.max_ord = ep->ord;
	attrs.llp_stream_handle = ep;
	attrs.next_state = C4IW_QP_STATE_RTS;

	/* bind QP and TID with INIT_WR */
	mask = C4IW_QP_ATTR_NEXT_STATE |
		C4IW_QP_ATTR_LLP_STREAM_HANDLE |
		C4IW_QP_ATTR_MPA_ATTR |
		C4IW_QP_ATTR_MAX_IRD |
		C4IW_QP_ATTR_MAX_ORD;

	err = c4iw_modify_qp(ep->com.qp->rhp, ep->com.qp, mask, &attrs, 1);

	if (err) {

		CTR2(KTR_IW_CXGBE, "%s:caca %p", __func__, ep);
		goto err_defef_cm_id;
	}
	err = send_mpa_reply(ep, conn_param->private_data,
			conn_param->private_data_len);

	if (err) {

		CTR2(KTR_IW_CXGBE, "%s:caca %p", __func__, ep);
		goto err_defef_cm_id;
	}

	state_set(&ep->com, FPDU_MODE);
	established_upcall(ep);
	c4iw_put_ep(&ep->com);
	CTR2(KTR_IW_CXGBE, "%s:cacE %p", __func__, ep);
	return 0;
err_defef_cm_id:
	deref_cm_id(&ep->com);
err_abort:
	abort = 1;
err_out:
	if (abort)
		c4iw_ep_disconnect(ep, 1, GFP_KERNEL);
	c4iw_put_ep(&ep->com);
	CTR2(KTR_IW_CXGBE, "%s:cacE err %p", __func__, ep);
	return err;
}



int c4iw_connect(struct iw_cm_id *cm_id, struct iw_cm_conn_param *conn_param)
{
	int err = 0;
	struct c4iw_dev *dev = to_c4iw_dev(cm_id->device);
	struct c4iw_ep *ep = NULL;
	struct nhop4_extended nh4;

	CTR2(KTR_IW_CXGBE, "%s:ccB %p", __func__, cm_id);

	if ((conn_param->ord > c4iw_max_read_depth) ||
		(conn_param->ird > c4iw_max_read_depth)) {

		CTR2(KTR_IW_CXGBE, "%s:cc1 %p", __func__, cm_id);
		err = -EINVAL;
		goto out;
	}
	ep = alloc_ep(sizeof(*ep), GFP_KERNEL);
	init_timer(&ep->timer);
	ep->plen = conn_param->private_data_len;

	if (ep->plen) {

		CTR2(KTR_IW_CXGBE, "%s:cc3 %p", __func__, ep);
		memcpy(ep->mpa_pkt + sizeof(struct mpa_message),
				conn_param->private_data, ep->plen);
	}
	ep->ird = conn_param->ird;
	ep->ord = conn_param->ord;

	if (peer2peer && ep->ord == 0) {

		CTR2(KTR_IW_CXGBE, "%s:cc4 %p", __func__, ep);
		ep->ord = 1;
	}

	ep->com.dev = dev;
	ep->com.cm_id = cm_id;
	ref_cm_id(&ep->com);
	ep->com.qp = get_qhp(dev, conn_param->qpn);

	if (!ep->com.qp) {

		CTR2(KTR_IW_CXGBE, "%s:cc5 %p", __func__, ep);
		err = -EINVAL;
		goto fail2;
	}
	ref_qp(ep);
	ep->com.thread = curthread;
	ep->com.so = cm_id->so;

	/* find a route */
	err = find_route(
		cm_id->local_addr.sin_addr.s_addr,
		cm_id->remote_addr.sin_addr.s_addr,
		cm_id->local_addr.sin_port,
		cm_id->remote_addr.sin_port, 0, &nh4);

	if (err) {

		CTR2(KTR_IW_CXGBE, "%s:cc7 %p", __func__, ep);
		printk(KERN_ERR MOD "%s - cannot find route.\n", __func__);
		err = -EHOSTUNREACH;
		goto fail2;
	}

	if (!(nh4.nh_ifp->if_capenable & IFCAP_TOE) ||
	    TOEDEV(nh4.nh_ifp) == NULL) {
		err = -ENOPROTOOPT;
		goto fail3;
	}
	fib4_free_nh_ext(RT_DEFAULT_FIB, &nh4);

	state_set(&ep->com, CONNECTING);
	ep->tos = 0;
	ep->com.local_addr = cm_id->local_addr;
	ep->com.remote_addr = cm_id->remote_addr;
	err = -soconnect(ep->com.so, (struct sockaddr *)&ep->com.remote_addr,
		ep->com.thread);

	if (!err) {
		init_iwarp_socket(cm_id->so, &ep->com);
		goto out;
	} else {
		goto fail2;
	}

fail3:
	fib4_free_nh_ext(RT_DEFAULT_FIB, &nh4);
fail2:
	deref_cm_id(&ep->com);
	c4iw_put_ep(&ep->com);
	ep = NULL;	/* CTR shouldn't display already-freed ep. */
out:
	CTR2(KTR_IW_CXGBE, "%s:ccE %p", __func__, ep);
	return err;
}

/*
 * iwcm->create_listen_ep.  Returns -errno on failure.
 */
int
c4iw_create_listen_ep(struct iw_cm_id *cm_id, int backlog)
{
	struct c4iw_dev *dev = to_c4iw_dev(cm_id->device);
	struct c4iw_listen_ep *ep;
	struct socket *so = cm_id->so;

	ep = alloc_ep(sizeof(*ep), GFP_KERNEL);
	ep->com.cm_id = cm_id;
	ref_cm_id(&ep->com);
	ep->com.dev = dev;
	ep->backlog = backlog;
	ep->com.local_addr = cm_id->local_addr;
	ep->com.thread = curthread;
	state_set(&ep->com, LISTEN);
	ep->com.so = so;

	cm_id->provider_data = ep;
	return (0);
}

void
c4iw_destroy_listen_ep(struct iw_cm_id *cm_id)
{
	struct c4iw_listen_ep *ep = to_listen_ep(cm_id);

	CTR4(KTR_IW_CXGBE, "%s: cm_id %p, so %p, state %s", __func__, cm_id,
	    cm_id->so, states[ep->com.state]);

	state_set(&ep->com, DEAD);
	deref_cm_id(&ep->com);
	c4iw_put_ep(&ep->com);

	return;
}

int c4iw_ep_disconnect(struct c4iw_ep *ep, int abrupt, gfp_t gfp)
{
	int ret = 0;
	int close = 0;
	int fatal = 0;
	struct c4iw_rdev *rdev;

	mutex_lock(&ep->com.mutex);

	CTR2(KTR_IW_CXGBE, "%s:cedB %p", __func__, ep);

	rdev = &ep->com.dev->rdev;

	if (c4iw_fatal_error(rdev)) {

		CTR2(KTR_IW_CXGBE, "%s:ced1 %p", __func__, ep);
		fatal = 1;
		close_complete_upcall(ep, -ECONNRESET);
		ep->com.state = DEAD;
	}
	CTR3(KTR_IW_CXGBE, "%s:ced2 %p %s", __func__, ep,
	    states[ep->com.state]);

	switch (ep->com.state) {

		case MPA_REQ_WAIT:
		case MPA_REQ_SENT:
		case MPA_REQ_RCVD:
		case MPA_REP_SENT:
		case FPDU_MODE:
			close = 1;
			if (abrupt)
				ep->com.state = ABORTING;
			else {
				ep->com.state = CLOSING;
				START_EP_TIMER(ep);
			}
			set_bit(CLOSE_SENT, &ep->com.flags);
			break;

		case CLOSING:

			if (!test_and_set_bit(CLOSE_SENT, &ep->com.flags)) {

				close = 1;
				if (abrupt) {
					STOP_EP_TIMER(ep);
					ep->com.state = ABORTING;
				} else
					ep->com.state = MORIBUND;
			}
			break;

		case MORIBUND:
		case ABORTING:
		case DEAD:
			CTR3(KTR_IW_CXGBE,
			    "%s ignoring disconnect ep %p state %u", __func__,
			    ep, ep->com.state);
			break;

		default:
			BUG();
			break;
	}

	mutex_unlock(&ep->com.mutex);

	if (close) {

		CTR2(KTR_IW_CXGBE, "%s:ced3 %p", __func__, ep);

		if (abrupt) {

			CTR2(KTR_IW_CXGBE, "%s:ced4 %p", __func__, ep);
			set_bit(EP_DISC_ABORT, &ep->com.history);
			close_complete_upcall(ep, -ECONNRESET);
			ret = send_abort(ep);
			if (ret)
				fatal = 1;
		} else {

			CTR2(KTR_IW_CXGBE, "%s:ced5 %p", __func__, ep);
			set_bit(EP_DISC_CLOSE, &ep->com.history);

			if (!ep->parent_ep)
				__state_set(&ep->com, MORIBUND);
			sodisconnect(ep->com.so);
		}

	}

	if (fatal) {
		set_bit(EP_DISC_FAIL, &ep->com.history);
		if (!abrupt) {
			STOP_EP_TIMER(ep);
			close_complete_upcall(ep, -EIO);
		}
		if (ep->com.qp) {
			struct c4iw_qp_attributes attrs;

			attrs.next_state = C4IW_QP_STATE_ERROR;
			ret = c4iw_modify_qp(ep->com.dev, ep->com.qp,
						C4IW_QP_ATTR_NEXT_STATE,
						&attrs, 1);
			if (ret) {
				CTR2(KTR_IW_CXGBE, "%s:ced7 %p", __func__, ep);
				printf("%s - qp <- error failed!\n", __func__);
			}
		}
		release_ep_resources(ep);
		ep->com.state = DEAD;
		CTR2(KTR_IW_CXGBE, "%s:ced6 %p", __func__, ep);
	}
	CTR2(KTR_IW_CXGBE, "%s:cedE %p", __func__, ep);
	return ret;
}

#ifdef C4IW_EP_REDIRECT
int c4iw_ep_redirect(void *ctx, struct dst_entry *old, struct dst_entry *new,
		struct l2t_entry *l2t)
{
	struct c4iw_ep *ep = ctx;

	if (ep->dst != old)
		return 0;

	PDBG("%s ep %p redirect to dst %p l2t %p\n", __func__, ep, new,
			l2t);
	dst_hold(new);
	cxgb4_l2t_release(ep->l2t);
	ep->l2t = l2t;
	dst_release(old);
	ep->dst = new;
	return 1;
}
#endif



static void ep_timeout(unsigned long arg)
{
	struct c4iw_ep *ep = (struct c4iw_ep *)arg;

	if (!test_and_set_bit(TIMEOUT, &ep->com.flags)) {

		/*
		 * Only insert if it is not already on the list.
		 */
		if (!(ep->com.ep_events & C4IW_EVENT_TIMEOUT)) {
			CTR2(KTR_IW_CXGBE, "%s:et1 %p", __func__, ep);
			add_ep_to_req_list(ep, C4IW_EVENT_TIMEOUT);
		}
	}
}

static int fw6_wr_rpl(struct adapter *sc, const __be64 *rpl)
{
	uint64_t val = be64toh(*rpl);
	int ret;
	struct c4iw_wr_wait *wr_waitp;

	ret = (int)((val >> 8) & 0xff);
	wr_waitp = (struct c4iw_wr_wait *)rpl[1];
	CTR3(KTR_IW_CXGBE, "%s wr_waitp %p ret %u", __func__, wr_waitp, ret);
	if (wr_waitp)
		c4iw_wake_up(wr_waitp, ret ? -ret : 0);

	return (0);
}

static int fw6_cqe_handler(struct adapter *sc, const __be64 *rpl)
{
	struct cqe_list_entry *cle;
	unsigned long flag;

	cle = malloc(sizeof(*cle), M_CXGBE, M_NOWAIT);
	cle->rhp = sc->iwarp_softc;
	cle->err_cqe = *(const struct t4_cqe *)(&rpl[0]);

	spin_lock_irqsave(&err_cqe_lock, flag);
	list_add_tail(&cle->entry, &err_cqe_list);
	queue_work(c4iw_taskq, &c4iw_task);
	spin_unlock_irqrestore(&err_cqe_lock, flag);

	return (0);
}

static int
process_terminate(struct c4iw_ep *ep)
{
	struct c4iw_qp_attributes attrs;

	CTR2(KTR_IW_CXGBE, "%s:tB %p %d", __func__, ep);

	if (ep && ep->com.qp) {

		printk(KERN_WARNING MOD "TERM received tid %u qpid %u\n",
				ep->hwtid, ep->com.qp->wq.sq.qid);
		attrs.next_state = C4IW_QP_STATE_TERMINATE;
		c4iw_modify_qp(ep->com.dev, ep->com.qp, C4IW_QP_ATTR_NEXT_STATE, &attrs,
				1);
	} else
		printk(KERN_WARNING MOD "TERM received tid %u no ep/qp\n",
								ep->hwtid);
	CTR2(KTR_IW_CXGBE, "%s:tE %p %d", __func__, ep);

	return 0;
}

int __init c4iw_cm_init(void)
{

	t4_register_cpl_handler(CPL_RDMA_TERMINATE, terminate);
	t4_register_fw_msg_handler(FW6_TYPE_WR_RPL, fw6_wr_rpl);
	t4_register_fw_msg_handler(FW6_TYPE_CQE, fw6_cqe_handler);
	t4_register_an_handler(c4iw_ev_handler);

	TAILQ_INIT(&req_list);
	spin_lock_init(&req_lock);
	INIT_LIST_HEAD(&err_cqe_list);
	spin_lock_init(&err_cqe_lock);

	INIT_WORK(&c4iw_task, process_req);

	c4iw_taskq = create_singlethread_workqueue("iw_cxgbe");
	if (!c4iw_taskq)
		return -ENOMEM;

	return 0;
}

void __exit c4iw_cm_term(void)
{
	WARN_ON(!TAILQ_EMPTY(&req_list));
	WARN_ON(!list_empty(&err_cqe_list));
	flush_workqueue(c4iw_taskq);
	destroy_workqueue(c4iw_taskq);

	t4_register_cpl_handler(CPL_RDMA_TERMINATE, NULL);
	t4_register_fw_msg_handler(FW6_TYPE_WR_RPL, NULL);
	t4_register_fw_msg_handler(FW6_TYPE_CQE, NULL);
	t4_register_an_handler(NULL);
}
#endif
