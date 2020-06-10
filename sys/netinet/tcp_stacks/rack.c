/*-
 * Copyright (c) 2016-2020 Netflix, Inc.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#include "opt_tcpdebug.h"
#include "opt_ratelimit.h"
#include "opt_kern_tls.h"
#include <sys/param.h>
#include <sys/arb.h>
#include <sys/module.h>
#include <sys/kernel.h>
#ifdef TCP_HHOOK
#include <sys/hhook.h>
#endif
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/proc.h>		/* for proc0 declaration */
#include <sys/socket.h>
#include <sys/socketvar.h>
#ifdef KERN_TLS
#include <sys/ktls.h>
#endif
#include <sys/sysctl.h>
#include <sys/systm.h>
#ifdef STATS
#include <sys/qmath.h>
#include <sys/tree.h>
#include <sys/stats.h> /* Must come after qmath.h and tree.h */
#else
#include <sys/tree.h>
#endif
#include <sys/refcount.h>
#include <sys/queue.h>
#include <sys/tim_filter.h>
#include <sys/smp.h>
#include <sys/kthread.h>
#include <sys/kern_prefetch.h>
#include <sys/protosw.h>

#include <vm/uma.h>

#include <net/route.h>
#include <net/route/nhop.h>
#include <net/vnet.h>

#define TCPSTATES		/* for logging */

#include <netinet/in.h>
#include <netinet/in_kdtrace.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>	/* required for icmp_var.h */
#include <netinet/icmp_var.h>	/* for ICMP_BANDLIM */
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet/tcp.h>
#define	TCPOUTFLAGS
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_log_buf.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_hpts.h>
#include <netinet/tcp_ratelimit.h>
#include <netinet/tcpip.h>
#include <netinet/cc/cc.h>
#include <netinet/tcp_fastopen.h>
#include <netinet/tcp_lro.h>
#ifdef NETFLIX_SHARED_CWND
#include <netinet/tcp_shared_cwnd.h>
#endif
#ifdef TCPDEBUG
#include <netinet/tcp_debug.h>
#endif				/* TCPDEBUG */
#ifdef TCP_OFFLOAD
#include <netinet/tcp_offload.h>
#endif
#ifdef INET6
#include <netinet6/tcp6_var.h>
#endif

#include <netipsec/ipsec_support.h>

#if defined(IPSEC) || defined(IPSEC_SUPPORT)
#include <netipsec/ipsec.h>
#include <netipsec/ipsec6.h>
#endif				/* IPSEC */

#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <machine/in_cksum.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif
#include "sack_filter.h"
#include "tcp_rack.h"
#include "rack_bbr_common.h"

uma_zone_t rack_zone;
uma_zone_t rack_pcb_zone;

#ifndef TICKS2SBT
#define	TICKS2SBT(__t)	(tick_sbt * ((sbintime_t)(__t)))
#endif

struct sysctl_ctx_list rack_sysctl_ctx;
struct sysctl_oid *rack_sysctl_root;

#define CUM_ACKED 1
#define SACKED 2

/*
 * The RACK module incorporates a number of
 * TCP ideas that have been put out into the IETF
 * over the last few years:
 * - Matt Mathis's Rate Halving which slowly drops
 *    the congestion window so that the ack clock can
 *    be maintained during a recovery.
 * - Yuchung Cheng's RACK TCP (for which its named) that
 *    will stop us using the number of dup acks and instead
 *    use time as the gage of when we retransmit.
 * - Reorder Detection of RFC4737 and the Tail-Loss probe draft
 *    of Dukkipati et.al.
 * RACK depends on SACK, so if an endpoint arrives that
 * cannot do SACK the state machine below will shuttle the
 * connection back to using the "default" TCP stack that is
 * in FreeBSD.
 *
 * To implement RACK the original TCP stack was first decomposed
 * into a functional state machine with individual states
 * for each of the possible TCP connection states. The do_segement
 * functions role in life is to mandate the connection supports SACK
 * initially and then assure that the RACK state matches the conenction
 * state before calling the states do_segment function. Each
 * state is simplified due to the fact that the original do_segment
 * has been decomposed and we *know* what state we are in (no
 * switches on the state) and all tests for SACK are gone. This
 * greatly simplifies what each state does.
 *
 * TCP output is also over-written with a new version since it
 * must maintain the new rack scoreboard.
 *
 */
static int32_t rack_tlp_thresh = 1;
static int32_t rack_tlp_limit = 2;	/* No more than 2 TLPs w-out new data */
static int32_t rack_tlp_use_greater = 1;
static int32_t rack_reorder_thresh = 2;
static int32_t rack_reorder_fade = 60000;	/* 0 - never fade, def 60,000
						 * - 60 seconds */
/* Attack threshold detections */
static uint32_t rack_highest_sack_thresh_seen = 0;
static uint32_t rack_highest_move_thresh_seen = 0;

static int32_t rack_pkt_delay = 1;
static int32_t rack_early_recovery = 1;
static int32_t rack_send_a_lot_in_prr = 1;
static int32_t rack_min_to = 1;	/* Number of ms minimum timeout */
static int32_t rack_verbose_logging = 0;
static int32_t rack_ignore_data_after_close = 1;
static int32_t rack_enable_shared_cwnd = 0;
static int32_t rack_limits_scwnd = 1;
static int32_t rack_enable_mqueue_for_nonpaced = 0;
static int32_t rack_disable_prr = 0;
static int32_t use_rack_rr = 1;
static int32_t rack_non_rxt_use_cr = 0; /* does a non-rxt in recovery use the configured rate (ss/ca)? */
static int32_t rack_persist_min = 250;	/* 250ms */
static int32_t rack_persist_max = 2000;	/* 2 Second */
static int32_t rack_sack_not_required = 0;	/* set to one to allow non-sack to use rack */
static int32_t rack_hw_tls_max_seg = 3; /* 3 means use hw-tls single segment */
static int32_t rack_default_init_window = 0; 	/* Use system default */
static int32_t rack_limit_time_with_srtt = 0;
static int32_t rack_hw_pace_adjust = 0;
/*
 * Currently regular tcp has a rto_min of 30ms
 * the backoff goes 12 times so that ends up
 * being a total of 122.850 seconds before a
 * connection is killed.
 */
static uint32_t rack_def_data_window = 20;
static uint32_t rack_goal_bdp = 2;
static uint32_t rack_min_srtts = 1;
static uint32_t rack_min_measure_usec = 0;
static int32_t rack_tlp_min = 10;
static int32_t rack_rto_min = 30;	/* 30ms same as main freebsd */
static int32_t rack_rto_max = 4000;	/* 4 seconds */
static const int32_t rack_free_cache = 2;
static int32_t rack_hptsi_segments = 40;
static int32_t rack_rate_sample_method = USE_RTT_LOW;
static int32_t rack_pace_every_seg = 0;
static int32_t rack_delayed_ack_time = 200;	/* 200ms */
static int32_t rack_slot_reduction = 4;
static int32_t rack_wma_divisor = 8;		/* For WMA calculation */
static int32_t rack_cwnd_block_ends_measure = 0;
static int32_t rack_rwnd_block_ends_measure = 0;

static int32_t rack_lower_cwnd_at_tlp = 0;
static int32_t rack_use_proportional_reduce = 0;
static int32_t rack_proportional_rate = 10;
static int32_t rack_tlp_max_resend = 2;
static int32_t rack_limited_retran = 0;
static int32_t rack_always_send_oldest = 0;
static int32_t rack_tlp_threshold_use = TLP_USE_TWO_ONE;

static uint16_t rack_per_of_gp_ss = 250;	/* 250 % slow-start */
static uint16_t rack_per_of_gp_ca = 200;	/* 200 % congestion-avoidance */
static uint16_t rack_per_of_gp_rec = 200;	/* 200 % of bw */

/* Probertt */
static uint16_t rack_per_of_gp_probertt = 60;	/* 60% of bw */
static uint16_t rack_per_of_gp_lowthresh = 40;	/* 40% is bottom */
static uint16_t rack_per_of_gp_probertt_reduce = 10; /* 10% reduction */
static uint16_t rack_atexit_prtt_hbp = 130;	/* Clamp to 130% on exit prtt if highly buffered path */
static uint16_t rack_atexit_prtt = 130;	/* Clamp to 100% on exit prtt if non highly buffered path */

static uint32_t rack_max_drain_wait = 2;	/* How man gp srtt's before we give up draining */
static uint32_t rack_must_drain = 1;		/* How many GP srtt's we *must* wait */
static uint32_t rack_probertt_use_min_rtt_entry = 1;	/* Use the min to calculate the goal else gp_srtt */
static uint32_t rack_probertt_use_min_rtt_exit = 0;
static uint32_t rack_probe_rtt_sets_cwnd = 0;
static uint32_t rack_probe_rtt_safety_val = 2000000;	/* No more than 2 sec in probe-rtt */
static uint32_t rack_time_between_probertt = 9600000;	/* 9.6 sec in us */
static uint32_t rack_probertt_gpsrtt_cnt_mul = 0;	/* How many srtt periods does probe-rtt last top fraction */
static uint32_t rack_probertt_gpsrtt_cnt_div = 0;	/* How many srtt periods does probe-rtt last bottom fraction  */
static uint32_t rack_min_probertt_hold = 200000;	/* Equal to delayed ack time */
static uint32_t rack_probertt_filter_life = 10000000;
static uint32_t rack_probertt_lower_within = 10;
static uint32_t rack_min_rtt_movement = 250;	/* Must move at least 250 useconds to count as a lowering */
static int32_t rack_pace_one_seg = 0;		/* Shall we pace for less than 1.4Meg 1MSS at a time */
static int32_t rack_probertt_clear_is = 1;
static int32_t rack_max_drain_hbp = 1;		/* Extra drain times gpsrtt for highly buffered paths */
static int32_t rack_hbp_thresh = 3;		/* what is the divisor max_rtt/min_rtt to decided a hbp */


/* Part of pacing */
static int32_t rack_max_per_above = 30;		/* When we go to increment stop if above 100+this% */

/* Timely information */
/* Combine these two gives the range of 'no change' to bw */
/* ie the up/down provide the upper and lower bound  */
static int32_t rack_gp_per_bw_mul_up = 2;	/* 2% */
static int32_t rack_gp_per_bw_mul_down = 4;	/* 4% */
static int32_t rack_gp_rtt_maxmul = 3;		/* 3 x maxmin */
static int32_t rack_gp_rtt_minmul = 1;		/* minrtt + (minrtt/mindiv) is lower rtt */
static int32_t rack_gp_rtt_mindiv = 4;		/* minrtt + (minrtt * minmul/mindiv) is lower rtt */
static int32_t rack_gp_decrease_per = 20;	/* 20% decrease in multipler */
static int32_t rack_gp_increase_per = 2;	/* 2% increase in multipler */
static int32_t rack_per_lower_bound = 50;	/* Don't allow to drop below this multiplier */
static int32_t rack_per_upper_bound_ss = 0;	/* Don't allow SS to grow above this */
static int32_t rack_per_upper_bound_ca = 0;	/* Don't allow CA to grow above this */
static int32_t rack_do_dyn_mul = 0;		/* Are the rack gp multipliers dynamic */
static int32_t rack_gp_no_rec_chg = 1;		/* Prohibit recovery from reducing it's multiplier */
static int32_t rack_timely_dec_clear = 6;	/* Do we clear decrement count at a value (6)? */
static int32_t rack_timely_max_push_rise = 3;	/* One round of pushing */
static int32_t rack_timely_max_push_drop = 3;	/* Three round of pushing */
static int32_t rack_timely_min_segs = 4;	/* 4 segment minimum */
static int32_t rack_use_max_for_nobackoff = 0;
static int32_t rack_timely_int_timely_only = 0;	/* do interim timely's only use the timely algo (no b/w changes)? */
static int32_t rack_timely_no_stopping = 0;
static int32_t rack_down_raise_thresh = 100;
static int32_t rack_req_segs = 1;

/* Weird delayed ack mode */
static int32_t rack_use_imac_dack = 0;
/* Rack specific counters */
counter_u64_t rack_badfr;
counter_u64_t rack_badfr_bytes;
counter_u64_t rack_rtm_prr_retran;
counter_u64_t rack_rtm_prr_newdata;
counter_u64_t rack_timestamp_mismatch;
counter_u64_t rack_reorder_seen;
counter_u64_t rack_paced_segments;
counter_u64_t rack_unpaced_segments;
counter_u64_t rack_calc_zero;
counter_u64_t rack_calc_nonzero;
counter_u64_t rack_saw_enobuf;
counter_u64_t rack_saw_enetunreach;
counter_u64_t rack_per_timer_hole;

/* Tail loss probe counters */
counter_u64_t rack_tlp_tot;
counter_u64_t rack_tlp_newdata;
counter_u64_t rack_tlp_retran;
counter_u64_t rack_tlp_retran_bytes;
counter_u64_t rack_tlp_retran_fail;
counter_u64_t rack_to_tot;
counter_u64_t rack_to_arm_rack;
counter_u64_t rack_to_arm_tlp;
counter_u64_t rack_to_alloc;
counter_u64_t rack_to_alloc_hard;
counter_u64_t rack_to_alloc_emerg;
counter_u64_t rack_to_alloc_limited;
counter_u64_t rack_alloc_limited_conns;
counter_u64_t rack_split_limited;

counter_u64_t rack_sack_proc_all;
counter_u64_t rack_sack_proc_short;
counter_u64_t rack_sack_proc_restart;
counter_u64_t rack_sack_attacks_detected;
counter_u64_t rack_sack_attacks_reversed;
counter_u64_t rack_sack_used_next_merge;
counter_u64_t rack_sack_splits;
counter_u64_t rack_sack_used_prev_merge;
counter_u64_t rack_sack_skipped_acked;
counter_u64_t rack_ack_total;
counter_u64_t rack_express_sack;
counter_u64_t rack_sack_total;
counter_u64_t rack_move_none;
counter_u64_t rack_move_some;

counter_u64_t rack_used_tlpmethod;
counter_u64_t rack_used_tlpmethod2;
counter_u64_t rack_enter_tlp_calc;
counter_u64_t rack_input_idle_reduces;
counter_u64_t rack_collapsed_win;
counter_u64_t rack_tlp_does_nada;
counter_u64_t rack_try_scwnd;

/* Counters for HW TLS */
counter_u64_t rack_tls_rwnd;
counter_u64_t rack_tls_cwnd;
counter_u64_t rack_tls_app;
counter_u64_t rack_tls_other;
counter_u64_t rack_tls_filled;
counter_u64_t rack_tls_rxt;
counter_u64_t rack_tls_tlp;

/* Temp CPU counters */
counter_u64_t rack_find_high;

counter_u64_t rack_progress_drops;
counter_u64_t rack_out_size[TCP_MSS_ACCT_SIZE];
counter_u64_t rack_opts_arry[RACK_OPTS_SIZE];

static void
rack_log_progress_event(struct tcp_rack *rack, struct tcpcb *tp, uint32_t tick,  int event, int line);

static int
rack_process_ack(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to,
    uint32_t tiwin, int32_t tlen, int32_t * ofia, int32_t thflags, int32_t * ret_val);
static int
rack_process_data(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);
static void
rack_ack_received(struct tcpcb *tp, struct tcp_rack *rack,
    struct tcphdr *th, uint16_t nsegs, uint16_t type, int32_t recovery);
static struct rack_sendmap *rack_alloc(struct tcp_rack *rack);
static struct rack_sendmap *rack_alloc_limit(struct tcp_rack *rack,
    uint8_t limit_type);
static struct rack_sendmap *
rack_check_recovery_mode(struct tcpcb *tp,
    uint32_t tsused);
static void
rack_cong_signal(struct tcpcb *tp, struct tcphdr *th,
    uint32_t type);
static void rack_counter_destroy(void);
static int
rack_ctloutput(struct socket *so, struct sockopt *sopt,
    struct inpcb *inp, struct tcpcb *tp);
static int32_t rack_ctor(void *mem, int32_t size, void *arg, int32_t how);
static void
rack_set_pace_segments(struct tcpcb *tp, struct tcp_rack *rack, uint32_t line);
static void
rack_do_segment(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen,
    uint8_t iptos);
static void rack_dtor(void *mem, int32_t size, void *arg);
static void
rack_earlier_retran(struct tcpcb *tp, struct rack_sendmap *rsm,
    uint32_t t, uint32_t cts);
static void
rack_log_alt_to_to_cancel(struct tcp_rack *rack,
    uint32_t flex1, uint32_t flex2,
    uint32_t flex3, uint32_t flex4,
    uint32_t flex5, uint32_t flex6,
    uint16_t flex7, uint8_t mod);
static void
rack_log_pacing_delay_calc(struct tcp_rack *rack, uint32_t len, uint32_t slot,
   uint64_t bw_est, uint64_t bw, uint64_t len_time, int method, int line, struct rack_sendmap *rsm);
static struct rack_sendmap *
rack_find_high_nonack(struct tcp_rack *rack,
    struct rack_sendmap *rsm);
static struct rack_sendmap *rack_find_lowest_rsm(struct tcp_rack *rack);
static void rack_free(struct tcp_rack *rack, struct rack_sendmap *rsm);
static void rack_fini(struct tcpcb *tp, int32_t tcb_is_purged);
static int
rack_get_sockopt(struct socket *so, struct sockopt *sopt,
    struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack);
static void
rack_do_goodput_measurement(struct tcpcb *tp, struct tcp_rack *rack,
			    tcp_seq th_ack, int line);
static uint32_t
rack_get_pacing_len(struct tcp_rack *rack, uint64_t bw, uint32_t mss);
static int32_t rack_handoff_ok(struct tcpcb *tp);
static int32_t rack_init(struct tcpcb *tp);
static void rack_init_sysctls(void);
static void
rack_log_ack(struct tcpcb *tp, struct tcpopt *to,
    struct tcphdr *th);
static void
rack_log_output(struct tcpcb *tp, struct tcpopt *to, int32_t len,
    uint32_t seq_out, uint8_t th_flags, int32_t err, uint32_t ts,
    uint8_t pass, struct rack_sendmap *hintrsm, uint32_t us_cts);
static void
rack_log_sack_passed(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm);
static void rack_log_to_event(struct tcp_rack *rack, int32_t to_num, struct rack_sendmap *rsm);
static int32_t rack_output(struct tcpcb *tp);

static uint32_t
rack_proc_sack_blk(struct tcpcb *tp, struct tcp_rack *rack,
    struct sackblk *sack, struct tcpopt *to, struct rack_sendmap **prsm,
    uint32_t cts, int *moved_two);
static void rack_post_recovery(struct tcpcb *tp, struct tcphdr *th);
static void rack_remxt_tmr(struct tcpcb *tp);
static int
rack_set_sockopt(struct socket *so, struct sockopt *sopt,
    struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack);
static void rack_set_state(struct tcpcb *tp, struct tcp_rack *rack);
static int32_t rack_stopall(struct tcpcb *tp);
static void
rack_timer_activate(struct tcpcb *tp, uint32_t timer_type,
    uint32_t delta);
static int32_t rack_timer_active(struct tcpcb *tp, uint32_t timer_type);
static void rack_timer_cancel(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, int line);
static void rack_timer_stop(struct tcpcb *tp, uint32_t timer_type);
static uint32_t
rack_update_entry(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm, uint32_t ts, int32_t * lenp);
static void
rack_update_rsm(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm, uint32_t ts);
static int
rack_update_rtt(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm, struct tcpopt *to, uint32_t cts, int32_t ack_type, tcp_seq th_ack);
static int32_t tcp_addrack(module_t mod, int32_t type, void *data);
static int
rack_do_close_wait(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_closing(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_established(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_fastnewdata(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_fin_wait_1(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_fin_wait_2(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_lastack(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_syn_recv(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
static int
rack_do_syn_sent(struct mbuf *m, struct tcphdr *th,
    struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen,
    int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos);
struct rack_sendmap *
tcp_rack_output(struct tcpcb *tp, struct tcp_rack *rack,
    uint32_t tsused);
static void tcp_rack_xmit_timer(struct tcp_rack *rack, int32_t rtt,
    uint32_t len, uint32_t us_tim, int confidence, struct rack_sendmap *rsm, uint16_t rtrcnt);
static void
     tcp_rack_partialack(struct tcpcb *tp, struct tcphdr *th);

int32_t rack_clear_counter=0;


static int
sysctl_rack_clear(SYSCTL_HANDLER_ARGS)
{
	uint32_t stat;
	int32_t error;

	error = SYSCTL_OUT(req, &rack_clear_counter, sizeof(uint32_t));
	if (error || req->newptr == NULL)
		return error;

	error = SYSCTL_IN(req, &stat, sizeof(uint32_t));
	if (error)
		return (error);
	if (stat == 1) {
#ifdef INVARIANTS
		printf("Clearing RACK counters\n");
#endif
		counter_u64_zero(rack_badfr);
		counter_u64_zero(rack_badfr_bytes);
		counter_u64_zero(rack_rtm_prr_retran);
		counter_u64_zero(rack_rtm_prr_newdata);
		counter_u64_zero(rack_timestamp_mismatch);
		counter_u64_zero(rack_reorder_seen);
		counter_u64_zero(rack_tlp_tot);
		counter_u64_zero(rack_tlp_newdata);
		counter_u64_zero(rack_tlp_retran);
		counter_u64_zero(rack_tlp_retran_bytes);
		counter_u64_zero(rack_tlp_retran_fail);
		counter_u64_zero(rack_to_tot);
		counter_u64_zero(rack_to_arm_rack);
		counter_u64_zero(rack_to_arm_tlp);
		counter_u64_zero(rack_paced_segments);
		counter_u64_zero(rack_calc_zero);
		counter_u64_zero(rack_calc_nonzero);
		counter_u64_zero(rack_unpaced_segments);
		counter_u64_zero(rack_saw_enobuf);
		counter_u64_zero(rack_saw_enetunreach);
		counter_u64_zero(rack_per_timer_hole);
		counter_u64_zero(rack_to_alloc_hard);
		counter_u64_zero(rack_to_alloc_emerg);
		counter_u64_zero(rack_sack_proc_all);
		counter_u64_zero(rack_sack_proc_short);
		counter_u64_zero(rack_sack_proc_restart);
		counter_u64_zero(rack_to_alloc);
		counter_u64_zero(rack_to_alloc_limited);
		counter_u64_zero(rack_alloc_limited_conns);
		counter_u64_zero(rack_split_limited);
		counter_u64_zero(rack_find_high);
		counter_u64_zero(rack_tls_rwnd);
		counter_u64_zero(rack_tls_cwnd);
		counter_u64_zero(rack_tls_app);
		counter_u64_zero(rack_tls_other);
		counter_u64_zero(rack_tls_filled);
		counter_u64_zero(rack_tls_rxt);
		counter_u64_zero(rack_tls_tlp);
		counter_u64_zero(rack_sack_attacks_detected);
		counter_u64_zero(rack_sack_attacks_reversed);
		counter_u64_zero(rack_sack_used_next_merge);
		counter_u64_zero(rack_sack_used_prev_merge);
		counter_u64_zero(rack_sack_splits);
		counter_u64_zero(rack_sack_skipped_acked);
		counter_u64_zero(rack_ack_total);
		counter_u64_zero(rack_express_sack);
		counter_u64_zero(rack_sack_total);
		counter_u64_zero(rack_move_none);
		counter_u64_zero(rack_move_some);
		counter_u64_zero(rack_used_tlpmethod);
		counter_u64_zero(rack_used_tlpmethod2);
		counter_u64_zero(rack_enter_tlp_calc);
		counter_u64_zero(rack_progress_drops);
		counter_u64_zero(rack_tlp_does_nada);
		counter_u64_zero(rack_try_scwnd);
		counter_u64_zero(rack_collapsed_win);

	}
	rack_clear_counter = 0;
	return (0);
}



static void
rack_init_sysctls(void)
{
	struct sysctl_oid *rack_counters;
	struct sysctl_oid *rack_attack;
	struct sysctl_oid *rack_pacing;
	struct sysctl_oid *rack_timely;
	struct sysctl_oid *rack_timers;
	struct sysctl_oid *rack_tlp;
	struct sysctl_oid *rack_misc;
	struct sysctl_oid *rack_measure;
	struct sysctl_oid *rack_probertt;

	rack_attack = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "sack_attack",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Rack Sack Attack Counters and Controls");
	rack_counters = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "stats",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Rack Counters");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO, "rate_sample_method", CTLFLAG_RW,
	    &rack_rate_sample_method , USE_RTT_LOW,
	    "What method should we use for rate sampling 0=high, 1=low ");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO, "hw_tlsmax", CTLFLAG_RW,
	    &rack_hw_tls_max_seg , 3,
	    "What is the maximum number of full TLS records that will be sent at once");
	/* Probe rtt related controls */
	rack_probertt = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "probertt",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "ProbeRTT related Controls");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "exit_per_hpb", CTLFLAG_RW,
	    &rack_atexit_prtt_hbp, 130,
	    "What percentage above goodput do we clamp CA/SS to at exit on high-BDP path 110%");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "exit_per_nonhpb", CTLFLAG_RW,
	    &rack_atexit_prtt, 130,
	    "What percentage above goodput do we clamp CA/SS to at exit on a non high-BDP path 100%");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "gp_per_mul", CTLFLAG_RW,
	    &rack_per_of_gp_probertt, 60,
	    "What percentage of goodput do we pace at in probertt");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "gp_per_reduce", CTLFLAG_RW,
	    &rack_per_of_gp_probertt_reduce, 10,
	    "What percentage of goodput do we reduce every gp_srtt");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "gp_per_low", CTLFLAG_RW,
	    &rack_per_of_gp_lowthresh, 40,
	    "What percentage of goodput do we allow the multiplier to fall to");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "time_between", CTLFLAG_RW,
	    & rack_time_between_probertt, 96000000,
	    "How many useconds between the lowest rtt falling must past before we enter probertt");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "safety", CTLFLAG_RW,
	    &rack_probe_rtt_safety_val, 2000000,
	    "If not zero, provides a maximum usecond that you can stay in probertt (2sec = 2000000)");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "sets_cwnd", CTLFLAG_RW,
	    &rack_probe_rtt_sets_cwnd, 0,
	    "Do we set the cwnd too (if always_lower is on)");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "maxdrainsrtts", CTLFLAG_RW,
	    &rack_max_drain_wait, 2,
	    "Maximum number of gp_srtt's to hold in drain waiting for flight to reach goal");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "mustdrainsrtts", CTLFLAG_RW,
	    &rack_must_drain, 1,
	    "We must drain this many gp_srtt's waiting for flight to reach goal");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "goal_use_min_entry", CTLFLAG_RW,
	    &rack_probertt_use_min_rtt_entry, 1,
	    "Should we use the min-rtt to calculate the goal rtt (else gp_srtt) at entry");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "goal_use_min_exit", CTLFLAG_RW,
	    &rack_probertt_use_min_rtt_exit, 0,
	    "How to set cwnd at exit, 0 - dynamic, 1 - use min-rtt, 2 - use curgprtt, 3 - entry gp-rtt");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "length_div", CTLFLAG_RW,
	    &rack_probertt_gpsrtt_cnt_div, 0,
	    "How many recent goodput srtt periods plus hold tim does probertt last (bottom of fraction)");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "length_mul", CTLFLAG_RW,
	    &rack_probertt_gpsrtt_cnt_mul, 0,
	    "How many recent goodput srtt periods plus hold tim does probertt last (top of fraction)");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "holdtim_at_target", CTLFLAG_RW,
	    &rack_min_probertt_hold, 200000,
	    "What is the minimum time we hold probertt at target");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "filter_life", CTLFLAG_RW,
	    &rack_probertt_filter_life, 10000000,
	    "What is the time for the filters life in useconds");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "lower_within", CTLFLAG_RW,
	    &rack_probertt_lower_within, 10,
	    "If the rtt goes lower within this percentage of the time, go into probe-rtt");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "must_move", CTLFLAG_RW,
	    &rack_min_rtt_movement, 250,
	    "How much is the minimum movement in rtt to count as a drop for probertt purposes");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "clear_is_cnts", CTLFLAG_RW,
	    &rack_probertt_clear_is, 1,
	    "Do we clear I/S counts on exiting probe-rtt");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "hbp_extra_drain", CTLFLAG_RW,
	    &rack_max_drain_hbp, 1,
	    "How many extra drain gpsrtt's do we get in highly buffered paths");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_probertt),
	    OID_AUTO, "hbp_threshold", CTLFLAG_RW,
	    &rack_hbp_thresh, 3,
	    "We are highly buffered if min_rtt_seen / max_rtt_seen > this-threshold");
	/* Pacing related sysctls */
	rack_pacing = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "pacing",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Pacing related Controls");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "max_pace_over", CTLFLAG_RW,
	    &rack_max_per_above, 30,
	    "What is the maximum allowable percentage that we can pace above (so 30 = 130% of our goal)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "pace_to_one", CTLFLAG_RW,
	    &rack_pace_one_seg, 0,
	    "Do we allow low b/w pacing of 1MSS instead of two");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "limit_wsrtt", CTLFLAG_RW,
	    &rack_limit_time_with_srtt, 0,
	    "Do we limit pacing time based on srtt");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "init_win", CTLFLAG_RW,
	    &rack_default_init_window, 0,
	    "Do we have a rack initial window 0 = system default");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "hw_pacing_adjust", CTLFLAG_RW,
	    &rack_hw_pace_adjust, 0,
	    "What percentage do we raise the MSS by (11 = 1.1%)");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "gp_per_ss", CTLFLAG_RW,
	    &rack_per_of_gp_ss, 250,
	    "If non zero, what percentage of goodput to pace at in slow start");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "gp_per_ca", CTLFLAG_RW,
	    &rack_per_of_gp_ca, 150,
	    "If non zero, what percentage of goodput to pace at in congestion avoidance");
	SYSCTL_ADD_U16(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "gp_per_rec", CTLFLAG_RW,
	    &rack_per_of_gp_rec, 200,
	    "If non zero, what percentage of goodput to pace at in recovery");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "pace_max_seg", CTLFLAG_RW,
	    &rack_hptsi_segments, 40,
	    "What size is the max for TSO segments in pacing and burst mitigation");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_pacing),
	    OID_AUTO, "burst_reduces", CTLFLAG_RW,
	    &rack_slot_reduction, 4,
	    "When doing only burst mitigation what is the reduce divisor");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO, "use_pacing", CTLFLAG_RW,
	    &rack_pace_every_seg, 0,
	    "If set we use pacing, if clear we use only the original burst mitigation");

	rack_timely = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "timely",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Rack Timely RTT Controls");
	/* Timely based GP dynmics */
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "upper", CTLFLAG_RW,
	    &rack_gp_per_bw_mul_up, 2,
	    "Rack timely upper range for equal b/w (in percentage)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "lower", CTLFLAG_RW,
	    &rack_gp_per_bw_mul_down, 4,
	    "Rack timely lower range for equal b/w (in percentage)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "rtt_max_mul", CTLFLAG_RW,
	    &rack_gp_rtt_maxmul, 3,
	    "Rack timely multipler of lowest rtt for rtt_max");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "rtt_min_div", CTLFLAG_RW,
	    &rack_gp_rtt_mindiv, 4,
	    "Rack timely divisor used for rtt + (rtt * mul/divisor) for check for lower rtt");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "rtt_min_mul", CTLFLAG_RW,
	    &rack_gp_rtt_minmul, 1,
	    "Rack timely multiplier used for rtt + (rtt * mul/divisor) for check for lower rtt");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "decrease", CTLFLAG_RW,
	    &rack_gp_decrease_per, 20,
	    "Rack timely decrease percentage of our GP multiplication factor");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "increase", CTLFLAG_RW,
	    &rack_gp_increase_per, 2,
	    "Rack timely increase perentage of our GP multiplication factor");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "lowerbound", CTLFLAG_RW,
	    &rack_per_lower_bound, 50,
	    "Rack timely lowest percentage we allow GP multiplier to fall to");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "upperboundss", CTLFLAG_RW,
	    &rack_per_upper_bound_ss, 0,
	    "Rack timely higest percentage we allow GP multiplier in SS to raise to (0 is no upperbound)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "upperboundca", CTLFLAG_RW,
	    &rack_per_upper_bound_ca, 0,
	    "Rack timely higest percentage we allow GP multiplier to CA raise to (0 is no upperbound)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "dynamicgp", CTLFLAG_RW,
	    &rack_do_dyn_mul, 0,
	    "Rack timely do we enable dynmaic timely goodput by default");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "no_rec_red", CTLFLAG_RW,
	    &rack_gp_no_rec_chg, 1,
	    "Rack timely do we prohibit the recovery multiplier from being lowered");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "red_clear_cnt", CTLFLAG_RW,
	    &rack_timely_dec_clear, 6,
	    "Rack timely what threshold do we count to before another boost during b/w decent");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "max_push_rise", CTLFLAG_RW,
	    &rack_timely_max_push_rise, 3,
	    "Rack timely how many times do we push up with b/w increase");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "max_push_drop", CTLFLAG_RW,
	    &rack_timely_max_push_drop, 3,
	    "Rack timely how many times do we push back on b/w decent");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "min_segs", CTLFLAG_RW,
	    &rack_timely_min_segs, 4,
	    "Rack timely when setting the cwnd what is the min num segments");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "noback_max", CTLFLAG_RW,
	    &rack_use_max_for_nobackoff, 0,
	    "Rack timely when deciding if to backoff on a loss, do we use under max rtt else min");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "interim_timely_only", CTLFLAG_RW,
	    &rack_timely_int_timely_only, 0,
	    "Rack timely when doing interim timely's do we only do timely (no b/w consideration)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "nonstop", CTLFLAG_RW,
	    &rack_timely_no_stopping, 0,
	    "Rack timely don't stop increase");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "dec_raise_thresh", CTLFLAG_RW,
	    &rack_down_raise_thresh, 100,
	    "If the CA or SS is below this threshold raise on the first 3 b/w lowers (0=always)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timely),
	    OID_AUTO, "bottom_drag_segs", CTLFLAG_RW,
	    &rack_req_segs, 1,
	    "Bottom dragging if not these many segments outstanding and room");

	/* TLP and Rack related parameters */
	rack_tlp = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "tlp",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "TLP and Rack related Controls");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "use_rrr", CTLFLAG_RW,
	    &use_rack_rr, 1,
	    "Do we use Rack Rapid Recovery");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "nonrxt_use_cr", CTLFLAG_RW,
	    &rack_non_rxt_use_cr, 0,
	    "Do we use ss/ca rate if in recovery we are transmitting a new data chunk");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "tlpmethod", CTLFLAG_RW,
	    &rack_tlp_threshold_use, TLP_USE_TWO_ONE,
	    "What method do we do for TLP time calc 0=no-de-ack-comp, 1=ID, 2=2.1, 3=2.2");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "limit", CTLFLAG_RW,
	    &rack_tlp_limit, 2,
	    "How many TLP's can be sent without sending new data");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "use_greater", CTLFLAG_RW,
	    &rack_tlp_use_greater, 1,
	    "Should we use the rack_rtt time if its greater than srtt");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "tlpminto", CTLFLAG_RW,
	    &rack_tlp_min, 10,
	    "TLP minimum timeout per the specification (10ms)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "send_oldest", CTLFLAG_RW,
	    &rack_always_send_oldest, 0,
	    "Should we always send the oldest TLP and RACK-TLP");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "rack_tlimit", CTLFLAG_RW,
	    &rack_limited_retran, 0,
	    "How many times can a rack timeout drive out sends");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "tlp_retry", CTLFLAG_RW,
	    &rack_tlp_max_resend, 2,
	    "How many times does TLP retry a single segment or multiple with no ACK");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "tlp_cwnd_flag", CTLFLAG_RW,
	    &rack_lower_cwnd_at_tlp, 0,
	    "When a TLP completes a retran should we enter recovery");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "reorder_thresh", CTLFLAG_RW,
	    &rack_reorder_thresh, 2,
	    "What factor for rack will be added when seeing reordering (shift right)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "rtt_tlp_thresh", CTLFLAG_RW,
	    &rack_tlp_thresh, 1,
	    "What divisor for TLP rtt/retran will be added (1=rtt, 2=1/2 rtt etc)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "reorder_fade", CTLFLAG_RW,
	    &rack_reorder_fade, 0,
	    "Does reorder detection fade, if so how many ms (0 means never)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_tlp),
	    OID_AUTO, "pktdelay", CTLFLAG_RW,
	    &rack_pkt_delay, 1,
	    "Extra RACK time (in ms) besides reordering thresh");

	/* Timer related controls */
	rack_timers = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "timers",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Timer related controls");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timers),
	    OID_AUTO, "persmin", CTLFLAG_RW,
	    &rack_persist_min, 250,
	    "What is the minimum time in milliseconds between persists");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timers),
	    OID_AUTO, "persmax", CTLFLAG_RW,
	    &rack_persist_max, 2000,
	    "What is the largest delay in milliseconds between persists");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timers),
	    OID_AUTO, "delayed_ack", CTLFLAG_RW,
	    &rack_delayed_ack_time, 200,
	    "Delayed ack time (200ms)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timers),
	    OID_AUTO, "minrto", CTLFLAG_RW,
	    &rack_rto_min, 0,
	    "Minimum RTO in ms -- set with caution below 1000 due to TLP");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timers),
	    OID_AUTO, "maxrto", CTLFLAG_RW,
	    &rack_rto_max, 0,
	    "Maxiumum RTO in ms -- should be at least as large as min_rto");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_timers),
	    OID_AUTO, "minto", CTLFLAG_RW,
	    &rack_min_to, 1,
	    "Minimum rack timeout in milliseconds");
	/* Measure controls */
	rack_measure = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "measure",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Measure related controls");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "wma_divisor", CTLFLAG_RW,
	    &rack_wma_divisor, 8,
	    "When doing b/w calculation what is the  divisor for the WMA");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "end_cwnd", CTLFLAG_RW,
	    &rack_cwnd_block_ends_measure, 0,
	    "Does a cwnd just-return end the measurement window (app limited)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "end_rwnd", CTLFLAG_RW,
	    &rack_rwnd_block_ends_measure, 0,
	    "Does an rwnd just-return end the measurement window (app limited -- not persists)");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "min_target", CTLFLAG_RW,
	    &rack_def_data_window, 20,
	    "What is the minimum target window (in mss) for a GP measurements");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "goal_bdp", CTLFLAG_RW,
	    &rack_goal_bdp, 2,
	    "What is the goal BDP to measure");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "min_srtts", CTLFLAG_RW,
	    &rack_min_srtts, 1,
	    "What is the goal BDP to measure");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_measure),
	    OID_AUTO, "min_measure_tim", CTLFLAG_RW,
	    &rack_min_measure_usec, 0,
	    "What is the Minimum time time for a measurement if 0, this is off");
	/* Misc rack controls */
	rack_misc = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO,
	    "misc",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Misc related controls");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "shared_cwnd", CTLFLAG_RW,
	    &rack_enable_shared_cwnd, 0,
	    "Should RACK try to use the shared cwnd on connections where allowed");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "limits_on_scwnd", CTLFLAG_RW,
	    &rack_limits_scwnd, 1,
	    "Should RACK place low end time limits on the shared cwnd feature");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "non_paced_lro_queue", CTLFLAG_RW,
	    &rack_enable_mqueue_for_nonpaced, 0,
	    "Should RACK use mbuf queuing for non-paced connections");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "iMac_dack", CTLFLAG_RW,
	    &rack_use_imac_dack, 0,
	    "Should RACK try to emulate iMac delayed ack");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "no_prr", CTLFLAG_RW,
	    &rack_disable_prr, 0,
	    "Should RACK not use prr and only pace (must have pacing on)");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "bb_verbose", CTLFLAG_RW,
	    &rack_verbose_logging, 0,
	    "Should RACK black box logging be verbose");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "data_after_close", CTLFLAG_RW,
	    &rack_ignore_data_after_close, 1,
	    "Do we hold off sending a RST until all pending data is ack'd");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "no_sack_needed", CTLFLAG_RW,
	    &rack_sack_not_required, 0,
	    "Do we allow rack to run on connections not supporting SACK");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "recovery_loss_prop", CTLFLAG_RW,
	    &rack_use_proportional_reduce, 0,
	    "Should we proportionaly reduce cwnd based on the number of losses ");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "recovery_prop", CTLFLAG_RW,
	    &rack_proportional_rate, 10,
	    "What percent reduction per loss");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "prr_sendalot", CTLFLAG_RW,
	    &rack_send_a_lot_in_prr, 1,
	    "Send a lot in prr");
	SYSCTL_ADD_S32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_misc),
	    OID_AUTO, "earlyrecovery", CTLFLAG_RW,
	    &rack_early_recovery, 1,
	    "Do we do early recovery with rack");
	/* Sack Attacker detection stuff */
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "detect_highsackratio", CTLFLAG_RW,
	    &rack_highest_sack_thresh_seen, 0,
	    "Highest sack to ack ratio seen");
	SYSCTL_ADD_U32(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "detect_highmoveratio", CTLFLAG_RW,
	    &rack_highest_move_thresh_seen, 0,
	    "Highest move to non-move ratio seen");
	rack_ack_total = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "acktotal", CTLFLAG_RD,
	    &rack_ack_total,
	    "Total number of Ack's");
	rack_express_sack = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "exp_sacktotal", CTLFLAG_RD,
	    &rack_express_sack,
	    "Total expresss number of Sack's");
	rack_sack_total = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "sacktotal", CTLFLAG_RD,
	    &rack_sack_total,
	    "Total number of SACKs");
	rack_move_none = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "move_none", CTLFLAG_RD,
	    &rack_move_none,
	    "Total number of SACK index reuse of postions under threshold");
	rack_move_some = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "move_some", CTLFLAG_RD,
	    &rack_move_some,
	    "Total number of SACK index reuse of postions over threshold");
	rack_sack_attacks_detected = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "attacks", CTLFLAG_RD,
	    &rack_sack_attacks_detected,
	    "Total number of SACK attackers that had sack disabled");
	rack_sack_attacks_reversed = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "reversed", CTLFLAG_RD,
	    &rack_sack_attacks_reversed,
	    "Total number of SACK attackers that were later determined false positive");
	rack_sack_used_next_merge = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "nextmerge", CTLFLAG_RD,
	    &rack_sack_used_next_merge,
	    "Total number of times we used the next merge");
	rack_sack_used_prev_merge = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "prevmerge", CTLFLAG_RD,
	    &rack_sack_used_prev_merge,
	    "Total number of times we used the prev merge");
	/* Counters */
	rack_badfr = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "badfr", CTLFLAG_RD,
	    &rack_badfr, "Total number of bad FRs");
	rack_badfr_bytes = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "badfr_bytes", CTLFLAG_RD,
	    &rack_badfr_bytes, "Total number of bad FRs");
	rack_rtm_prr_retran = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "prrsndret", CTLFLAG_RD,
	    &rack_rtm_prr_retran,
	    "Total number of prr based retransmits");
	rack_rtm_prr_newdata = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "prrsndnew", CTLFLAG_RD,
	    &rack_rtm_prr_newdata,
	    "Total number of prr based new transmits");
	rack_timestamp_mismatch = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tsnf", CTLFLAG_RD,
	    &rack_timestamp_mismatch,
	    "Total number of timestamps that we could not find the reported ts");
	rack_find_high = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "findhigh", CTLFLAG_RD,
	    &rack_find_high,
	    "Total number of FIN causing find-high");
	rack_reorder_seen = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "reordering", CTLFLAG_RD,
	    &rack_reorder_seen,
	    "Total number of times we added delay due to reordering");
	rack_tlp_tot = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_to_total", CTLFLAG_RD,
	    &rack_tlp_tot,
	    "Total number of tail loss probe expirations");
	rack_tlp_newdata = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_new", CTLFLAG_RD,
	    &rack_tlp_newdata,
	    "Total number of tail loss probe sending new data");
	rack_tlp_retran = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_retran", CTLFLAG_RD,
	    &rack_tlp_retran,
	    "Total number of tail loss probe sending retransmitted data");
	rack_tlp_retran_bytes = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_retran_bytes", CTLFLAG_RD,
	    &rack_tlp_retran_bytes,
	    "Total bytes of tail loss probe sending retransmitted data");
	rack_tlp_retran_fail = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_retran_fail", CTLFLAG_RD,
	    &rack_tlp_retran_fail,
	    "Total number of tail loss probe sending retransmitted data that failed (wait for t3)");
	rack_to_tot = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "rack_to_tot", CTLFLAG_RD,
	    &rack_to_tot,
	    "Total number of times the rack to expired");
	rack_to_arm_rack = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "arm_rack", CTLFLAG_RD,
	    &rack_to_arm_rack,
	    "Total number of times the rack timer armed");
	rack_to_arm_tlp = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "arm_tlp", CTLFLAG_RD,
	    &rack_to_arm_tlp,
	    "Total number of times the tlp timer armed");
	rack_calc_zero = counter_u64_alloc(M_WAITOK);
	rack_calc_nonzero = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "calc_zero", CTLFLAG_RD,
	    &rack_calc_zero,
	    "Total number of times pacing time worked out to zero");
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "calc_nonzero", CTLFLAG_RD,
	    &rack_calc_nonzero,
	    "Total number of times pacing time worked out to non-zero");
	rack_paced_segments = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "paced", CTLFLAG_RD,
	    &rack_paced_segments,
	    "Total number of times a segment send caused hptsi");
	rack_unpaced_segments = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "unpaced", CTLFLAG_RD,
	    &rack_unpaced_segments,
	    "Total number of times a segment did not cause hptsi");
	rack_saw_enobuf = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "saw_enobufs", CTLFLAG_RD,
	    &rack_saw_enobuf,
	    "Total number of times a segment did not cause hptsi");
	rack_saw_enetunreach = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "saw_enetunreach", CTLFLAG_RD,
	    &rack_saw_enetunreach,
	    "Total number of times a segment did not cause hptsi");
	rack_to_alloc = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "allocs", CTLFLAG_RD,
	    &rack_to_alloc,
	    "Total allocations of tracking structures");
	rack_to_alloc_hard = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "allochard", CTLFLAG_RD,
	    &rack_to_alloc_hard,
	    "Total allocations done with sleeping the hard way");
	rack_to_alloc_emerg = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "allocemerg", CTLFLAG_RD,
	    &rack_to_alloc_emerg,
	    "Total allocations done from emergency cache");
	rack_to_alloc_limited = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "alloc_limited", CTLFLAG_RD,
	    &rack_to_alloc_limited,
	    "Total allocations dropped due to limit");
	rack_alloc_limited_conns = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "alloc_limited_conns", CTLFLAG_RD,
	    &rack_alloc_limited_conns,
	    "Connections with allocations dropped due to limit");
	rack_split_limited = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "split_limited", CTLFLAG_RD,
	    &rack_split_limited,
	    "Split allocations dropped due to limit");
	rack_sack_proc_all = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "sack_long", CTLFLAG_RD,
	    &rack_sack_proc_all,
	    "Total times we had to walk whole list for sack processing");
	rack_sack_proc_restart = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "sack_restart", CTLFLAG_RD,
	    &rack_sack_proc_restart,
	    "Total times we had to walk whole list due to a restart");
	rack_sack_proc_short = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "sack_short", CTLFLAG_RD,
	    &rack_sack_proc_short,
	    "Total times we took shortcut for sack processing");
	rack_enter_tlp_calc = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_calc_entered", CTLFLAG_RD,
	    &rack_enter_tlp_calc,
	    "Total times we called calc-tlp");
	rack_used_tlpmethod = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "hit_tlp_method", CTLFLAG_RD,
	    &rack_used_tlpmethod,
	    "Total number of runt sacks");
	rack_used_tlpmethod2 = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "hit_tlp_method2", CTLFLAG_RD,
	    &rack_used_tlpmethod2,
	    "Total number of times we hit TLP method 2");
	rack_sack_skipped_acked = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "skipacked", CTLFLAG_RD,
	    &rack_sack_skipped_acked,
	    "Total number of times we skipped previously sacked");
	rack_sack_splits = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_attack),
	    OID_AUTO, "ofsplit", CTLFLAG_RD,
	    &rack_sack_splits,
	    "Total number of times we did the old fashion tree split");
	rack_progress_drops = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "prog_drops", CTLFLAG_RD,
	    &rack_progress_drops,
	    "Total number of progress drops");
	rack_input_idle_reduces = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "idle_reduce_oninput", CTLFLAG_RD,
	    &rack_input_idle_reduces,
	    "Total number of idle reductions on input");
	rack_collapsed_win = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "collapsed_win", CTLFLAG_RD,
	    &rack_collapsed_win,
	    "Total number of collapsed windows");
	rack_tlp_does_nada = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tlp_nada", CTLFLAG_RD,
	    &rack_tlp_does_nada,
	    "Total number of nada tlp calls");
	rack_try_scwnd = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tried_scwnd", CTLFLAG_RD,
	    &rack_try_scwnd,
	    "Total number of scwnd attempts");

	rack_tls_rwnd = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_rwnd", CTLFLAG_RD,
	    &rack_tls_rwnd,
	    "Total hdwr tls rwnd limited");
	rack_tls_cwnd = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_cwnd", CTLFLAG_RD,
	    &rack_tls_cwnd,
	    "Total hdwr tls cwnd limited");
	rack_tls_app = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_app", CTLFLAG_RD,
	    &rack_tls_app,
	    "Total hdwr tls app limited");
	rack_tls_other = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_other", CTLFLAG_RD,
	    &rack_tls_other,
	    "Total hdwr tls other limited");
	rack_tls_filled = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_filled", CTLFLAG_RD,
	    &rack_tls_filled,
	    "Total hdwr tls filled");
	rack_tls_rxt = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_rxt", CTLFLAG_RD,
	    &rack_tls_rxt,
	    "Total hdwr rxt");
	rack_tls_tlp = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "tls_tlp", CTLFLAG_RD,
	    &rack_tls_tlp,
	    "Total hdwr tls tlp");
	rack_per_timer_hole = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_counters),
	    OID_AUTO, "timer_hole", CTLFLAG_RD,
	    &rack_per_timer_hole,
	    "Total persists start in timer hole");
	COUNTER_ARRAY_ALLOC(rack_out_size, TCP_MSS_ACCT_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO, "outsize", CTLFLAG_RD,
	    rack_out_size, TCP_MSS_ACCT_SIZE, "MSS send sizes");
	COUNTER_ARRAY_ALLOC(rack_opts_arry, RACK_OPTS_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO, "opts", CTLFLAG_RD,
	    rack_opts_arry, RACK_OPTS_SIZE, "RACK Option Stats");
	SYSCTL_ADD_PROC(&rack_sysctl_ctx,
	    SYSCTL_CHILDREN(rack_sysctl_root),
	    OID_AUTO, "clear", CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    &rack_clear_counter, 0, sysctl_rack_clear, "IU", "Clear counters");
}

static __inline int
rb_map_cmp(struct rack_sendmap *b, struct rack_sendmap *a)
{
	if (SEQ_GEQ(b->r_start, a->r_start) &&
	    SEQ_LT(b->r_start, a->r_end)) {
		/*
		 * The entry b is within the
		 * block a. i.e.:
		 * a --   |-------------|
		 * b --   |----|
		 * <or>
		 * b --       |------|
		 * <or>
		 * b --       |-----------|
		 */
		return (0);
	} else if (SEQ_GEQ(b->r_start, a->r_end)) {
		/*
		 * b falls as either the next
		 * sequence block after a so a
		 * is said to be smaller than b.
		 * i.e:
		 * a --   |------|
		 * b --          |--------|
		 * or
		 * b --              |-----|
		 */
		return (1);
	}
	/*
	 * Whats left is where a is
	 * larger than b. i.e:
	 * a --         |-------|
	 * b --  |---|
	 * or even possibly
	 * b --   |--------------|
	 */
	return (-1);
}

RB_PROTOTYPE(rack_rb_tree_head, rack_sendmap, r_next, rb_map_cmp);
RB_GENERATE(rack_rb_tree_head, rack_sendmap, r_next, rb_map_cmp);

static uint32_t
rc_init_window(struct tcp_rack *rack)
{
	uint32_t win;

	if (rack->rc_init_win == 0) {
		/*
		 * Nothing set by the user, use the system stack
		 * default.
		 */
		return(tcp_compute_initwnd(tcp_maxseg(rack->rc_tp)));
	}
	win = ctf_fixed_maxseg(rack->rc_tp) * rack->rc_init_win;
	return(win);
}

static uint64_t
rack_get_fixed_pacing_bw(struct tcp_rack *rack)
{
	if (IN_RECOVERY(rack->rc_tp->t_flags))
		return (rack->r_ctl.rc_fixed_pacing_rate_rec);
	else if (rack->r_ctl.cwnd_to_use < rack->rc_tp->snd_ssthresh)
		return (rack->r_ctl.rc_fixed_pacing_rate_ss);
	else
		return (rack->r_ctl.rc_fixed_pacing_rate_ca);
}

static uint64_t
rack_get_bw(struct tcp_rack *rack)
{
	if (rack->use_fixed_rate) {
		/* Return the fixed pacing rate */
		return (rack_get_fixed_pacing_bw(rack));
	}
	if (rack->r_ctl.gp_bw == 0) {
		/*
		 * We have yet no b/w measurement,
		 * if we have a user set initial bw
		 * return it. If we don't have that and
		 * we have an srtt, use the tcp IW (10) to
		 * calculate a fictional b/w over the SRTT
		 * which is more or less a guess. Note
		 * we don't use our IW from rack on purpose
		 * so if we have like IW=30, we are not
		 * calculating a "huge" b/w.
		 */
		uint64_t bw, srtt;
		if (rack->r_ctl.init_rate)
			return (rack->r_ctl.init_rate);

		/* Has the user set a max peak rate? */
#ifdef NETFLIX_PEAKRATE
		if (rack->rc_tp->t_maxpeakrate)
			return (rack->rc_tp->t_maxpeakrate);
#endif
		/* Ok lets come up with the IW guess, if we have a srtt */
		if (rack->rc_tp->t_srtt == 0) {
			/*
			 * Go with old pacing method
			 * i.e. burst mitigation only.
			 */
			return (0);
		}
		/* Ok lets get the initial TCP win (not racks) */
		bw = tcp_compute_initwnd(tcp_maxseg(rack->rc_tp));
		srtt = ((uint64_t)TICKS_2_USEC(rack->rc_tp->t_srtt) >> TCP_RTT_SHIFT);
		bw *= (uint64_t)USECS_IN_SECOND;
		bw /= srtt;
		return (bw);
	} else {
		uint64_t bw;

		if(rack->r_ctl.num_avg >= RACK_REQ_AVG) {
			/* Averaging is done, we can return the value */
			bw = rack->r_ctl.gp_bw;
		} else {
			/* Still doing initial average must calculate */
			bw = rack->r_ctl.gp_bw / rack->r_ctl.num_avg;
		}
#ifdef NETFLIX_PEAKRATE
		if ((rack->rc_tp->t_maxpeakrate) &&
		    (bw > rack->rc_tp->t_maxpeakrate)) {
			/* The user has set a peak rate to pace at
			 * don't allow us to pace faster than that.
			 */
			return (rack->rc_tp->t_maxpeakrate);
		}
#endif
		return (bw);
	}
}

static uint16_t
rack_get_output_gain(struct tcp_rack *rack, struct rack_sendmap *rsm)
{
	if (rack->use_fixed_rate) {
		return (100);
	} else if (rack->in_probe_rtt && (rsm == NULL))
		return(rack->r_ctl.rack_per_of_gp_probertt);
	else if ((IN_RECOVERY(rack->rc_tp->t_flags) &&
		  rack->r_ctl.rack_per_of_gp_rec)) {
		if (rsm) {
			/* a retransmission always use the recovery rate */
			return(rack->r_ctl.rack_per_of_gp_rec);
		} else if (rack->rack_rec_nonrxt_use_cr) {
			/* Directed to use the configured rate */
			goto configured_rate;
		} else if (rack->rack_no_prr &&
			   (rack->r_ctl.rack_per_of_gp_rec > 100)) {
			/* No PRR, lets just use the b/w estimate only */
			return(100);
		} else {
			/*
			 * Here we may have a non-retransmit but we
			 * have no overrides, so just use the recovery
			 * rate (prr is in effect).
			 */
			return(rack->r_ctl.rack_per_of_gp_rec);
		}
	}
configured_rate:
	/* For the configured rate we look at our cwnd vs the ssthresh */
	if (rack->r_ctl.cwnd_to_use < rack->rc_tp->snd_ssthresh)
		return (rack->r_ctl.rack_per_of_gp_ss);
	else
		return(rack->r_ctl.rack_per_of_gp_ca);
}

static uint64_t
rack_get_output_bw(struct tcp_rack *rack, uint64_t bw, struct rack_sendmap *rsm)
{
	/*
	 * We allow rack_per_of_gp_xx to dictate our bw rate we want.
	 */
	uint64_t bw_est;
	uint64_t gain;

	gain = (uint64_t)rack_get_output_gain(rack, rsm);
	bw_est = bw * gain;
	bw_est /= (uint64_t)100;
	/* Never fall below the minimum (def 64kbps) */
	if (bw_est < RACK_MIN_BW)
		bw_est = RACK_MIN_BW;
	return (bw_est);
}

static void
rack_log_retran_reason(struct tcp_rack *rack, struct rack_sendmap *rsm, uint32_t tsused, uint32_t thresh, int mod)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		if ((mod != 1) && (rack_verbose_logging == 0)) {
			/*
			 * We get 3 values currently for mod
			 * 1 - We are retransmitting and this tells the reason.
			 * 2 - We are clearing a dup-ack count.
			 * 3 - We are incrementing a dup-ack count.
			 *
			 * The clear/increment are only logged
			 * if you have BBverbose on.
			 */
			return;
		}
		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = tsused;
		log.u_bbr.flex2 = thresh;
		log.u_bbr.flex3 = rsm->r_flags;
		log.u_bbr.flex4 = rsm->r_dupack;
		log.u_bbr.flex5 = rsm->r_start;
		log.u_bbr.flex6 = rsm->r_end;
		log.u_bbr.flex8 = mod;
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_SETTINGS_CHG, 0,
		    0, &log, false, &tv);
	}
}



static void
rack_log_to_start(struct tcp_rack *rack, uint32_t cts, uint32_t to, int32_t slot, uint8_t which)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = TICKS_2_MSEC(rack->rc_tp->t_srtt >> TCP_RTT_SHIFT);
		log.u_bbr.flex2 = to * 1000;
		log.u_bbr.flex3 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex4 = slot;
		log.u_bbr.flex5 = rack->rc_inp->inp_hptsslot;
		log.u_bbr.flex6 = rack->rc_tp->t_rxtcur;
		log.u_bbr.flex7 = rack->rc_in_persist;
		log.u_bbr.flex8 = which;
		if (rack->rack_no_prr)
			log.u_bbr.pkts_out = 0;
		else
			log.u_bbr.pkts_out = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_TIMERSTAR, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_to_event(struct tcp_rack *rack, int32_t to_num, struct rack_sendmap *rsm)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex8 = to_num;
		log.u_bbr.flex1 = rack->r_ctl.rc_rack_min_rtt;
		log.u_bbr.flex2 = rack->rc_rack_rtt;
		if (rsm == NULL)
			log.u_bbr.flex3 = 0;
		else
			log.u_bbr.flex3 = rsm->r_end - rsm->r_start;
		if (rack->rack_no_prr)
			log.u_bbr.flex5 = 0;
		else
			log.u_bbr.flex5 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_RTO, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_rtt_upd(struct tcpcb *tp, struct tcp_rack *rack, uint32_t t, uint32_t len,
		 struct rack_sendmap *rsm, int conf)
{
	if (tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;
		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = t;
		log.u_bbr.flex2 = len;
		log.u_bbr.flex3 = rack->r_ctl.rc_rack_min_rtt * HPTS_USEC_IN_MSEC;
		log.u_bbr.flex4 = rack->r_ctl.rack_rs.rs_rtt_lowest * HPTS_USEC_IN_MSEC;
		log.u_bbr.flex5 = rack->r_ctl.rack_rs.rs_rtt_highest * HPTS_USEC_IN_MSEC;
		log.u_bbr.flex6 = rack->r_ctl.rack_rs.rs_rtt_cnt;
		log.u_bbr.flex7 = conf;
		log.u_bbr.rttProp = (uint64_t)rack->r_ctl.rack_rs.rs_rtt_tot * (uint64_t)HPTS_USEC_IN_MSEC;
		log.u_bbr.flex8 = rack->r_ctl.rc_rate_sample_method;
		if (rack->rack_no_prr)
			log.u_bbr.pkts_out = 0;
		else
			log.u_bbr.pkts_out = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.delivered = rack->r_ctl.rack_rs.rs_us_rtt;
		log.u_bbr.pkts_out = rack->r_ctl.rack_rs.rs_flags;
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		if (rsm) {
			log.u_bbr.pkt_epoch = rsm->r_start;
			log.u_bbr.lost = rsm->r_end;
			log.u_bbr.cwnd_gain = rsm->r_rtr_cnt;
		} else {

			/* Its a SYN */
			log.u_bbr.pkt_epoch = rack->rc_tp->iss;
			log.u_bbr.lost = 0;
			log.u_bbr.cwnd_gain = 0;
		}
		/* Write out general bits of interest rrs here */
		log.u_bbr.use_lt_bw = rack->rc_highly_buffered;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->forced_ack;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->rc_gp_dyn_mul;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->in_probe_rtt;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->measure_saw_probe_rtt;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->app_limited_needs_set;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->rc_gp_filled;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->rc_dragged_bottom;
		log.u_bbr.applimited = rack->r_ctl.rc_target_probertt_flight;
		log.u_bbr.epoch = rack->r_ctl.rc_time_probertt_starts;
		log.u_bbr.lt_epoch = rack->r_ctl.rc_time_probertt_entered;
		log.u_bbr.cur_del_rate = rack->r_ctl.rc_lower_rtt_us_cts;
		log.u_bbr.delRate = rack->r_ctl.rc_gp_srtt;
		TCP_LOG_EVENTP(tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_BBRRTT, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_rtt_sample(struct tcp_rack *rack, uint32_t rtt)
{
	/*
	 * Log the rtt sample we are
	 * applying to the srtt algorithm in
	 * useconds.
	 */
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		/* Convert our ms to a microsecond */
		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = rtt * 1000;
		log.u_bbr.flex2 = rack->r_ctl.ack_count;
		log.u_bbr.flex3 = rack->r_ctl.sack_count;
		log.u_bbr.flex4 = rack->r_ctl.sack_noextra_move;
		log.u_bbr.flex5 = rack->r_ctl.sack_moved_extra;
		log.u_bbr.flex8 = rack->sack_attack_disable;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    TCP_LOG_RTT, 0,
		    0, &log, false, &tv);
	}
}


static inline void
rack_log_progress_event(struct tcp_rack *rack, struct tcpcb *tp, uint32_t tick,  int event, int line)
{
	if (rack_verbose_logging && (tp->t_logstate != TCP_LOG_STATE_OFF)) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = line;
		log.u_bbr.flex2 = tick;
		log.u_bbr.flex3 = tp->t_maxunacktime;
		log.u_bbr.flex4 = tp->t_acktime;
		log.u_bbr.flex8 = event;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_PROGRESS, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_type_bbrsnd(struct tcp_rack *rack, uint32_t len, uint32_t slot, uint32_t cts, struct timeval *tv)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = slot;
		if (rack->rack_no_prr)
			log.u_bbr.flex2 = 0;
		else
			log.u_bbr.flex2 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.flex7 = (0x0000ffff & rack->r_ctl.rc_hpts_flags);
		log.u_bbr.flex8 = rack->rc_in_persist;
		log.u_bbr.timeStamp = cts;
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_BBRSND, 0,
		    0, &log, false, tv);
	}
}

static void
rack_log_doseg_done(struct tcp_rack *rack, uint32_t cts, int32_t nxt_pkt, int32_t did_out, int way_out)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = did_out;
		log.u_bbr.flex2 = nxt_pkt;
		log.u_bbr.flex3 = way_out;
		log.u_bbr.flex4 = rack->r_ctl.rc_hpts_flags;
		if (rack->rack_no_prr)
			log.u_bbr.flex5 = 0;
		else
			log.u_bbr.flex5 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.applimited = rack->r_ctl.rc_pace_min_segs;
		log.u_bbr.flex7 = rack->r_wanted_output;
		log.u_bbr.flex8 = rack->rc_in_persist;
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_DOSEG_DONE, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_type_hrdwtso(struct tcpcb *tp, struct tcp_rack *rack, int len, int mod, int32_t orig_len, int frm)
{
	if (tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;
		uint32_t cts;

		memset(&log, 0, sizeof(log));
		cts = tcp_get_usecs(&tv);
		log.u_bbr.flex1 = rack->r_ctl.rc_pace_min_segs;
		log.u_bbr.flex3 = rack->r_ctl.rc_pace_max_segs;
		log.u_bbr.flex4 = len;
		log.u_bbr.flex5 = orig_len;
		log.u_bbr.flex6 = rack->r_ctl.rc_sacked;
		log.u_bbr.flex7 = mod;
		log.u_bbr.flex8 = frm;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(tp, NULL,
		    &tp->t_inpcb->inp_socket->so_rcv,
		    &tp->t_inpcb->inp_socket->so_snd,
		    TCP_HDWR_TLS, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_type_just_return(struct tcp_rack *rack, uint32_t cts, uint32_t tlen, uint32_t slot,
			  uint8_t hpts_calling, int reason, uint32_t cwnd_to_use)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = slot;
		log.u_bbr.flex2 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex4 = reason;
		if (rack->rack_no_prr)
			log.u_bbr.flex5 = 0;
		else
			log.u_bbr.flex5 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.flex7 = hpts_calling;
		log.u_bbr.flex8 = rack->rc_in_persist;
		log.u_bbr.lt_epoch = cwnd_to_use;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_JUSTRET, 0,
		    tlen, &log, false, &tv);
	}
}

static void
rack_log_to_cancel(struct tcp_rack *rack, int32_t hpts_removed, int line, uint32_t us_cts,
		   struct timeval *tv, uint32_t flags_on_entry)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = line;
		log.u_bbr.flex2 = rack->r_ctl.rc_last_output_to;
		log.u_bbr.flex3 = flags_on_entry;
		log.u_bbr.flex4 = us_cts;
		if (rack->rack_no_prr)
			log.u_bbr.flex5 = 0;
		else
			log.u_bbr.flex5 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.flex6 = rack->rc_tp->t_rxtcur;
		log.u_bbr.flex7 = hpts_removed;
		log.u_bbr.flex8 = 1;
		log.u_bbr.applimited = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.timeStamp = us_cts;
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_TIMERCANC, 0,
		    0, &log, false, tv);
	}
}

static void
rack_log_alt_to_to_cancel(struct tcp_rack *rack,
			  uint32_t flex1, uint32_t flex2,
			  uint32_t flex3, uint32_t flex4,
			  uint32_t flex5, uint32_t flex6,
			  uint16_t flex7, uint8_t mod)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		if (mod == 1) {
			/* No you can't use 1, its for the real to cancel */
			return;
		}
		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.flex1 = flex1;
		log.u_bbr.flex2 = flex2;
		log.u_bbr.flex3 = flex3;
		log.u_bbr.flex4 = flex4;
		log.u_bbr.flex5 = flex5;
		log.u_bbr.flex6 = flex6;
		log.u_bbr.flex7 = flex7;
		log.u_bbr.flex8 =  mod;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_TIMERCANC, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_to_processing(struct tcp_rack *rack, uint32_t cts, int32_t ret, int32_t timers)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = timers;
		log.u_bbr.flex2 = ret;
		log.u_bbr.flex3 = rack->r_ctl.rc_timer_exp;
		log.u_bbr.flex4 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex5 = cts;
		if (rack->rack_no_prr)
			log.u_bbr.flex6 = 0;
		else
			log.u_bbr.flex6 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_TO_PROCESS, 0,
		    0, &log, false, &tv);
	}
}

static void
rack_log_to_prr(struct tcp_rack *rack, int frm, int orig_cwnd)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = rack->r_ctl.rc_prr_out;
		log.u_bbr.flex2 = rack->r_ctl.rc_prr_recovery_fs;
		if (rack->rack_no_prr)
			log.u_bbr.flex3 = 0;
		else
			log.u_bbr.flex3 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.flex4 = rack->r_ctl.rc_prr_delivered;
		log.u_bbr.flex5 = rack->r_ctl.rc_sacked;
		log.u_bbr.flex6 = rack->r_ctl.rc_holes_rxt;
		log.u_bbr.flex8 = frm;
		log.u_bbr.pkts_out = orig_cwnd;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_BBRUPD, 0,
		    0, &log, false, &tv);
	}
}

#ifdef NETFLIX_EXP_DETECTION
static void
rack_log_sad(struct tcp_rack *rack, int event)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = rack->r_ctl.sack_count;
		log.u_bbr.flex2 = rack->r_ctl.ack_count;
		log.u_bbr.flex3 = rack->r_ctl.sack_moved_extra;
		log.u_bbr.flex4 = rack->r_ctl.sack_noextra_move;
		log.u_bbr.flex5 = rack->r_ctl.rc_num_maps_alloced;
		log.u_bbr.flex6 = tcp_sack_to_ack_thresh;
		log.u_bbr.pkts_out = tcp_sack_to_move_thresh;
		log.u_bbr.lt_epoch = (tcp_force_detection << 8);
		log.u_bbr.lt_epoch |= rack->do_detection;
		log.u_bbr.applimited = tcp_map_minimum;
		log.u_bbr.flex7 = rack->sack_attack_disable;
		log.u_bbr.flex8 = event;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		log.u_bbr.delivered = tcp_sad_decay_val;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    TCP_SAD_DETECTION, 0,
		    0, &log, false, &tv);
	}
}
#endif

static void
rack_counter_destroy(void)
{
	counter_u64_free(rack_ack_total);
	counter_u64_free(rack_express_sack);
	counter_u64_free(rack_sack_total);
	counter_u64_free(rack_move_none);
	counter_u64_free(rack_move_some);
	counter_u64_free(rack_sack_attacks_detected);
	counter_u64_free(rack_sack_attacks_reversed);
	counter_u64_free(rack_sack_used_next_merge);
	counter_u64_free(rack_sack_used_prev_merge);
	counter_u64_free(rack_badfr);
	counter_u64_free(rack_badfr_bytes);
	counter_u64_free(rack_rtm_prr_retran);
	counter_u64_free(rack_rtm_prr_newdata);
	counter_u64_free(rack_timestamp_mismatch);
	counter_u64_free(rack_find_high);
	counter_u64_free(rack_reorder_seen);
	counter_u64_free(rack_tlp_tot);
	counter_u64_free(rack_tlp_newdata);
	counter_u64_free(rack_tlp_retran);
	counter_u64_free(rack_tlp_retran_bytes);
	counter_u64_free(rack_tlp_retran_fail);
	counter_u64_free(rack_to_tot);
	counter_u64_free(rack_to_arm_rack);
	counter_u64_free(rack_to_arm_tlp);
	counter_u64_free(rack_calc_zero);
	counter_u64_free(rack_calc_nonzero);
	counter_u64_free(rack_paced_segments);
	counter_u64_free(rack_unpaced_segments);
	counter_u64_free(rack_saw_enobuf);
	counter_u64_free(rack_saw_enetunreach);
	counter_u64_free(rack_to_alloc);
	counter_u64_free(rack_to_alloc_hard);
	counter_u64_free(rack_to_alloc_emerg);
	counter_u64_free(rack_to_alloc_limited);
	counter_u64_free(rack_alloc_limited_conns);
	counter_u64_free(rack_split_limited);
	counter_u64_free(rack_sack_proc_all);
	counter_u64_free(rack_sack_proc_restart);
	counter_u64_free(rack_sack_proc_short);
	counter_u64_free(rack_enter_tlp_calc);
	counter_u64_free(rack_used_tlpmethod);
	counter_u64_free(rack_used_tlpmethod2);
	counter_u64_free(rack_sack_skipped_acked);
	counter_u64_free(rack_sack_splits);
	counter_u64_free(rack_progress_drops);
	counter_u64_free(rack_input_idle_reduces);
	counter_u64_free(rack_collapsed_win);
	counter_u64_free(rack_tlp_does_nada);
	counter_u64_free(rack_try_scwnd);
	counter_u64_free(rack_tls_rwnd);
	counter_u64_free(rack_tls_cwnd);
	counter_u64_free(rack_tls_app);
	counter_u64_free(rack_tls_other);
	counter_u64_free(rack_tls_filled);
	counter_u64_free(rack_tls_rxt);
	counter_u64_free(rack_tls_tlp);
	counter_u64_free(rack_per_timer_hole);
	COUNTER_ARRAY_FREE(rack_out_size, TCP_MSS_ACCT_SIZE);
	COUNTER_ARRAY_FREE(rack_opts_arry, RACK_OPTS_SIZE);
}

static struct rack_sendmap *
rack_alloc(struct tcp_rack *rack)
{
	struct rack_sendmap *rsm;

	rsm = uma_zalloc(rack_zone, M_NOWAIT);
	if (rsm) {
		rack->r_ctl.rc_num_maps_alloced++;
		counter_u64_add(rack_to_alloc, 1);
		return (rsm);
	}
	if (rack->rc_free_cnt) {
		counter_u64_add(rack_to_alloc_emerg, 1);
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_free);
		TAILQ_REMOVE(&rack->r_ctl.rc_free, rsm, r_tnext);
		rack->rc_free_cnt--;
		return (rsm);
	}
	return (NULL);
}

static struct rack_sendmap *
rack_alloc_full_limit(struct tcp_rack *rack)
{
	if ((V_tcp_map_entries_limit > 0) &&
	    (rack->do_detection == 0) &&
	    (rack->r_ctl.rc_num_maps_alloced >= V_tcp_map_entries_limit)) {
		counter_u64_add(rack_to_alloc_limited, 1);
		if (!rack->alloc_limit_reported) {
			rack->alloc_limit_reported = 1;
			counter_u64_add(rack_alloc_limited_conns, 1);
		}
		return (NULL);
	}
	return (rack_alloc(rack));
}

/* wrapper to allocate a sendmap entry, subject to a specific limit */
static struct rack_sendmap *
rack_alloc_limit(struct tcp_rack *rack, uint8_t limit_type)
{
	struct rack_sendmap *rsm;

	if (limit_type) {
		/* currently there is only one limit type */
		if (V_tcp_map_split_limit > 0 &&
		    (rack->do_detection == 0) &&
		    rack->r_ctl.rc_num_split_allocs >= V_tcp_map_split_limit) {
			counter_u64_add(rack_split_limited, 1);
			if (!rack->alloc_limit_reported) {
				rack->alloc_limit_reported = 1;
				counter_u64_add(rack_alloc_limited_conns, 1);
			}
			return (NULL);
		}
	}

	/* allocate and mark in the limit type, if set */
	rsm = rack_alloc(rack);
	if (rsm != NULL && limit_type) {
		rsm->r_limit_type = limit_type;
		rack->r_ctl.rc_num_split_allocs++;
	}
	return (rsm);
}

static void
rack_free(struct tcp_rack *rack, struct rack_sendmap *rsm)
{
	if (rsm->r_flags & RACK_APP_LIMITED) {
		if (rack->r_ctl.rc_app_limited_cnt > 0) {
			rack->r_ctl.rc_app_limited_cnt--;
		}
	}
	if (rsm->r_limit_type) {
		/* currently there is only one limit type */
		rack->r_ctl.rc_num_split_allocs--;
	}
	if (rsm == rack->r_ctl.rc_first_appl) {
		if (rack->r_ctl.rc_app_limited_cnt == 0)
			rack->r_ctl.rc_first_appl = NULL;
		else {
			/* Follow the next one out */
			struct rack_sendmap fe;

			fe.r_start = rsm->r_nseq_appl;
			rack->r_ctl.rc_first_appl = RB_FIND(rack_rb_tree_head, &rack->r_ctl.rc_mtree, &fe);
		}
	}
	if (rsm == rack->r_ctl.rc_resend)
		rack->r_ctl.rc_resend = NULL;
	if (rsm == rack->r_ctl.rc_rsm_at_retran)
		rack->r_ctl.rc_rsm_at_retran = NULL;
	if (rsm == rack->r_ctl.rc_end_appl)
		rack->r_ctl.rc_end_appl = NULL;
	if (rack->r_ctl.rc_tlpsend == rsm)
		rack->r_ctl.rc_tlpsend = NULL;
	if (rack->r_ctl.rc_sacklast == rsm)
		rack->r_ctl.rc_sacklast = NULL;
	if (rack->rc_free_cnt < rack_free_cache) {
		memset(rsm, 0, sizeof(struct rack_sendmap));
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_free, rsm, r_tnext);
		rsm->r_limit_type = 0;
		rack->rc_free_cnt++;
		return;
	}
	rack->r_ctl.rc_num_maps_alloced--;
	uma_zfree(rack_zone, rsm);
}

static uint32_t
rack_get_measure_window(struct tcpcb *tp, struct tcp_rack *rack)
{
	uint64_t srtt, bw, len, tim;
	uint32_t segsiz, def_len, minl;

	segsiz = min(ctf_fixed_maxseg(tp), rack->r_ctl.rc_pace_min_segs);
	def_len = rack_def_data_window * segsiz;
	if (rack->rc_gp_filled == 0) {
		/*
		 * We have no measurement (IW is in flight?) so
		 * we can only guess using our data_window sysctl
		 * value (usually 100MSS).
		 */
		return (def_len);
	}
	/*
	 * Now we have a number of factors to consider.
	 *
	 * 1) We have a desired BDP which is usually
	 *    at least 2.
	 * 2) We have a minimum number of rtt's usually 1 SRTT
	 *    but we allow it too to be more.
	 * 3) We want to make sure a measurement last N useconds (if
	 *    we have set rack_min_measure_usec.
	 *
	 * We handle the first concern here by trying to create a data
	 * window of max(rack_def_data_window, DesiredBDP). The
	 * second concern we handle in not letting the measurement
	 * window end normally until at least the required SRTT's
	 * have gone by which is done further below in
	 * rack_enough_for_measurement(). Finally the third concern
	 * we also handle here by calculating how long that time
	 * would take at the current BW and then return the
	 * max of our first calculation and that length. Note
	 * that if rack_min_measure_usec is 0, we don't deal
	 * with concern 3. Also for both Concern 1 and 3 an
	 * application limited period could end the measurement
	 * earlier.
	 *
	 * So lets calculate the BDP with the "known" b/w using
	 * the SRTT has our rtt and then multiply it by the
	 * goal.
	 */
	bw = rack_get_bw(rack);
	srtt = ((uint64_t)TICKS_2_USEC(tp->t_srtt) >> TCP_RTT_SHIFT);
	len = bw * srtt;
	len /= (uint64_t)HPTS_USEC_IN_SEC;
	len *= max(1, rack_goal_bdp);
        /* Now we need to round up to the nearest MSS */
	len = roundup(len, segsiz);
	if (rack_min_measure_usec) {
		/* Now calculate our min length for this b/w */
		tim = rack_min_measure_usec;
		minl = (tim * bw) / (uint64_t)HPTS_USEC_IN_SEC;
		if (minl == 0)
			minl = 1;
		minl = roundup(minl, segsiz);
		if (len < minl)
			len = minl;
	}
	/*
	 * Now if we have a very small window we want
	 * to attempt to get the window that is
	 * as small as possible. This happens on
	 * low b/w connections and we don't want to
	 * span huge numbers of rtt's between measurements.
	 *
	 * We basically include 2 over our "MIN window" so
	 * that the measurement can be shortened (possibly) by
	 * an ack'ed packet.
	 */
	if (len < def_len)
		return (max((uint32_t)len, ((MIN_GP_WIN+2) * segsiz)));
	else
		return (max((uint32_t)len, def_len));

}

static int
rack_enough_for_measurement(struct tcpcb *tp, struct tcp_rack *rack, tcp_seq th_ack)
{
	uint32_t tim, srtts, segsiz;

	/*
	 * Has enough time passed for the GP measurement to be valid?
	 */
	if ((tp->snd_max == tp->snd_una) ||
	    (th_ack == tp->snd_max)){
		/* All is acked */
		return (1);
	}
	if (SEQ_LT(th_ack, tp->gput_seq)) {
		/* Not enough bytes yet */
		return (0);
	}
	segsiz = min(ctf_fixed_maxseg(tp), rack->r_ctl.rc_pace_min_segs);
	if (SEQ_LT(th_ack, tp->gput_ack) &&
	    ((th_ack - tp->gput_seq) < max(rc_init_window(rack), (MIN_GP_WIN * segsiz)))) {
		/* Not enough bytes yet */
		return (0);
	}
	if (rack->r_ctl.rc_first_appl &&
	    (rack->r_ctl.rc_first_appl->r_start == th_ack)) {
		/*
		 * We are up to the app limited point
		 * we have to measure irrespective of the time..
		 */
		return (1);
	}
	/* Now what about time? */
	srtts = (rack->r_ctl.rc_gp_srtt * rack_min_srtts);
	tim = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time) - tp->gput_ts;
	if (tim >= srtts) {
		return (1);
	}
	/* Nope not even a full SRTT has passed */
	return (0);
}


static void
rack_log_timely(struct tcp_rack *rack,
		uint32_t logged, uint64_t cur_bw, uint64_t low_bnd,
		uint64_t up_bnd, int line, uint8_t method)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = logged;
		log.u_bbr.flex2 = rack->rc_gp_timely_inc_cnt;
		log.u_bbr.flex2 <<= 4;
		log.u_bbr.flex2 |= rack->rc_gp_timely_dec_cnt;
		log.u_bbr.flex2 <<= 4;
		log.u_bbr.flex2 |= rack->rc_gp_incr;
		log.u_bbr.flex2 <<= 4;
		log.u_bbr.flex2 |= rack->rc_gp_bwred;
		log.u_bbr.flex3 = rack->rc_gp_incr;
		log.u_bbr.flex4 = rack->r_ctl.rack_per_of_gp_ss;
		log.u_bbr.flex5 = rack->r_ctl.rack_per_of_gp_ca;
		log.u_bbr.flex6 = rack->r_ctl.rack_per_of_gp_rec;
		log.u_bbr.flex7 = rack->rc_gp_bwred;
		log.u_bbr.flex8 = method;
		log.u_bbr.cur_del_rate = cur_bw;
		log.u_bbr.delRate = low_bnd;
		log.u_bbr.bw_inuse = up_bnd;
		log.u_bbr.rttProp = rack_get_bw(rack);
		log.u_bbr.pkt_epoch = line;
		log.u_bbr.pkts_out = rack->r_ctl.rc_rtt_diff;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		log.u_bbr.epoch = rack->r_ctl.rc_gp_srtt;
		log.u_bbr.lt_epoch = rack->r_ctl.rc_prev_gp_srtt;
		log.u_bbr.cwnd_gain = rack->rc_dragged_bottom;
		log.u_bbr.cwnd_gain <<= 1;
		log.u_bbr.cwnd_gain |= rack->rc_gp_saw_rec;
		log.u_bbr.cwnd_gain <<= 1;
		log.u_bbr.cwnd_gain |= rack->rc_gp_saw_ss;
		log.u_bbr.cwnd_gain <<= 1;
		log.u_bbr.cwnd_gain |= rack->rc_gp_saw_ca;
		log.u_bbr.lost = rack->r_ctl.rc_loss_count;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    TCP_TIMELY_WORK, 0,
		    0, &log, false, &tv);
	}
}

static int
rack_bw_can_be_raised(struct tcp_rack *rack, uint64_t cur_bw, uint64_t last_bw_est, uint16_t mult)
{
	/*
	 * Before we increase we need to know if
	 * the estimate just made was less than
	 * our pacing goal (i.e. (cur_bw * mult) > last_bw_est)
	 *
	 * If we already are pacing at a fast enough
	 * rate to push us faster there is no sense of
	 * increasing.
	 *
	 * We first caculate our actual pacing rate (ss or ca multipler
	 * times our cur_bw).
	 *
	 * Then we take the last measured rate and multipy by our
	 * maximum pacing overage to give us a max allowable rate.
	 *
	 * If our act_rate is smaller than our max_allowable rate
	 * then we should increase. Else we should hold steady.
	 *
	 */
	uint64_t act_rate, max_allow_rate;

	if (rack_timely_no_stopping)
		return (1);

	if ((cur_bw == 0) || (last_bw_est == 0)) {
		/*
		 * Initial startup case or
		 * everything is acked case.
		 */
		rack_log_timely(rack,  mult, cur_bw, 0, 0,
				__LINE__, 9);
		return (1);
	}
	if (mult <= 100) {
		/*
		 * We can always pace at or slightly above our rate.
		 */
		rack_log_timely(rack,  mult, cur_bw, 0, 0,
				__LINE__, 9);
		return (1);
	}
	act_rate = cur_bw * (uint64_t)mult;
	act_rate /= 100;
	max_allow_rate = last_bw_est * ((uint64_t)rack_max_per_above + (uint64_t)100);
	max_allow_rate /= 100;
	if (act_rate < max_allow_rate) {
		/*
		 * Here the rate we are actually pacing at
		 * is smaller than 10% above our last measurement.
		 * This means we are pacing below what we would
		 * like to try to achieve (plus some wiggle room).
		 */
		rack_log_timely(rack,  mult, cur_bw, act_rate, max_allow_rate,
				__LINE__, 9);
		return (1);
	} else {
		/*
		 * Here we are already pacing at least rack_max_per_above(10%)
		 * what we are getting back. This indicates most likely
		 * that we are being limited (cwnd/rwnd/app) and can't
		 * get any more b/w. There is no sense of trying to
		 * raise up the pacing rate its not speeding us up
		 * and we already are pacing faster than we are getting.
		 */
		rack_log_timely(rack,  mult, cur_bw, act_rate, max_allow_rate,
				__LINE__, 8);
		return (0);
	}
}

static void
rack_validate_multipliers_at_or_above100(struct tcp_rack *rack)
{
	/*
	 * When we drag bottom, we want to assure
	 * that no multiplier is below 1.0, if so
	 * we want to restore it to at least that.
	 */
	if (rack->r_ctl.rack_per_of_gp_rec  < 100) {
		/* This is unlikely we usually do not touch recovery */
		rack->r_ctl.rack_per_of_gp_rec = 100;
	}
	if (rack->r_ctl.rack_per_of_gp_ca < 100) {
		rack->r_ctl.rack_per_of_gp_ca = 100;
	}
	if (rack->r_ctl.rack_per_of_gp_ss < 100) {
		rack->r_ctl.rack_per_of_gp_ss = 100;
	}
}

static void
rack_validate_multipliers_at_or_below_100(struct tcp_rack *rack)
{
	if (rack->r_ctl.rack_per_of_gp_ca > 100) {
		rack->r_ctl.rack_per_of_gp_ca = 100;
	}
	if (rack->r_ctl.rack_per_of_gp_ss > 100) {
		rack->r_ctl.rack_per_of_gp_ss = 100;
	}
}

static void
rack_increase_bw_mul(struct tcp_rack *rack, int timely_says, uint64_t cur_bw, uint64_t last_bw_est, int override)
{
	int32_t  calc, logged, plus;

	logged = 0;

	if (override) {
		/*
		 * override is passed when we are
		 * loosing b/w and making one last
		 * gasp at trying to not loose out
		 * to a new-reno flow.
		 */
		goto extra_boost;
	}
	/* In classic timely we boost by 5x if we have 5 increases in a row, lets not */
	if (rack->rc_gp_incr &&
	    ((rack->rc_gp_timely_inc_cnt + 1) >= RACK_TIMELY_CNT_BOOST)) {
		/*
		 * Reset and get 5 strokes more before the boost. Note
		 * that the count is 0 based so we have to add one.
		 */
extra_boost:
		plus = (uint32_t)rack_gp_increase_per * RACK_TIMELY_CNT_BOOST;
		rack->rc_gp_timely_inc_cnt = 0;
	} else
		plus = (uint32_t)rack_gp_increase_per;
	/* Must be at least 1% increase for true timely increases */
	if ((plus < 1) &&
	    ((rack->r_ctl.rc_rtt_diff <= 0) || (timely_says <= 0)))
		plus = 1;
	if (rack->rc_gp_saw_rec &&
	    (rack->rc_gp_no_rec_chg == 0) &&
	    rack_bw_can_be_raised(rack, cur_bw, last_bw_est,
				  rack->r_ctl.rack_per_of_gp_rec)) {
		/* We have been in recovery ding it too */
		calc = rack->r_ctl.rack_per_of_gp_rec + plus;
		if (calc > 0xffff)
			calc = 0xffff;
		logged |= 1;
		rack->r_ctl.rack_per_of_gp_rec = (uint16_t)calc;
		if (rack_per_upper_bound_ss &&
		    (rack->rc_dragged_bottom == 0) &&
		    (rack->r_ctl.rack_per_of_gp_rec > rack_per_upper_bound_ss))
			rack->r_ctl.rack_per_of_gp_rec = rack_per_upper_bound_ss;
	}
	if (rack->rc_gp_saw_ca &&
	    (rack->rc_gp_saw_ss == 0) &&
	    rack_bw_can_be_raised(rack, cur_bw, last_bw_est,
				  rack->r_ctl.rack_per_of_gp_ca)) {
		/* In CA */
		calc = rack->r_ctl.rack_per_of_gp_ca + plus;
		if (calc > 0xffff)
			calc = 0xffff;
		logged |= 2;
		rack->r_ctl.rack_per_of_gp_ca = (uint16_t)calc;
		if (rack_per_upper_bound_ca &&
		    (rack->rc_dragged_bottom == 0) &&
		    (rack->r_ctl.rack_per_of_gp_ca > rack_per_upper_bound_ca))
			rack->r_ctl.rack_per_of_gp_ca = rack_per_upper_bound_ca;
	}
	if (rack->rc_gp_saw_ss &&
	    rack_bw_can_be_raised(rack, cur_bw, last_bw_est,
				  rack->r_ctl.rack_per_of_gp_ss)) {
		/* In SS */
		calc = rack->r_ctl.rack_per_of_gp_ss + plus;
		if (calc > 0xffff)
			calc = 0xffff;
		rack->r_ctl.rack_per_of_gp_ss = (uint16_t)calc;
		if (rack_per_upper_bound_ss &&
		    (rack->rc_dragged_bottom == 0) &&
		    (rack->r_ctl.rack_per_of_gp_ss > rack_per_upper_bound_ss))
			rack->r_ctl.rack_per_of_gp_ss = rack_per_upper_bound_ss;
		logged |= 4;
	}
	if (logged &&
	    (rack->rc_gp_incr == 0)){
		/* Go into increment mode */
		rack->rc_gp_incr = 1;
		rack->rc_gp_timely_inc_cnt = 0;
	}
	if (rack->rc_gp_incr &&
	    logged &&
	    (rack->rc_gp_timely_inc_cnt < RACK_TIMELY_CNT_BOOST)) {
		rack->rc_gp_timely_inc_cnt++;
	}
	rack_log_timely(rack,  logged, plus, 0, 0,
			__LINE__, 1);
}

static uint32_t
rack_get_decrease(struct tcp_rack *rack, uint32_t curper, int32_t rtt_diff)
{
	/*
	 * norm_grad = rtt_diff / minrtt;
	 * new_per = curper  * (1 - B * norm_grad)
	 *
	 * B = rack_gp_decrease_per (default 10%)
	 * rtt_dif = input var current rtt-diff
	 * curper = input var current percentage
	 * minrtt = from rack filter
	 *
	 */
	uint64_t perf;

	perf = (((uint64_t)curper * ((uint64_t)1000000 -
		    ((uint64_t)rack_gp_decrease_per * (uint64_t)10000 *
		     (((uint64_t)rtt_diff * (uint64_t)1000000)/
		      (uint64_t)get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt)))/
		     (uint64_t)1000000)) /
		(uint64_t)1000000);
	if (perf > curper) {
		/* TSNH */
		perf = curper - 1;
	}
	return ((uint32_t)perf);
}

static uint32_t
rack_decrease_highrtt(struct tcp_rack *rack, uint32_t curper, uint32_t rtt)
{
	/*
	 *                                   highrttthresh
	 * result = curper * (1 - (B * ( 1 -  ------          ))
	 *                                     gp_srtt
	 *
	 * B = rack_gp_decrease_per (default 10%)
	 * highrttthresh = filter_min * rack_gp_rtt_maxmul
	 */
	uint64_t perf;
	uint32_t highrttthresh;

	highrttthresh = get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) * rack_gp_rtt_maxmul;

	perf =  (((uint64_t)curper * ((uint64_t)1000000 -
				    ((uint64_t)rack_gp_decrease_per * ((uint64_t)1000000 -
					((uint64_t)highrttthresh * (uint64_t)1000000) /
						    (uint64_t)rtt)) / 100)) /(uint64_t)1000000);
	return (perf);
}


static void
rack_decrease_bw_mul(struct tcp_rack *rack, int timely_says, uint32_t rtt, int32_t rtt_diff)
{
	uint64_t logvar, logvar2, logvar3;
	uint32_t logged, new_per, ss_red, ca_red, rec_red, alt, val;

	if (rack->rc_gp_incr) {
		/* Turn off increment counting  */
		rack->rc_gp_incr = 0;
		rack->rc_gp_timely_inc_cnt = 0;
	}
	ss_red = ca_red = rec_red = 0;
	logged = 0;
	/* Calculate the reduction value */
	if (rtt_diff < 0) {
		rtt_diff *= -1;
	}
	/* Must be at least 1% reduction */
	if (rack->rc_gp_saw_rec && (rack->rc_gp_no_rec_chg == 0)) {
		/* We have been in recovery ding it too */
		if (timely_says == 2) {
			new_per = rack_decrease_highrtt(rack, rack->r_ctl.rack_per_of_gp_rec, rtt);
			alt = rack_get_decrease(rack, rack->r_ctl.rack_per_of_gp_rec, rtt_diff);
			if (alt < new_per)
				val = alt;
			else
				val = new_per;
		} else
			 val = new_per = alt = rack_get_decrease(rack, rack->r_ctl.rack_per_of_gp_rec, rtt_diff);
		if (rack->r_ctl.rack_per_of_gp_rec > val) {
			rec_red = (rack->r_ctl.rack_per_of_gp_rec - val);
			rack->r_ctl.rack_per_of_gp_rec = (uint16_t)val;
		} else {
			rack->r_ctl.rack_per_of_gp_rec = rack_per_lower_bound;
			rec_red = 0;
		}
		if (rack_per_lower_bound > rack->r_ctl.rack_per_of_gp_rec)
			rack->r_ctl.rack_per_of_gp_rec = rack_per_lower_bound;
		logged |= 1;
	}
	if (rack->rc_gp_saw_ss) {
		/* Sent in SS */
		if (timely_says == 2) {
			new_per = rack_decrease_highrtt(rack, rack->r_ctl.rack_per_of_gp_ss, rtt);
			alt = rack_get_decrease(rack, rack->r_ctl.rack_per_of_gp_rec, rtt_diff);
			if (alt < new_per)
				val = alt;
			else
				val = new_per;
		} else
			val = new_per = alt = rack_get_decrease(rack, rack->r_ctl.rack_per_of_gp_ss, rtt_diff);
		if (rack->r_ctl.rack_per_of_gp_ss > new_per) {
			ss_red = rack->r_ctl.rack_per_of_gp_ss - val;
			rack->r_ctl.rack_per_of_gp_ss = (uint16_t)val;
		} else {
			ss_red = new_per;
			rack->r_ctl.rack_per_of_gp_ss = rack_per_lower_bound;
			logvar = new_per;
			logvar <<= 32;
			logvar |= alt;
			logvar2 = (uint32_t)rtt;
			logvar2 <<= 32;
			logvar2 |= (uint32_t)rtt_diff;
			logvar3 = rack_gp_rtt_maxmul;
			logvar3 <<= 32;
			logvar3 |= get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt);
			rack_log_timely(rack, timely_says,
					logvar2, logvar3,
					logvar, __LINE__, 10);
		}
		if (rack_per_lower_bound > rack->r_ctl.rack_per_of_gp_ss)
			rack->r_ctl.rack_per_of_gp_ss = rack_per_lower_bound;
		logged |= 4;
	} else 	if (rack->rc_gp_saw_ca) {
		/* Sent in CA */
		if (timely_says == 2) {
			new_per = rack_decrease_highrtt(rack, rack->r_ctl.rack_per_of_gp_ca, rtt);
			alt = rack_get_decrease(rack, rack->r_ctl.rack_per_of_gp_rec, rtt_diff);
			if (alt < new_per)
				val = alt;
			else
				val = new_per;
		} else
			val = new_per = alt = rack_get_decrease(rack, rack->r_ctl.rack_per_of_gp_ca, rtt_diff);
		if (rack->r_ctl.rack_per_of_gp_ca > val) {
			ca_red = rack->r_ctl.rack_per_of_gp_ca - val;
			rack->r_ctl.rack_per_of_gp_ca = (uint16_t)val;
		} else {
			rack->r_ctl.rack_per_of_gp_ca = rack_per_lower_bound;
			ca_red = 0;
			logvar = new_per;
			logvar <<= 32;
			logvar |= alt;
			logvar2 = (uint32_t)rtt;
			logvar2 <<= 32;
			logvar2 |= (uint32_t)rtt_diff;
			logvar3 = rack_gp_rtt_maxmul;
			logvar3 <<= 32;
			logvar3 |= get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt);
			rack_log_timely(rack, timely_says,
					logvar2, logvar3,
					logvar, __LINE__, 10);
		}
		if (rack_per_lower_bound > rack->r_ctl.rack_per_of_gp_ca)
			rack->r_ctl.rack_per_of_gp_ca = rack_per_lower_bound;
		logged |= 2;
	}
	if (rack->rc_gp_timely_dec_cnt < 0x7) {
		rack->rc_gp_timely_dec_cnt++;
		if (rack_timely_dec_clear &&
		    (rack->rc_gp_timely_dec_cnt == rack_timely_dec_clear))
			rack->rc_gp_timely_dec_cnt = 0;
	}
	logvar = ss_red;
	logvar <<= 32;
	logvar |= ca_red;
	rack_log_timely(rack,  logged, rec_red, rack_per_lower_bound, logvar,
			__LINE__, 2);
}

static void
rack_log_rtt_shrinks(struct tcp_rack *rack, uint32_t us_cts,
		     uint32_t rtt, uint32_t line, uint8_t reas)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = line;
		log.u_bbr.flex2 = rack->r_ctl.rc_time_probertt_starts;
		log.u_bbr.flex3 = rack->r_ctl.rc_lower_rtt_us_cts;
		log.u_bbr.flex4 = rack->r_ctl.rack_per_of_gp_ss;
		log.u_bbr.flex5 = rtt;
		log.u_bbr.flex6 = rack->rc_highly_buffered;
		log.u_bbr.flex6 <<= 1;
		log.u_bbr.flex6 |= rack->forced_ack;
		log.u_bbr.flex6 <<= 1;
		log.u_bbr.flex6 |= rack->rc_gp_dyn_mul;
		log.u_bbr.flex6 <<= 1;
		log.u_bbr.flex6 |= rack->in_probe_rtt;
		log.u_bbr.flex6 <<= 1;
		log.u_bbr.flex6 |= rack->measure_saw_probe_rtt;
		log.u_bbr.flex7 = rack->r_ctl.rack_per_of_gp_probertt;
		log.u_bbr.pacing_gain = rack->r_ctl.rack_per_of_gp_ca;
		log.u_bbr.cwnd_gain = rack->r_ctl.rack_per_of_gp_rec;
		log.u_bbr.flex8 = reas;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.delRate = rack_get_bw(rack);
		log.u_bbr.cur_del_rate = rack->r_ctl.rc_highest_us_rtt;
		log.u_bbr.cur_del_rate <<= 32;
		log.u_bbr.cur_del_rate |= rack->r_ctl.rc_lowest_us_rtt;
		log.u_bbr.applimited = rack->r_ctl.rc_time_probertt_entered;
		log.u_bbr.pkts_out = rack->r_ctl.rc_rtt_diff;
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		log.u_bbr.epoch = rack->r_ctl.rc_gp_srtt;
		log.u_bbr.lt_epoch = rack->r_ctl.rc_prev_gp_srtt;
		log.u_bbr.pkt_epoch = rack->r_ctl.rc_lower_rtt_us_cts;
		log.u_bbr.delivered = rack->r_ctl.rc_target_probertt_flight;
		log.u_bbr.lost = get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt);
		log.u_bbr.rttProp = us_cts;
		log.u_bbr.rttProp <<= 32;
		log.u_bbr.rttProp |= rack->r_ctl.rc_entry_gp_rtt;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_RTT_SHRINKS, 0,
		    0, &log, false, &rack->r_ctl.act_rcv_time);
	}
}

static void
rack_set_prtt_target(struct tcp_rack *rack, uint32_t segsiz, uint32_t rtt)
{
	uint64_t bwdp;

	bwdp = rack_get_bw(rack);
	bwdp *= (uint64_t)rtt;
	bwdp /= (uint64_t)HPTS_USEC_IN_SEC;
	rack->r_ctl.rc_target_probertt_flight = roundup((uint32_t)bwdp, segsiz);
	if (rack->r_ctl.rc_target_probertt_flight < (segsiz * rack_timely_min_segs)) {
		/*
		 * A window protocol must be able to have 4 packets
		 * outstanding as the floor in order to function
		 * (especially considering delayed ack :D).
		 */
		rack->r_ctl.rc_target_probertt_flight = (segsiz * rack_timely_min_segs);
	}
}

static void
rack_enter_probertt(struct tcp_rack *rack, uint32_t us_cts)
{
	/**
	 * ProbeRTT is a bit different in rack_pacing than in
	 * BBR. It is like BBR in that it uses the lowering of
	 * the RTT as a signal that we saw something new and
	 * counts from there for how long between. But it is
	 * different in that its quite simple. It does not
	 * play with the cwnd and wait until we get down
	 * to N segments outstanding and hold that for
	 * 200ms. Instead it just sets the pacing reduction
	 * rate to a set percentage (70 by default) and hold
	 * that for a number of recent GP Srtt's.
	 */
	uint32_t segsiz;

	if (rack->rc_gp_dyn_mul == 0)
		return;

	if (rack->rc_tp->snd_max == rack->rc_tp->snd_una) {
		/* We are idle */
		return;
	}
	if ((rack->rc_tp->t_flags & TF_GPUTINPROG) &&
	    SEQ_GT(rack->rc_tp->snd_una, rack->rc_tp->gput_seq)) {
		/*
		 * Stop the goodput now, the idea here is
		 * that future measurements with in_probe_rtt
		 * won't register if they are not greater so
		 * we want to get what info (if any) is available
		 * now.
		 */
		rack_do_goodput_measurement(rack->rc_tp, rack,
					    rack->rc_tp->snd_una, __LINE__);
	}
	rack->r_ctl.rack_per_of_gp_probertt = rack_per_of_gp_probertt;
	rack->r_ctl.rc_time_probertt_entered = us_cts;
	segsiz = min(ctf_fixed_maxseg(rack->rc_tp),
		     rack->r_ctl.rc_pace_min_segs);
	rack->in_probe_rtt = 1;
	rack->measure_saw_probe_rtt = 1;
	rack->r_ctl.rc_lower_rtt_us_cts = us_cts;
	rack->r_ctl.rc_time_probertt_starts = 0;
	rack->r_ctl.rc_entry_gp_rtt = rack->r_ctl.rc_gp_srtt;
	if (rack_probertt_use_min_rtt_entry)
		rack_set_prtt_target(rack, segsiz, get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt));
	else
		rack_set_prtt_target(rack, segsiz, rack->r_ctl.rc_gp_srtt);
	rack_log_rtt_shrinks(rack,  us_cts,  get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt),
			     __LINE__, RACK_RTTS_ENTERPROBE);
}

static void
rack_exit_probertt(struct tcp_rack *rack, uint32_t us_cts)
{
	struct rack_sendmap *rsm;
	uint32_t segsiz;

	segsiz = min(ctf_fixed_maxseg(rack->rc_tp),
		     rack->r_ctl.rc_pace_min_segs);
	rack->in_probe_rtt = 0;
	if ((rack->rc_tp->t_flags & TF_GPUTINPROG) &&
	    SEQ_GT(rack->rc_tp->snd_una, rack->rc_tp->gput_seq)) {
		/*
		 * Stop the goodput now, the idea here is
		 * that future measurements with in_probe_rtt
		 * won't register if they are not greater so
		 * we want to get what info (if any) is available
		 * now.
		 */
		rack_do_goodput_measurement(rack->rc_tp, rack,
					    rack->rc_tp->snd_una, __LINE__);
	} else if (rack->rc_tp->t_flags & TF_GPUTINPROG) {
		/*
		 * We don't have enough data to make a measurement.
		 * So lets just stop and start here after exiting
		 * probe-rtt. We probably are not interested in
		 * the results anyway.
		 */
		rack->rc_tp->t_flags &= ~TF_GPUTINPROG;
	}
	/*
	 * Measurements through the current snd_max are going
	 * to be limited by the slower pacing rate.
	 *
	 * We need to mark these as app-limited so we
	 * don't collapse the b/w.
	 */
	rsm = RB_MAX(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
	if (rsm && ((rsm->r_flags & RACK_APP_LIMITED) == 0)) {
		if (rack->r_ctl.rc_app_limited_cnt == 0)
			rack->r_ctl.rc_end_appl = rack->r_ctl.rc_first_appl = rsm;
		else {
			/*
			 * Go out to the end app limited and mark
			 * this new one as next and move the end_appl up
			 * to this guy.
			 */
			if (rack->r_ctl.rc_end_appl)
				rack->r_ctl.rc_end_appl->r_nseq_appl = rsm->r_start;
			rack->r_ctl.rc_end_appl = rsm;
		}
		rsm->r_flags |= RACK_APP_LIMITED;
		rack->r_ctl.rc_app_limited_cnt++;
	}
	/*
	 * Now, we need to examine our pacing rate multipliers.
	 * If its under 100%, we need to kick it back up to
	 * 100%. We also don't let it be over our "max" above
	 * the actual rate i.e. 100% + rack_clamp_atexit_prtt.
	 * Note setting clamp_atexit_prtt to 0 has the effect
	 * of setting CA/SS to 100% always at exit (which is
	 * the default behavior).
	 */
	if (rack_probertt_clear_is) {
		rack->rc_gp_incr = 0;
		rack->rc_gp_bwred = 0;
		rack->rc_gp_timely_inc_cnt = 0;
		rack->rc_gp_timely_dec_cnt = 0;
	}
	/* Do we do any clamping at exit? */
	if (rack->rc_highly_buffered && rack_atexit_prtt_hbp) {
		rack->r_ctl.rack_per_of_gp_ca = rack_atexit_prtt_hbp;
		rack->r_ctl.rack_per_of_gp_ss = rack_atexit_prtt_hbp;
	}
	if ((rack->rc_highly_buffered == 0) && rack_atexit_prtt) {
		rack->r_ctl.rack_per_of_gp_ca = rack_atexit_prtt;
		rack->r_ctl.rack_per_of_gp_ss = rack_atexit_prtt;
	}
	/*
	 * Lets set rtt_diff to 0, so that we will get a "boost"
	 * after exiting.
	 */
	rack->r_ctl.rc_rtt_diff = 0;

	/* Clear all flags so we start fresh */
	rack->rc_tp->t_bytes_acked = 0;
	rack->rc_tp->ccv->flags &= ~CCF_ABC_SENTAWND;
	/*
	 * If configured to, set the cwnd and ssthresh to
	 * our targets.
	 */
	if (rack_probe_rtt_sets_cwnd) {
		uint64_t ebdp;
		uint32_t setto;

		/* Set ssthresh so we get into CA once we hit our target */
		if (rack_probertt_use_min_rtt_exit == 1) {
			/* Set to min rtt */
			rack_set_prtt_target(rack, segsiz,
					     get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt));
		} else if (rack_probertt_use_min_rtt_exit == 2) {
			/* Set to current gp rtt */
			rack_set_prtt_target(rack, segsiz,
					     rack->r_ctl.rc_gp_srtt);
		} else if (rack_probertt_use_min_rtt_exit == 3) {
			/* Set to entry gp rtt */
			rack_set_prtt_target(rack, segsiz,
					     rack->r_ctl.rc_entry_gp_rtt);
		} else  {
			uint64_t sum;
			uint32_t setval;

			sum = rack->r_ctl.rc_entry_gp_rtt;
			sum *= 10;
			sum /= (uint64_t)(max(1, rack->r_ctl.rc_gp_srtt));
			if (sum >= 20) {
				/*
				 * A highly buffered path needs
				 * cwnd space for timely to work.
				 * Lets set things up as if
				 * we are heading back here again.
				 */
				setval = rack->r_ctl.rc_entry_gp_rtt;
			} else if (sum >= 15) {
				/*
				 * Lets take the smaller of the
				 * two since we are just somewhat
				 * buffered.
				 */
				setval = rack->r_ctl.rc_gp_srtt;
				if (setval > rack->r_ctl.rc_entry_gp_rtt)
					setval = rack->r_ctl.rc_entry_gp_rtt;
			} else {
				/*
				 * Here we are not highly buffered
				 * and should pick the min we can to
				 * keep from causing loss.
				 */
				setval = get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt);
			}
			rack_set_prtt_target(rack, segsiz,
					     setval);
		}
		if (rack_probe_rtt_sets_cwnd > 1) {
			/* There is a percentage here to boost */
			ebdp = rack->r_ctl.rc_target_probertt_flight;
			ebdp *= rack_probe_rtt_sets_cwnd;
			ebdp /= 100;
			setto = rack->r_ctl.rc_target_probertt_flight + ebdp;
		} else
			setto = rack->r_ctl.rc_target_probertt_flight;
		rack->rc_tp->snd_cwnd = roundup(setto, segsiz);
		if (rack->rc_tp->snd_cwnd < (segsiz * rack_timely_min_segs)) {
			/* Enforce a min */
			rack->rc_tp->snd_cwnd = segsiz * rack_timely_min_segs;
		}
		/* If we set in the cwnd also set the ssthresh point so we are in CA */
		rack->rc_tp->snd_ssthresh = (rack->rc_tp->snd_cwnd - 1);
	}
	rack_log_rtt_shrinks(rack,  us_cts,
			     get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt),
			     __LINE__, RACK_RTTS_EXITPROBE);
	/* Clear times last so log has all the info */
	rack->r_ctl.rc_probertt_sndmax_atexit = rack->rc_tp->snd_max;
	rack->r_ctl.rc_time_probertt_entered = us_cts;
	rack->r_ctl.rc_time_probertt_starts = rack->r_ctl.rc_lower_rtt_us_cts = us_cts;
	rack->r_ctl.rc_time_of_last_probertt = us_cts;
}

static void
rack_check_probe_rtt(struct tcp_rack *rack, uint32_t us_cts)
{
	/* Check in on probe-rtt */
	if (rack->rc_gp_filled == 0) {
		/* We do not do p-rtt unless we have gp measurements */
		return;
	}
	if (rack->in_probe_rtt) {
		uint64_t no_overflow;
		uint32_t endtime, must_stay;

		if (rack->r_ctl.rc_went_idle_time &&
		    ((us_cts - rack->r_ctl.rc_went_idle_time) > rack_min_probertt_hold)) {
			/*
			 * We went idle during prtt, just exit now.
			 */
			rack_exit_probertt(rack, us_cts);
		} else if (rack_probe_rtt_safety_val &&
		    TSTMP_GT(us_cts, rack->r_ctl.rc_time_probertt_entered) &&
		    ((us_cts - rack->r_ctl.rc_time_probertt_entered) > rack_probe_rtt_safety_val)) {
			/*
			 * Probe RTT safety value triggered!
			 */
			rack_log_rtt_shrinks(rack,  us_cts,
					     get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt),
					     __LINE__, RACK_RTTS_SAFETY);
			rack_exit_probertt(rack, us_cts);
		}
		/* Calculate the max we will wait */
		endtime = rack->r_ctl.rc_time_probertt_entered + (rack->r_ctl.rc_gp_srtt * rack_max_drain_wait);
		if (rack->rc_highly_buffered)
			endtime += (rack->r_ctl.rc_gp_srtt * rack_max_drain_hbp);
		/* Calculate the min we must wait */
		must_stay = rack->r_ctl.rc_time_probertt_entered + (rack->r_ctl.rc_gp_srtt * rack_must_drain);
		if ((ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked) > rack->r_ctl.rc_target_probertt_flight) &&
		    TSTMP_LT(us_cts, endtime)) {
			uint32_t calc;
			/* Do we lower more? */
no_exit:
			if (TSTMP_GT(us_cts, rack->r_ctl.rc_time_probertt_entered))
				calc = us_cts - rack->r_ctl.rc_time_probertt_entered;
			else
				calc = 0;
			calc /= max(rack->r_ctl.rc_gp_srtt, 1);
			if (calc) {
				/* Maybe */
				calc *= rack_per_of_gp_probertt_reduce;
				rack->r_ctl.rack_per_of_gp_probertt = rack_per_of_gp_probertt - calc;
				/* Limit it too */
				if (rack->r_ctl.rack_per_of_gp_probertt < rack_per_of_gp_lowthresh)
					rack->r_ctl.rack_per_of_gp_probertt = rack_per_of_gp_lowthresh;
			}
			/* We must reach target or the time set */
			return;
		}
		if (rack->r_ctl.rc_time_probertt_starts == 0) {
			if ((TSTMP_LT(us_cts, must_stay) &&
			     rack->rc_highly_buffered) ||
			     (ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked) >
			      rack->r_ctl.rc_target_probertt_flight)) {
				/* We are not past the must_stay time */
				goto no_exit;
			}
			rack_log_rtt_shrinks(rack,  us_cts,
					     get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt),
					     __LINE__, RACK_RTTS_REACHTARGET);
			rack->r_ctl.rc_time_probertt_starts = us_cts;
			if (rack->r_ctl.rc_time_probertt_starts == 0)
				rack->r_ctl.rc_time_probertt_starts = 1;
			/* Restore back to our rate we want to pace at in prtt */
			rack->r_ctl.rack_per_of_gp_probertt = rack_per_of_gp_probertt;
		}
		/*
		 * Setup our end time, some number of gp_srtts plus 200ms.
		 */
		no_overflow = ((uint64_t)rack->r_ctl.rc_gp_srtt *
			       (uint64_t)rack_probertt_gpsrtt_cnt_mul);
		if (rack_probertt_gpsrtt_cnt_div)
			endtime = (uint32_t)(no_overflow / (uint64_t)rack_probertt_gpsrtt_cnt_div);
		else
			endtime = 0;
		endtime += rack_min_probertt_hold;
		endtime += rack->r_ctl.rc_time_probertt_starts;
		if (TSTMP_GEQ(us_cts,  endtime)) {
			/* yes, exit probertt  */
			rack_exit_probertt(rack, us_cts);
 		}

	} else 	if((us_cts - rack->r_ctl.rc_lower_rtt_us_cts) >= rack_time_between_probertt) {
		/* Go into probertt, its been too long since we went lower  */
		rack_enter_probertt(rack, us_cts);
	}
}

static void
rack_update_multiplier(struct tcp_rack *rack, int32_t timely_says, uint64_t last_bw_est,
		       uint32_t rtt, int32_t rtt_diff)
{
	uint64_t cur_bw, up_bnd, low_bnd, subfr;
	uint32_t losses;

	if ((rack->rc_gp_dyn_mul == 0) ||
	    (rack->use_fixed_rate) ||
	    (rack->in_probe_rtt) ||
	    (rack->rc_always_pace == 0)) {
		/* No dynamic GP multipler in play */
		return;
	}
	losses = rack->r_ctl.rc_loss_count - rack->r_ctl.rc_loss_at_start;
	cur_bw = rack_get_bw(rack);
	/* Calculate our up and down range */
	up_bnd = rack->r_ctl.last_gp_comp_bw * (uint64_t)rack_gp_per_bw_mul_up;
	up_bnd /= 100;
	up_bnd += rack->r_ctl.last_gp_comp_bw;

	subfr = (uint64_t)rack->r_ctl.last_gp_comp_bw * (uint64_t)rack_gp_per_bw_mul_down;
	subfr /= 100;
	low_bnd = rack->r_ctl.last_gp_comp_bw - subfr;
	if ((timely_says == 2) && (rack->r_ctl.rc_no_push_at_mrtt)) {
		/*
		 * This is the case where our RTT is above
		 * the max target and we have been configured
		 * to just do timely no bonus up stuff in that case.
		 *
		 * There are two configurations, set to 1, and we
		 * just do timely if we are over our max. If its
		 * set above 1 then we slam the multipliers down
		 * to 100 and then decrement per timely.
		 */
		rack_log_timely(rack,  timely_says, cur_bw, low_bnd, up_bnd,
				__LINE__, 3);
		if (rack->r_ctl.rc_no_push_at_mrtt > 1)
			rack_validate_multipliers_at_or_below_100(rack);
		rack_decrease_bw_mul(rack, timely_says, rtt, rtt_diff);
	} else if ((last_bw_est < low_bnd) && !losses) {
		/*
		 * We are decreasing this is a bit complicated this
		 * means we are loosing ground. This could be
		 * because another flow entered and we are competing
		 * for b/w with it. This will push the RTT up which
		 * makes timely unusable unless we want to get shoved
		 * into a corner and just be backed off (the age
		 * old problem with delay based CC).
		 *
		 * On the other hand if it was a route change we
		 * would like to stay somewhat contained and not
		 * blow out the buffers.
		 */
		rack_log_timely(rack,  timely_says, cur_bw, low_bnd, up_bnd,
				__LINE__, 3);
		rack->r_ctl.last_gp_comp_bw = cur_bw;
		if (rack->rc_gp_bwred == 0) {
			/* Go into reduction counting */
			rack->rc_gp_bwred = 1;
			rack->rc_gp_timely_dec_cnt = 0;
		}
		if ((rack->rc_gp_timely_dec_cnt < rack_timely_max_push_drop) ||
		    (timely_says == 0)) {
			/*
			 * Push another time with a faster pacing
			 * to try to gain back (we include override to
			 * get a full raise factor).
			 */
			if ((rack->rc_gp_saw_ca && rack->r_ctl.rack_per_of_gp_ca <= rack_down_raise_thresh) ||
			    (rack->rc_gp_saw_ss && rack->r_ctl.rack_per_of_gp_ss <= rack_down_raise_thresh) ||
			    (timely_says == 0) ||
			    (rack_down_raise_thresh == 0)) {
				/*
				 * Do an override up in b/w if we were
				 * below the threshold or if the threshold
				 * is zero we always do the raise.
				 */
				rack_increase_bw_mul(rack, timely_says, cur_bw, last_bw_est, 1);
			} else {
				/* Log it stays the same */
				rack_log_timely(rack,  0, last_bw_est, low_bnd, 0,
						__LINE__, 11);

			}
			rack->rc_gp_timely_dec_cnt++;
			/* We are not incrementing really no-count */
			rack->rc_gp_incr = 0;
			rack->rc_gp_timely_inc_cnt = 0;
		} else {
			/*
			 * Lets just use the RTT
			 * information and give up
			 * pushing.
			 */
			goto use_timely;
		}
	}  else if ((timely_says != 2) &&
		    !losses &&
		    (last_bw_est > up_bnd)) {
		/*
		 * We are increasing b/w lets keep going, updating
		 * our b/w and ignoring any timely input, unless
		 * of course we are at our max raise (if there is one).
		 */

		rack_log_timely(rack,  timely_says, cur_bw, low_bnd, up_bnd,
				__LINE__, 3);
		rack->r_ctl.last_gp_comp_bw = cur_bw;
		if (rack->rc_gp_saw_ss &&
		    rack_per_upper_bound_ss &&
		     (rack->r_ctl.rack_per_of_gp_ss == rack_per_upper_bound_ss)) {
			    /*
			     * In cases where we can't go higher
			     * we should just use timely.
			     */
			    goto use_timely;
		}
		if (rack->rc_gp_saw_ca &&
		    rack_per_upper_bound_ca &&
		    (rack->r_ctl.rack_per_of_gp_ca == rack_per_upper_bound_ca)) {
			    /*
			     * In cases where we can't go higher
			     * we should just use timely.
			     */
			    goto use_timely;
		}
		rack->rc_gp_bwred = 0;
		rack->rc_gp_timely_dec_cnt = 0;
		/* You get a set number of pushes if timely is trying to reduce  */
		if ((rack->rc_gp_incr < rack_timely_max_push_rise) || (timely_says == 0)) {
			rack_increase_bw_mul(rack, timely_says, cur_bw, last_bw_est, 0);
		} else {
 			/* Log it stays the same */
			rack_log_timely(rack,  0, last_bw_est, up_bnd, 0,
			    __LINE__, 12);

		}
		return;
	} else {
		/*
		 * We are staying between the lower and upper range bounds
		 * so use timely to decide.
		 */
		rack_log_timely(rack,  timely_says, cur_bw, low_bnd, up_bnd,
				__LINE__, 3);
use_timely:
		if (timely_says) {
			rack->rc_gp_incr = 0;
			rack->rc_gp_timely_inc_cnt = 0;
			if ((rack->rc_gp_timely_dec_cnt < rack_timely_max_push_drop) &&
			    !losses &&
			    (last_bw_est < low_bnd)) {
				/* We are loosing ground */
				rack_increase_bw_mul(rack, timely_says, cur_bw, last_bw_est, 0);
				rack->rc_gp_timely_dec_cnt++;
				/* We are not incrementing really no-count */
				rack->rc_gp_incr = 0;
				rack->rc_gp_timely_inc_cnt = 0;
			} else
				rack_decrease_bw_mul(rack, timely_says, rtt, rtt_diff);
		} else  {
			rack->rc_gp_bwred = 0;
			rack->rc_gp_timely_dec_cnt = 0;
			rack_increase_bw_mul(rack, timely_says, cur_bw, last_bw_est, 0);
		}
	}
}

static int32_t
rack_make_timely_judgement(struct tcp_rack *rack, uint32_t rtt, int32_t rtt_diff, uint32_t prev_rtt)
{
	int32_t timely_says;
	uint64_t log_mult, log_rtt_a_diff;

	log_rtt_a_diff = rtt;
	log_rtt_a_diff <<= 32;
	log_rtt_a_diff |= (uint32_t)rtt_diff;
	if (rtt >= (get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) *
		    rack_gp_rtt_maxmul)) {
		/* Reduce the b/w multipler */
		timely_says = 2;
		log_mult = get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) * rack_gp_rtt_maxmul;
		log_mult <<= 32;
		log_mult |= prev_rtt;
		rack_log_timely(rack,  timely_says, log_mult,
				get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt),
				log_rtt_a_diff, __LINE__, 4);
	} else if (rtt <= (get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) +
			   ((get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) * rack_gp_rtt_minmul) /
			    max(rack_gp_rtt_mindiv , 1)))) {
		/* Increase the b/w multipler */
		log_mult = get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) +
			((get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) * rack_gp_rtt_minmul) /
			 max(rack_gp_rtt_mindiv , 1));
		log_mult <<= 32;
		log_mult |= prev_rtt;
		timely_says = 0;
		rack_log_timely(rack,  timely_says, log_mult ,
				get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt),
				log_rtt_a_diff, __LINE__, 5);
	} else {
		/*
		 * Use a gradient to find it the timely gradient
		 * is:
		 * grad = rc_rtt_diff / min_rtt;
		 *
		 * anything below or equal to 0 will be
		 * a increase indication. Anything above
		 * zero is a decrease. Note we take care
		 * of the actual gradient calculation
		 * in the reduction (its not needed for
		 * increase).
		 */
		log_mult = prev_rtt;
		if (rtt_diff <= 0) {
			/*
			 * Rttdiff is less than zero, increase the
			 * b/w multipler (its 0 or negative)
			 */
			timely_says = 0;
			rack_log_timely(rack,  timely_says, log_mult,
					get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt), log_rtt_a_diff, __LINE__, 6);
		} else {
			/* Reduce the b/w multipler */
			timely_says = 1;
			rack_log_timely(rack,  timely_says, log_mult,
					get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt), log_rtt_a_diff, __LINE__, 7);
		}
	}
	return (timely_says);
}

static void
rack_do_goodput_measurement(struct tcpcb *tp, struct tcp_rack *rack,
			    tcp_seq th_ack, int line)
{
	uint64_t tim, bytes_ps, ltim, stim, utim;
	uint32_t segsiz, bytes, reqbytes, us_cts;
	int32_t gput, new_rtt_diff, timely_says;

	us_cts = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
	segsiz = min(ctf_fixed_maxseg(tp), rack->r_ctl.rc_pace_min_segs);
	if (TSTMP_GEQ(us_cts, tp->gput_ts))
		tim = us_cts - tp->gput_ts;
	else
		tim = 0;

	if (TSTMP_GT(rack->r_ctl.rc_gp_cumack_ts, rack->r_ctl.rc_gp_output_ts))
		stim = rack->r_ctl.rc_gp_cumack_ts - rack->r_ctl.rc_gp_output_ts;
	else
		stim = 0;
	/*
	 * Use the larger of the send time or ack time. This prevents us
	 * from being influenced by ack artifacts to come up with too
	 * high of measurement. Note that since we are spanning over many more
	 * bytes in most of our measurements hopefully that is less likely to
	 * occur.
	 */
	if (tim > stim)
		utim = max(tim, 1);
	else
		utim = max(stim, 1);
	/* Lets validate utim */
	ltim = max(1, (utim/HPTS_USEC_IN_MSEC));
	gput = (((uint64_t) (th_ack - tp->gput_seq)) << 3) / ltim;
	reqbytes = min(rc_init_window(rack), (MIN_GP_WIN * segsiz));
	if ((tim == 0) && (stim == 0)) {
		/*
		 * Invalid measurement time, maybe
		 * all on one ack/one send?
		 */
		bytes = 0;
		bytes_ps = 0;
		rack_log_pacing_delay_calc(rack, bytes_ps, reqbytes,
					   0, 0, 0, 10, __LINE__, NULL);
		goto skip_measurement;
	}
	if (rack->r_ctl.rc_gp_lowrtt == 0xffffffff) {
		/* We never made a us_rtt measurement? */
		bytes = 0;
		bytes_ps = 0;
		rack_log_pacing_delay_calc(rack, bytes_ps, reqbytes,
					   0, 0, 0, 10, __LINE__, NULL);
		goto skip_measurement;
	}
	/*
	 * Calculate the maximum possible b/w this connection
	 * could have. We base our calculation on the lowest
	 * rtt we have seen during the measurement and the
	 * largest rwnd the client has given us in that time. This
	 * forms a BDP that is the maximum that we could ever
	 * get to the client. Anything larger is not valid.
	 *
	 * I originally had code here that rejected measurements
	 * where the time was less than 1/2 the latest us_rtt.
	 * But after thinking on that I realized its wrong since
	 * say you had a 150Mbps or even 1Gbps link, and you
	 * were a long way away.. example I am in Europe (100ms rtt)
	 * talking to my 1Gbps link in S.C. Now measuring say 150,000
	 * bytes my time would be 1.2ms, and yet my rtt would say
	 * the measurement was invalid the time was < 50ms. The
	 * same thing is true for 150Mb (8ms of time).
	 *
	 * A better way I realized is to look at what the maximum
	 * the connection could possibly do. This is gated on
	 * the lowest RTT we have seen and the highest rwnd.
	 * We should in theory never exceed that, if we are
	 * then something on the path is storing up packets
	 * and then feeding them all at once to our endpoint
	 * messing up our measurement.
	 */
	rack->r_ctl.last_max_bw = rack->r_ctl.rc_gp_high_rwnd;
	rack->r_ctl.last_max_bw *= HPTS_USEC_IN_SEC;
	rack->r_ctl.last_max_bw /= rack->r_ctl.rc_gp_lowrtt;
	if (SEQ_LT(th_ack, tp->gput_seq)) {
		/* No measurement can be made */
		bytes = 0;
		bytes_ps = 0;
		rack_log_pacing_delay_calc(rack, bytes_ps, reqbytes,
					   0, 0, 0, 10, __LINE__, NULL);
		goto skip_measurement;
	} else
		bytes = (th_ack - tp->gput_seq);
	bytes_ps = (uint64_t)bytes;
	/*
	 * Don't measure a b/w for pacing unless we have gotten at least
	 * an initial windows worth of data in this measurement interval.
	 *
	 * Small numbers of bytes get badly influenced by delayed ack and
	 * other artifacts. Note we take the initial window or our
	 * defined minimum GP (defaulting to 10 which hopefully is the
	 * IW).
	 */
	if (rack->rc_gp_filled == 0) {
		/*
		 * The initial estimate is special. We
		 * have blasted out an IW worth of packets
		 * without a real valid ack ts results. We
		 * then setup the app_limited_needs_set flag,
		 * this should get the first ack in (probably 2
		 * MSS worth) to be recorded as the timestamp.
		 * We thus allow a smaller number of bytes i.e.
		 * IW - 2MSS.
		 */
		reqbytes -= (2 * segsiz);
		/* Also lets fill previous for our first measurement to be neutral */
		rack->r_ctl.rc_prev_gp_srtt = rack->r_ctl.rc_gp_srtt;
	}
	if ((bytes_ps < reqbytes) || rack->app_limited_needs_set) {
		rack_log_pacing_delay_calc(rack, bytes_ps, reqbytes,
					   rack->r_ctl.rc_app_limited_cnt,
					   0, 0, 10, __LINE__, NULL);
		goto skip_measurement;
	}
	/*
	 * We now need to calculate the Timely like status so
	 * we can update (possibly) the b/w multipliers.
	 */
	new_rtt_diff = (int32_t)rack->r_ctl.rc_gp_srtt - (int32_t)rack->r_ctl.rc_prev_gp_srtt;
	if (rack->rc_gp_filled == 0) {
		/* No previous reading */
		rack->r_ctl.rc_rtt_diff = new_rtt_diff;
	} else {
		if (rack->measure_saw_probe_rtt == 0) {
			/*
			 * We don't want a probertt to be counted
			 * since it will be negative incorrectly. We
			 * expect to be reducing the RTT when we
			 * pace at a slower rate.
			 */
			rack->r_ctl.rc_rtt_diff -= (rack->r_ctl.rc_rtt_diff / 8);
			rack->r_ctl.rc_rtt_diff += (new_rtt_diff / 8);
		}
	}
	timely_says = rack_make_timely_judgement(rack,
		rack->r_ctl.rc_gp_srtt,
		rack->r_ctl.rc_rtt_diff,
	        rack->r_ctl.rc_prev_gp_srtt
		);
	bytes_ps *= HPTS_USEC_IN_SEC;
	bytes_ps /= utim;
	if (bytes_ps > rack->r_ctl.last_max_bw) {
		/*
		 * Something is on path playing
		 * since this b/w is not possible based
		 * on our BDP (highest rwnd and lowest rtt
		 * we saw in the measurement window).
		 *
		 * Another option here would be to
		 * instead skip the measurement.
		 */
		rack_log_pacing_delay_calc(rack, bytes, reqbytes,
					   bytes_ps, rack->r_ctl.last_max_bw, 0,
					   11, __LINE__, NULL);
		bytes_ps = rack->r_ctl.last_max_bw;
	}
	/* We store gp for b/w in bytes per second  */
	if (rack->rc_gp_filled == 0) {
		/* Initial measurment */
		if (bytes_ps) {
			rack->r_ctl.gp_bw = bytes_ps;
			rack->rc_gp_filled = 1;
			rack->r_ctl.num_avg = 1;
			rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
		} else {
			rack_log_pacing_delay_calc(rack, bytes_ps, reqbytes,
						   rack->r_ctl.rc_app_limited_cnt,
						   0, 0, 10, __LINE__, NULL);
		}
		if (rack->rc_inp->inp_in_hpts &&
		    (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {
			/*
			 * Ok we can't trust the pacer in this case
			 * where we transition from un-paced to paced.
			 * Or for that matter when the burst mitigation
			 * was making a wild guess and got it wrong.
			 * Stop the pacer and clear up all the aggregate
			 * delays etc.
			 */
			tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
			rack->r_ctl.rc_hpts_flags = 0;
			rack->r_ctl.rc_last_output_to = 0;
		}
	} else if (rack->r_ctl.num_avg < RACK_REQ_AVG) {
		/* Still a small number run an average */
		rack->r_ctl.gp_bw += bytes_ps;
		rack->r_ctl.num_avg++;
		if (rack->r_ctl.num_avg >= RACK_REQ_AVG) {
			/* We have collected enought to move forward */
			rack->r_ctl.gp_bw /= (uint64_t)rack->r_ctl.num_avg;
		}
	} else {
		/*
		 * We want to take 1/wma of the goodput and add in to 7/8th
		 * of the old value weighted by the srtt. So if your measurement
		 * period is say 2 SRTT's long you would get 1/4 as the
		 * value, if it was like 1/2 SRTT then you would get 1/16th.
		 *
		 * But we must be careful not to take too much i.e. if the
		 * srtt is say 20ms and the measurement is taken over
		 * 400ms our weight would be 400/20 i.e. 20. On the
		 * other hand if we get a measurement over 1ms with a
		 * 10ms rtt we only want to take a much smaller portion.
		 */
		uint64_t  resid_bw, subpart, addpart, srtt;

		srtt = ((uint64_t)TICKS_2_USEC(tp->t_srtt) >> TCP_RTT_SHIFT);
		if (srtt == 0) {
			/*
			 * Strange why did t_srtt go back to zero?
			 */
			if (rack->r_ctl.rc_rack_min_rtt)
				srtt = (rack->r_ctl.rc_rack_min_rtt * HPTS_USEC_IN_MSEC);
			else
				srtt = HPTS_USEC_IN_MSEC;
		}
		/*
		 * XXXrrs: Note for reviewers, in playing with
		 * dynamic pacing I discovered this GP calculation
		 * as done originally leads to some undesired results.
		 * Basically you can get longer measurements contributing
		 * too much to the WMA. Thus I changed it if you are doing
		 * dynamic adjustments to only do the aportioned adjustment
		 * if we have a very small (time wise) measurement. Longer
		 * measurements just get there weight (defaulting to 1/8)
		 * add to the WMA. We may want to think about changing
		 * this to always do that for both sides i.e. dynamic
		 * and non-dynamic... but considering lots of folks
		 * were playing with this I did not want to change the
		 * calculation per.se. without your thoughts.. Lawerence?
		 * Peter??
		 */
		if (rack->rc_gp_dyn_mul == 0) {
			subpart = rack->r_ctl.gp_bw * utim;
			subpart /= (srtt * 8);
			if (subpart < (rack->r_ctl.gp_bw / 2)) {
				/*
				 * The b/w update takes no more
				 * away then 1/2 our running total
				 * so factor it in.
				 */
				addpart = bytes_ps * utim;
				addpart /= (srtt * 8);
			} else {
				/*
				 * Don't allow a single measurement
				 * to account for more than 1/2 of the
				 * WMA. This could happen on a retransmission
				 * where utim becomes huge compared to
				 * srtt (multiple retransmissions when using
				 * the sending rate which factors in all the
				 * transmissions from the first one).
				 */
				subpart = rack->r_ctl.gp_bw / 2;
				addpart = bytes_ps / 2;
			}
			resid_bw = rack->r_ctl.gp_bw - subpart;
			rack->r_ctl.gp_bw = resid_bw + addpart;
		} else {
			if ((utim / srtt) <= 1) {
				/*
				 * The b/w update was over a small period
				 * of time. The idea here is to prevent a small
				 * measurement time period from counting
				 * too much. So we scale it based on the
				 * time so it attributes less than 1/rack_wma_divisor
				 * of its measurement.
				 */
				subpart = rack->r_ctl.gp_bw * utim;
				subpart /= (srtt * rack_wma_divisor);
				addpart = bytes_ps * utim;
				addpart /= (srtt * rack_wma_divisor);
			} else {
				/*
				 * The scaled measurement was long
				 * enough so lets just add in the
				 * portion of the measurment i.e. 1/rack_wma_divisor
				 */
				subpart = rack->r_ctl.gp_bw / rack_wma_divisor;
				addpart = bytes_ps / rack_wma_divisor;
			}
			if ((rack->measure_saw_probe_rtt == 0) ||
		            (bytes_ps > rack->r_ctl.gp_bw)) {
				/*
				 * For probe-rtt we only add it in
				 * if its larger, all others we just
				 * add in.
				 */
				resid_bw = rack->r_ctl.gp_bw - subpart;
				rack->r_ctl.gp_bw = resid_bw + addpart;
			}
		}
	}
	/* We do not update any multipliers if we are in or have seen a probe-rtt */
	if ((rack->measure_saw_probe_rtt == 0) && rack->rc_gp_rtt_set)
		rack_update_multiplier(rack, timely_says, bytes_ps,
				       rack->r_ctl.rc_gp_srtt,
				       rack->r_ctl.rc_rtt_diff);
	rack_log_pacing_delay_calc(rack, bytes, tim, bytes_ps, stim,
				   rack_get_bw(rack), 3, line, NULL);
	/* reset the gp srtt and setup the new prev */
	rack->r_ctl.rc_prev_gp_srtt = rack->r_ctl.rc_gp_srtt;
	/* Record the lost count for the next measurement */
	rack->r_ctl.rc_loss_at_start = rack->r_ctl.rc_loss_count;
	/*
	 * We restart our diffs based on the gpsrtt in the
	 * measurement window.
	 */
	rack->rc_gp_rtt_set = 0;
	rack->rc_gp_saw_rec = 0;
	rack->rc_gp_saw_ca = 0;
	rack->rc_gp_saw_ss = 0;
	rack->rc_dragged_bottom = 0;
skip_measurement:

#ifdef STATS
	stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_GPUT,
				 gput);
	/*
	 * XXXLAS: This is a temporary hack, and should be
	 * chained off VOI_TCP_GPUT when stats(9) grows an
	 * API to deal with chained VOIs.
	 */
	if (tp->t_stats_gput_prev > 0)
		stats_voi_update_abs_s32(tp->t_stats,
					 VOI_TCP_GPUT_ND,
					 ((gput - tp->t_stats_gput_prev) * 100) /
					 tp->t_stats_gput_prev);
#endif
	tp->t_flags &= ~TF_GPUTINPROG;
	tp->t_stats_gput_prev = gput;
	/*
	 * Now are we app limited now and there is space from where we
	 * were to where we want to go?
	 *
	 * We don't do the other case i.e. non-applimited here since
	 * the next send will trigger us picking up the missing data.
	 */
	if (rack->r_ctl.rc_first_appl &&
	    TCPS_HAVEESTABLISHED(tp->t_state) &&
	    rack->r_ctl.rc_app_limited_cnt &&
	    (SEQ_GT(rack->r_ctl.rc_first_appl->r_start, th_ack)) &&
	    ((rack->r_ctl.rc_first_appl->r_start - th_ack) >
	     max(rc_init_window(rack), (MIN_GP_WIN * segsiz)))) {
		/*
		 * Yep there is enough outstanding to make a measurement here.
		 */
		struct rack_sendmap *rsm, fe;

		tp->t_flags |= TF_GPUTINPROG;
		rack->r_ctl.rc_gp_lowrtt = 0xffffffff;
		rack->r_ctl.rc_gp_high_rwnd = rack->rc_tp->snd_wnd;
		tp->gput_ts = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
		rack->app_limited_needs_set = 0;
		tp->gput_seq = th_ack;
		if (rack->in_probe_rtt)
			rack->measure_saw_probe_rtt = 1;
		else if ((rack->measure_saw_probe_rtt) &&
			 (SEQ_GEQ(tp->gput_seq, rack->r_ctl.rc_probertt_sndmax_atexit)))
			rack->measure_saw_probe_rtt = 0;
		if ((rack->r_ctl.rc_first_appl->r_start - th_ack) >= rack_get_measure_window(tp, rack)) {
			/* There is a full window to gain info from */
			tp->gput_ack = tp->gput_seq + rack_get_measure_window(tp, rack);
		} else {
			/* We can only measure up to the applimited point */
			tp->gput_ack = tp->gput_seq + (rack->r_ctl.rc_first_appl->r_start - th_ack);
		}
		/*
		 * Now we need to find the timestamp of the send at tp->gput_seq
		 * for the send based measurement.
		 */
		fe.r_start = tp->gput_seq;
		rsm = RB_FIND(rack_rb_tree_head, &rack->r_ctl.rc_mtree, &fe);
		if (rsm) {
			/* Ok send-based limit is set */
			if (SEQ_LT(rsm->r_start, tp->gput_seq)) {
				/*
				 * Move back to include the earlier part
				 * so our ack time lines up right (this may
				 * make an overlapping measurement but thats
				 * ok).
				 */
				tp->gput_seq = rsm->r_start;
			}
			if (rsm->r_flags & RACK_ACKED)
				tp->gput_ts = rsm->r_ack_arrival;
			else
				rack->app_limited_needs_set = 1;
			rack->r_ctl.rc_gp_output_ts = rsm->usec_orig_send;
		} else {
			/*
			 * If we don't find the rsm due to some
			 * send-limit set the current time, which
			 * basically disables the send-limit.
			 */
			rack->r_ctl.rc_gp_output_ts = tcp_get_usecs(NULL);
		}
		rack_log_pacing_delay_calc(rack,
					   tp->gput_seq,
					   tp->gput_ack,
					   (uint64_t)rsm,
					   tp->gput_ts,
					   rack->r_ctl.rc_app_limited_cnt,
					   9,
					   __LINE__, NULL);
	}
}

/*
 * CC wrapper hook functions
 */
static void
rack_ack_received(struct tcpcb *tp, struct tcp_rack *rack, struct tcphdr *th, uint16_t nsegs,
    uint16_t type, int32_t recovery)
{
	INP_WLOCK_ASSERT(tp->t_inpcb);
	tp->ccv->nsegs = nsegs;
	tp->ccv->bytes_this_ack = BYTES_THIS_ACK(tp, th);
	if ((recovery) && (rack->r_ctl.rc_early_recovery_segs)) {
		uint32_t max;

		max = rack->r_ctl.rc_early_recovery_segs * ctf_fixed_maxseg(tp);
		if (tp->ccv->bytes_this_ack > max) {
			tp->ccv->bytes_this_ack = max;
		}
	}
	if (rack->r_ctl.cwnd_to_use <= tp->snd_wnd)
		tp->ccv->flags |= CCF_CWND_LIMITED;
	else
		tp->ccv->flags &= ~CCF_CWND_LIMITED;
#ifdef STATS
	stats_voi_update_abs_s32(tp->t_stats, VOI_TCP_CALCFRWINDIFF,
	    ((int32_t)rack->r_ctl.cwnd_to_use) - tp->snd_wnd);
#endif
	if ((tp->t_flags & TF_GPUTINPROG) &&
	    rack_enough_for_measurement(tp, rack, th->th_ack)) {
		/* Measure the Goodput */
		rack_do_goodput_measurement(tp, rack, th->th_ack, __LINE__);
#ifdef NETFLIX_PEAKRATE
		if ((type == CC_ACK) &&
		    (tp->t_maxpeakrate)) {
			/*
			 * We update t_peakrate_thr. This gives us roughly
			 * one update per round trip time. Note
			 * it will only be used if pace_always is off i.e
			 * we don't do this for paced flows.
			 */
			tcp_update_peakrate_thr(tp);
		}
#endif
	}
	if (rack->r_ctl.cwnd_to_use > tp->snd_ssthresh) {
		tp->t_bytes_acked += min(tp->ccv->bytes_this_ack,
			 nsegs * V_tcp_abc_l_var * ctf_fixed_maxseg(tp));
		if (tp->t_bytes_acked >= rack->r_ctl.cwnd_to_use) {
			tp->t_bytes_acked -= rack->r_ctl.cwnd_to_use;
			tp->ccv->flags |= CCF_ABC_SENTAWND;
		}
	} else {
		tp->ccv->flags &= ~CCF_ABC_SENTAWND;
		tp->t_bytes_acked = 0;
	}
	if (CC_ALGO(tp)->ack_received != NULL) {
		/* XXXLAS: Find a way to live without this */
		tp->ccv->curack = th->th_ack;
		CC_ALGO(tp)->ack_received(tp->ccv, type);
	}
#ifdef STATS
	stats_voi_update_abs_ulong(tp->t_stats, VOI_TCP_LCWIN, rack->r_ctl.cwnd_to_use);
#endif
	if (rack->r_ctl.rc_rack_largest_cwnd < rack->r_ctl.cwnd_to_use) {
		rack->r_ctl.rc_rack_largest_cwnd = rack->r_ctl.cwnd_to_use;
	}
#ifdef NETFLIX_PEAKRATE
	/* we enforce max peak rate if it is set and we are not pacing */
	if ((rack->rc_always_pace == 0) &&
	    tp->t_peakrate_thr &&
	    (tp->snd_cwnd > tp->t_peakrate_thr)) {
		tp->snd_cwnd = tp->t_peakrate_thr;
	}
#endif
}

static void
tcp_rack_partialack(struct tcpcb *tp, struct tcphdr *th)
{
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	INP_WLOCK_ASSERT(tp->t_inpcb);
	/*
	 * If we are doing PRR and have enough
	 * room to send <or> we are pacing and prr
	 * is disabled we will want to see if we
	 * can send data (by setting r_wanted_output to
	 * true).
	 */
	if ((rack->r_ctl.rc_prr_sndcnt > 0) ||
	    rack->rack_no_prr)
		rack->r_wanted_output = 1;
}

static void
rack_post_recovery(struct tcpcb *tp, struct tcphdr *th)
{
	struct tcp_rack *rack;
	uint32_t orig_cwnd;


	orig_cwnd = tp->snd_cwnd;
	INP_WLOCK_ASSERT(tp->t_inpcb);
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack->rc_not_backing_off == 0) {
		/* only alert CC if we alerted when we entered */
		if (CC_ALGO(tp)->post_recovery != NULL) {
			tp->ccv->curack = th->th_ack;
			CC_ALGO(tp)->post_recovery(tp->ccv);
		}
		if (tp->snd_cwnd > tp->snd_ssthresh) {
			/* Drop us down to the ssthresh (1/2 cwnd at loss) */
			tp->snd_cwnd = tp->snd_ssthresh;
		}
	}
	if ((rack->rack_no_prr == 0) &&
	    (rack->r_ctl.rc_prr_sndcnt > 0)) {
		/* Suck the next prr cnt back into cwnd */
		tp->snd_cwnd += rack->r_ctl.rc_prr_sndcnt;
		rack->r_ctl.rc_prr_sndcnt = 0;
		rack_log_to_prr(rack, 1, 0);
	}
	rack_log_to_prr(rack, 14, orig_cwnd);
	tp->snd_recover = tp->snd_una;
	EXIT_RECOVERY(tp->t_flags);
}

static void
rack_cong_signal(struct tcpcb *tp, struct tcphdr *th, uint32_t type)
{
	struct tcp_rack *rack;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	switch (type) {
	case CC_NDUPACK:
		tp->t_flags &= ~TF_WASFRECOVERY;
		tp->t_flags &= ~TF_WASCRECOVERY;
		if (!IN_FASTRECOVERY(tp->t_flags)) {
			rack->r_ctl.rc_prr_delivered = 0;
			rack->r_ctl.rc_prr_out = 0;
			if (rack->rack_no_prr == 0) {
				rack->r_ctl.rc_prr_sndcnt = ctf_fixed_maxseg(tp);
				rack_log_to_prr(rack, 2, 0);
			}
			rack->r_ctl.rc_prr_recovery_fs = tp->snd_max - tp->snd_una;
			tp->snd_recover = tp->snd_max;
			if (tp->t_flags2 & TF2_ECN_PERMIT)
				tp->t_flags2 |= TF2_ECN_SND_CWR;
		}
		break;
	case CC_ECN:
		if (!IN_CONGRECOVERY(tp->t_flags) ||
		    /*
		     * Allow ECN reaction on ACK to CWR, if
		     * that data segment was also CE marked.
		     */
		    SEQ_GEQ(th->th_ack, tp->snd_recover)) {
			EXIT_CONGRECOVERY(tp->t_flags);
			KMOD_TCPSTAT_INC(tcps_ecn_rcwnd);
			tp->snd_recover = tp->snd_max + 1;
			if (tp->t_flags2 & TF2_ECN_PERMIT)
				tp->t_flags2 |= TF2_ECN_SND_CWR;
		}
		break;
	case CC_RTO:
		tp->t_dupacks = 0;
		tp->t_bytes_acked = 0;
		EXIT_RECOVERY(tp->t_flags);
		tp->snd_ssthresh = max(2, min(tp->snd_wnd, rack->r_ctl.cwnd_to_use) / 2 /
		    ctf_fixed_maxseg(tp)) * ctf_fixed_maxseg(tp);
		tp->snd_cwnd = ctf_fixed_maxseg(tp);
		if (tp->t_flags2 & TF2_ECN_PERMIT)
			tp->t_flags2 |= TF2_ECN_SND_CWR;
		break;
	case CC_RTO_ERR:
		KMOD_TCPSTAT_INC(tcps_sndrexmitbad);
		/* RTO was unnecessary, so reset everything. */
		tp->snd_cwnd = tp->snd_cwnd_prev;
		tp->snd_ssthresh = tp->snd_ssthresh_prev;
		tp->snd_recover = tp->snd_recover_prev;
		if (tp->t_flags & TF_WASFRECOVERY) {
			ENTER_FASTRECOVERY(tp->t_flags);
			tp->t_flags &= ~TF_WASFRECOVERY;
		}
		if (tp->t_flags & TF_WASCRECOVERY) {
			ENTER_CONGRECOVERY(tp->t_flags);
			tp->t_flags &= ~TF_WASCRECOVERY;
		}
		tp->snd_nxt = tp->snd_max;
		tp->t_badrxtwin = 0;
		break;
	}
	/*
	 * If we are below our max rtt, don't
	 * signal the CC control to change things.
	 * instead set it up so that we are in
	 * recovery but not going to back off.
	 */

	if (rack->rc_highly_buffered) {
		/*
		 * Do we use the higher rtt for
		 * our threshold to not backoff (like CDG)?
		 */
		uint32_t rtt_mul, rtt_div;

		if (rack_use_max_for_nobackoff) {
			rtt_mul = (rack_gp_rtt_maxmul - 1);
			rtt_div = 1;
		} else {
			rtt_mul = rack_gp_rtt_minmul;
			rtt_div = max(rack_gp_rtt_mindiv , 1);
		}
		if (rack->r_ctl.rc_gp_srtt <= (rack->r_ctl.rc_lowest_us_rtt +
					       ((rack->r_ctl.rc_lowest_us_rtt * rtt_mul) /
						rtt_div))) {
			/* below our min threshold */
			rack->rc_not_backing_off = 1;
			ENTER_RECOVERY(rack->rc_tp->t_flags);
			rack_log_rtt_shrinks(rack, 0,
					     rtt_mul,
					     rtt_div,
					     RACK_RTTS_NOBACKOFF);
			return;
		}
	}
	rack->rc_not_backing_off = 0;
	if (CC_ALGO(tp)->cong_signal != NULL) {
		if (th != NULL)
			tp->ccv->curack = th->th_ack;
		CC_ALGO(tp)->cong_signal(tp->ccv, type);
	}
}



static inline void
rack_cc_after_idle(struct tcp_rack *rack, struct tcpcb *tp)
{
	uint32_t i_cwnd;

	INP_WLOCK_ASSERT(tp->t_inpcb);

#ifdef NETFLIX_STATS
	KMOD_TCPSTAT_INC(tcps_idle_restarts);
	if (tp->t_state == TCPS_ESTABLISHED)
		KMOD_TCPSTAT_INC(tcps_idle_estrestarts);
#endif
	if (CC_ALGO(tp)->after_idle != NULL)
		CC_ALGO(tp)->after_idle(tp->ccv);

	if (tp->snd_cwnd == 1)
		i_cwnd = tp->t_maxseg;		/* SYN(-ACK) lost */
	else
		i_cwnd = rc_init_window(rack);

	/*
	 * Being idle is no differnt than the initial window. If the cc
	 * clamps it down below the initial window raise it to the initial
	 * window.
	 */
	if (tp->snd_cwnd < i_cwnd) {
		tp->snd_cwnd = i_cwnd;
	}
}


/*
 * Indicate whether this ack should be delayed.  We can delay the ack if
 * following conditions are met:
 *	- There is no delayed ack timer in progress.
 *	- Our last ack wasn't a 0-sized window. We never want to delay
 *	  the ack that opens up a 0-sized window.
 *	- LRO wasn't used for this segment. We make sure by checking that the
 *	  segment size is not larger than the MSS.
 *	- Delayed acks are enabled or this is a half-synchronized T/TCP
 *	  connection.
 */
#define DELAY_ACK(tp, tlen)			 \
	(((tp->t_flags & TF_RXWIN0SENT) == 0) && \
	((tp->t_flags & TF_DELACK) == 0) && 	 \
	(tlen <= tp->t_maxseg) &&		 \
	(tp->t_delayed_ack || (tp->t_flags & TF_NEEDSYN)))

static struct rack_sendmap *
rack_find_lowest_rsm(struct tcp_rack *rack)
{
	struct rack_sendmap *rsm;

	/*
	 * Walk the time-order transmitted list looking for an rsm that is
	 * not acked. This will be the one that was sent the longest time
	 * ago that is still outstanding.
	 */
	TAILQ_FOREACH(rsm, &rack->r_ctl.rc_tmap, r_tnext) {
		if (rsm->r_flags & RACK_ACKED) {
			continue;
		}
		goto finish;
	}
finish:
	return (rsm);
}

static struct rack_sendmap *
rack_find_high_nonack(struct tcp_rack *rack, struct rack_sendmap *rsm)
{
	struct rack_sendmap *prsm;

	/*
	 * Walk the sequence order list backward until we hit and arrive at
	 * the highest seq not acked. In theory when this is called it
	 * should be the last segment (which it was not).
	 */
	counter_u64_add(rack_find_high, 1);
	prsm = rsm;
	RB_FOREACH_REVERSE_FROM(prsm, rack_rb_tree_head, rsm) {
		if (prsm->r_flags & (RACK_ACKED | RACK_HAS_FIN)) {
			continue;
		}
		return (prsm);
	}
	return (NULL);
}


static uint32_t
rack_calc_thresh_rack(struct tcp_rack *rack, uint32_t srtt, uint32_t cts)
{
	int32_t lro;
	uint32_t thresh;

	/*
	 * lro is the flag we use to determine if we have seen reordering.
	 * If it gets set we have seen reordering. The reorder logic either
	 * works in one of two ways:
	 *
	 * If reorder-fade is configured, then we track the last time we saw
	 * re-ordering occur. If we reach the point where enough time as
	 * passed we no longer consider reordering has occuring.
	 *
	 * Or if reorder-face is 0, then once we see reordering we consider
	 * the connection to alway be subject to reordering and just set lro
	 * to 1.
	 *
	 * In the end if lro is non-zero we add the extra time for
	 * reordering in.
	 */
	if (srtt == 0)
		srtt = 1;
	if (rack->r_ctl.rc_reorder_ts) {
		if (rack->r_ctl.rc_reorder_fade) {
			if (SEQ_GEQ(cts, rack->r_ctl.rc_reorder_ts)) {
				lro = cts - rack->r_ctl.rc_reorder_ts;
				if (lro == 0) {
					/*
					 * No time as passed since the last
					 * reorder, mark it as reordering.
					 */
					lro = 1;
				}
			} else {
				/* Negative time? */
				lro = 0;
			}
			if (lro > rack->r_ctl.rc_reorder_fade) {
				/* Turn off reordering seen too */
				rack->r_ctl.rc_reorder_ts = 0;
				lro = 0;
			}
		} else {
			/* Reodering does not fade */
			lro = 1;
		}
	} else {
		lro = 0;
	}
	thresh = srtt + rack->r_ctl.rc_pkt_delay;
	if (lro) {
		/* It must be set, if not you get 1/4 rtt */
		if (rack->r_ctl.rc_reorder_shift)
			thresh += (srtt >> rack->r_ctl.rc_reorder_shift);
		else
			thresh += (srtt >> 2);
	} else {
		thresh += 1;
	}
	/* We don't let the rack timeout be above a RTO */
	if (thresh > TICKS_2_MSEC(rack->rc_tp->t_rxtcur)) {
		thresh = TICKS_2_MSEC(rack->rc_tp->t_rxtcur);
	}
	/* And we don't want it above the RTO max either */
	if (thresh > rack_rto_max) {
		thresh = rack_rto_max;
	}
	return (thresh);
}

static uint32_t
rack_calc_thresh_tlp(struct tcpcb *tp, struct tcp_rack *rack,
		     struct rack_sendmap *rsm, uint32_t srtt)
{
	struct rack_sendmap *prsm;
	uint32_t thresh, len;
	int segsiz;

	if (srtt == 0)
		srtt = 1;
	if (rack->r_ctl.rc_tlp_threshold)
		thresh = srtt + (srtt / rack->r_ctl.rc_tlp_threshold);
	else
		thresh = (srtt * 2);

	/* Get the previous sent packet, if any  */
	segsiz = min(ctf_fixed_maxseg(tp), rack->r_ctl.rc_pace_min_segs);
	counter_u64_add(rack_enter_tlp_calc, 1);
	len = rsm->r_end - rsm->r_start;
	if (rack->rack_tlp_threshold_use == TLP_USE_ID) {
		/* Exactly like the ID */
		if (((tp->snd_max - tp->snd_una) - rack->r_ctl.rc_sacked + rack->r_ctl.rc_holes_rxt) <= segsiz) {
			uint32_t alt_thresh;
			/*
			 * Compensate for delayed-ack with the d-ack time.
			 */
			counter_u64_add(rack_used_tlpmethod, 1);
			alt_thresh = srtt + (srtt / 2) + rack_delayed_ack_time;
			if (alt_thresh > thresh)
				thresh = alt_thresh;
		}
	} else if (rack->rack_tlp_threshold_use == TLP_USE_TWO_ONE) {
		/* 2.1 behavior */
		prsm = TAILQ_PREV(rsm, rack_head, r_tnext);
		if (prsm && (len <= segsiz)) {
			/*
			 * Two packets outstanding, thresh should be (2*srtt) +
			 * possible inter-packet delay (if any).
			 */
			uint32_t inter_gap = 0;
			int idx, nidx;

			counter_u64_add(rack_used_tlpmethod, 1);
			idx = rsm->r_rtr_cnt - 1;
			nidx = prsm->r_rtr_cnt - 1;
			if (TSTMP_GEQ(rsm->r_tim_lastsent[nidx], prsm->r_tim_lastsent[idx])) {
				/* Yes it was sent later (or at the same time) */
				inter_gap = rsm->r_tim_lastsent[idx] - prsm->r_tim_lastsent[nidx];
			}
			thresh += inter_gap;
		} else 	if (len <= segsiz) {
			/*
			 * Possibly compensate for delayed-ack.
			 */
			uint32_t alt_thresh;

			counter_u64_add(rack_used_tlpmethod2, 1);
			alt_thresh = srtt + (srtt / 2) + rack_delayed_ack_time;
			if (alt_thresh > thresh)
				thresh = alt_thresh;
		}
	} else if (rack->rack_tlp_threshold_use == TLP_USE_TWO_TWO) {
		/* 2.2 behavior */
		if (len <= segsiz) {
			uint32_t alt_thresh;
			/*
			 * Compensate for delayed-ack with the d-ack time.
			 */
			counter_u64_add(rack_used_tlpmethod, 1);
			alt_thresh = srtt + (srtt / 2) + rack_delayed_ack_time;
			if (alt_thresh > thresh)
				thresh = alt_thresh;
		}
	}
 	/* Not above an RTO */
	if (thresh > TICKS_2_MSEC(tp->t_rxtcur)) {
		thresh = TICKS_2_MSEC(tp->t_rxtcur);
	}
	/* Not above a RTO max */
	if (thresh > rack_rto_max) {
		thresh = rack_rto_max;
	}
	/* Apply user supplied min TLP */
	if (thresh < rack_tlp_min) {
		thresh = rack_tlp_min;
	}
	return (thresh);
}

static uint32_t
rack_grab_rtt(struct tcpcb *tp, struct tcp_rack *rack)
{
	/*
	 * We want the rack_rtt which is the
	 * last rtt we measured. However if that
	 * does not exist we fallback to the srtt (which
	 * we probably will never do) and then as a last
	 * resort we use RACK_INITIAL_RTO if no srtt is
	 * yet set.
	 */
	if (rack->rc_rack_rtt)
		return(rack->rc_rack_rtt);
	else if (tp->t_srtt == 0)
		return(RACK_INITIAL_RTO);
	return (TICKS_2_MSEC(tp->t_srtt >> TCP_RTT_SHIFT));
}

static struct rack_sendmap *
rack_check_recovery_mode(struct tcpcb *tp, uint32_t tsused)
{
	/*
	 * Check to see that we don't need to fall into recovery. We will
	 * need to do so if our oldest transmit is past the time we should
	 * have had an ack.
	 */
	struct tcp_rack *rack;
	struct rack_sendmap *rsm;
	int32_t idx;
	uint32_t srtt, thresh;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (RB_EMPTY(&rack->r_ctl.rc_mtree)) {
		return (NULL);
	}
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm == NULL)
		return (NULL);

	if (rsm->r_flags & RACK_ACKED) {
		rsm = rack_find_lowest_rsm(rack);
		if (rsm == NULL)
			return (NULL);
	}
	idx = rsm->r_rtr_cnt - 1;
	srtt = rack_grab_rtt(tp, rack);
	thresh = rack_calc_thresh_rack(rack, srtt, tsused);
	if (TSTMP_LT(tsused, rsm->r_tim_lastsent[idx])) {
		return (NULL);
	}
	if ((tsused - rsm->r_tim_lastsent[idx]) < thresh) {
		return (NULL);
	}
	/* Ok if we reach here we are over-due and this guy can be sent */
	if (IN_RECOVERY(tp->t_flags) == 0) {
		/*
		 * For the one that enters us into recovery record undo
		 * info.
		 */
		rack->r_ctl.rc_rsm_start = rsm->r_start;
		rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
		rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
	}
	rack_cong_signal(tp, NULL, CC_NDUPACK);
	return (rsm);
}

static uint32_t
rack_get_persists_timer_val(struct tcpcb *tp, struct tcp_rack *rack)
{
	int32_t t;
	int32_t tt;
	uint32_t ret_val;

	t = TICKS_2_MSEC((tp->t_srtt >> TCP_RTT_SHIFT) + ((tp->t_rttvar * 4) >> TCP_RTT_SHIFT));
	TCPT_RANGESET(tt, t * tcp_backoff[tp->t_rxtshift],
	    rack_persist_min, rack_persist_max);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	rack->r_ctl.rc_hpts_flags |= PACE_TMR_PERSIT;
	ret_val = (uint32_t)tt;
	return (ret_val);
}

static uint32_t
rack_timer_start(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, int sup_rack)
{
	/*
	 * Start the FR timer, we do this based on getting the first one in
	 * the rc_tmap. Note that if its NULL we must stop the timer. in all
	 * events we need to stop the running timer (if its running) before
	 * starting the new one.
	 */
	uint32_t thresh, exp, to, srtt, time_since_sent, tstmp_touse;
	uint32_t srtt_cur;
	int32_t idx;
	int32_t is_tlp_timer = 0;
	struct rack_sendmap *rsm;

	if (rack->t_timers_stopped) {
		/* All timers have been stopped none are to run */
		return (0);
	}
	if (rack->rc_in_persist) {
		/* We can't start any timer in persists */
		return (rack_get_persists_timer_val(tp, rack));
	}
	rack->rc_on_min_to = 0;
	if ((tp->t_state < TCPS_ESTABLISHED) ||
	    ((tp->t_flags & TF_SACK_PERMIT) == 0))
		goto activate_rxt;
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if ((rsm == NULL) || sup_rack) {
		/* Nothing on the send map */
activate_rxt:
		time_since_sent = 0;
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
		if (rsm) {
			idx = rsm->r_rtr_cnt - 1;
			if (TSTMP_GEQ(rsm->r_tim_lastsent[idx], rack->r_ctl.rc_tlp_rxt_last_time))
				tstmp_touse = rsm->r_tim_lastsent[idx];
			else
				tstmp_touse = rack->r_ctl.rc_tlp_rxt_last_time;
			if (TSTMP_GT(cts, tstmp_touse))
			    time_since_sent = cts - tstmp_touse;
		}
		if (SEQ_LT(tp->snd_una, tp->snd_max) || sbavail(&(tp->t_inpcb->inp_socket->so_snd))) {
			rack->r_ctl.rc_hpts_flags |= PACE_TMR_RXT;
			to = TICKS_2_MSEC(tp->t_rxtcur);
			if (to > time_since_sent)
				to -= time_since_sent;
			else
				to = rack->r_ctl.rc_min_to;
			if (to == 0)
				to = 1;
			return (to);
		}
		return (0);
	}
	if (rsm->r_flags & RACK_ACKED) {
		rsm = rack_find_lowest_rsm(rack);
		if (rsm == NULL) {
			/* No lowest? */
			goto activate_rxt;
		}
	}
	if (rack->sack_attack_disable) {
		/*
		 * We don't want to do
		 * any TLP's if you are an attacker.
		 * Though if you are doing what
		 * is expected you may still have
		 * SACK-PASSED marks.
		 */
		goto activate_rxt;
	}
	/* Convert from ms to usecs */
	if (rsm->r_flags & RACK_SACK_PASSED) {
		if ((tp->t_flags & TF_SENTFIN) &&
		    ((tp->snd_max - tp->snd_una) == 1) &&
		    (rsm->r_flags & RACK_HAS_FIN)) {
			/*
			 * We don't start a rack timer if all we have is a
			 * FIN outstanding.
			 */
			goto activate_rxt;
		}
		if ((rack->use_rack_rr == 0) &&
		    (IN_RECOVERY(tp->t_flags)) &&
		    (rack->rack_no_prr == 0) &&
		     (rack->r_ctl.rc_prr_sndcnt  < ctf_fixed_maxseg(tp))) {
			/*
			 * We are not cheating, in recovery  and
			 * not enough ack's to yet get our next
			 * retransmission out.
			 *
			 * Note that classified attackers do not
			 * get to use the rack-cheat.
			 */
			goto activate_tlp;
		}
		srtt = rack_grab_rtt(tp, rack);
		thresh = rack_calc_thresh_rack(rack, srtt, cts);
		idx = rsm->r_rtr_cnt - 1;
		exp = rsm->r_tim_lastsent[idx] + thresh;
		if (SEQ_GEQ(exp, cts)) {
			to = exp - cts;
			if (to < rack->r_ctl.rc_min_to) {
				to = rack->r_ctl.rc_min_to;
				if (rack->r_rr_config == 3)
					rack->rc_on_min_to = 1;
			}
		} else {
			to = rack->r_ctl.rc_min_to;
			if (rack->r_rr_config == 3)
				rack->rc_on_min_to = 1;
		}
	} else {
		/* Ok we need to do a TLP not RACK */
activate_tlp:
		if ((rack->rc_tlp_in_progress != 0) &&
		    (rack->r_ctl.rc_tlp_cnt_out >= rack_tlp_limit)) {
			/*
			 * The previous send was a TLP and we have sent
			 * N TLP's without sending new data.
			 */
			goto activate_rxt;
		}
		rsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_tmap, rack_sendmap, r_tnext);
		if (rsm == NULL) {
			/* We found no rsm to TLP with. */
			goto activate_rxt;
		}
		if (rsm->r_flags & RACK_HAS_FIN) {
			/* If its a FIN we dont do TLP */
			rsm = NULL;
			goto activate_rxt;
		}
		idx = rsm->r_rtr_cnt - 1;
		time_since_sent = 0;
		if (TSTMP_GEQ(rsm->r_tim_lastsent[idx], rack->r_ctl.rc_tlp_rxt_last_time))
			tstmp_touse = rsm->r_tim_lastsent[idx];
		else
			tstmp_touse = rack->r_ctl.rc_tlp_rxt_last_time;
		if (TSTMP_GT(cts, tstmp_touse))
		    time_since_sent = cts - tstmp_touse;
		is_tlp_timer = 1;
		if (tp->t_srtt) {
			srtt_cur = (tp->t_srtt >> TCP_RTT_SHIFT);
			srtt = TICKS_2_MSEC(srtt_cur);
		} else
			srtt = RACK_INITIAL_RTO;
		/*
		 * If the SRTT is not keeping up and the
		 * rack RTT has spiked we want to use
		 * the last RTT not the smoothed one.
		 */
		if (rack_tlp_use_greater && (srtt < rack_grab_rtt(tp, rack)))
			srtt = rack_grab_rtt(tp, rack);
		thresh = rack_calc_thresh_tlp(tp, rack, rsm, srtt);
		if (thresh > time_since_sent)
			to = thresh - time_since_sent;
		else {
			to = rack->r_ctl.rc_min_to;
			rack_log_alt_to_to_cancel(rack,
						  thresh,		/* flex1 */
						  time_since_sent,	/* flex2 */
						  tstmp_touse,		/* flex3 */
						  rack->r_ctl.rc_tlp_rxt_last_time, /* flex4 */
						  rsm->r_tim_lastsent[idx],
						  srtt,
						  idx, 99);
		}
		if (to > TCPTV_REXMTMAX) {
			/*
			 * If the TLP time works out to larger than the max
			 * RTO lets not do TLP.. just RTO.
			 */
			goto activate_rxt;
		}
	}
	if (is_tlp_timer == 0) {
		rack->r_ctl.rc_hpts_flags |= PACE_TMR_RACK;
	} else {
		rack->r_ctl.rc_hpts_flags |= PACE_TMR_TLP;
	}
	if (to == 0)
		to = 1;
	return (to);
}

static void
rack_enter_persist(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	if (rack->rc_in_persist == 0) {
		if (tp->t_flags & TF_GPUTINPROG) {
			/*
			 * Stop the goodput now, the calling of the
			 * measurement function clears the flag.
			 */
			rack_do_goodput_measurement(tp, rack, tp->snd_una, __LINE__);
		}
#ifdef NETFLIX_SHARED_CWND
		if (rack->r_ctl.rc_scw) {
			tcp_shared_cwnd_idle(rack->r_ctl.rc_scw, rack->r_ctl.rc_scw_index);
			rack->rack_scwnd_is_idle = 1;
		}
#endif
		rack->r_ctl.rc_went_idle_time = tcp_get_usecs(NULL);
		if (rack->r_ctl.rc_went_idle_time == 0)
			rack->r_ctl.rc_went_idle_time = 1;
		rack_timer_cancel(tp, rack, cts, __LINE__);
		tp->t_rxtshift = 0;
		rack->rc_in_persist = 1;
	}
}

static void
rack_exit_persist(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	if (rack->rc_inp->inp_in_hpts)  {
		tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
		rack->r_ctl.rc_hpts_flags  = 0;
	}
#ifdef NETFLIX_SHARED_CWND
	if (rack->r_ctl.rc_scw) {
		tcp_shared_cwnd_active(rack->r_ctl.rc_scw, rack->r_ctl.rc_scw_index);
		rack->rack_scwnd_is_idle = 0;
	}
#endif
	if (rack->rc_gp_dyn_mul &&
	    (rack->use_fixed_rate == 0) &&
	    (rack->rc_always_pace)) {
		/*
		 * Do we count this as if a probe-rtt just
		 * finished?
		 */
		uint32_t time_idle, idle_min;

		time_idle = tcp_get_usecs(NULL) - rack->r_ctl.rc_went_idle_time;
		idle_min = rack_min_probertt_hold;
		if (rack_probertt_gpsrtt_cnt_div) {
			uint64_t extra;
			extra = (uint64_t)rack->r_ctl.rc_gp_srtt *
				(uint64_t)rack_probertt_gpsrtt_cnt_mul;
			extra /= (uint64_t)rack_probertt_gpsrtt_cnt_div;
			idle_min += (uint32_t)extra;
		}
		if (time_idle >= idle_min)  {
			/* Yes, we count it as a probe-rtt. */
			uint32_t us_cts;

			us_cts = tcp_get_usecs(NULL);
			if (rack->in_probe_rtt == 0) {
				rack->r_ctl.rc_lower_rtt_us_cts = us_cts;
				rack->r_ctl.rc_time_probertt_entered = rack->r_ctl.rc_lower_rtt_us_cts;
				rack->r_ctl.rc_time_probertt_starts = rack->r_ctl.rc_lower_rtt_us_cts;
				rack->r_ctl.rc_time_of_last_probertt = rack->r_ctl.rc_lower_rtt_us_cts;
			} else {
				rack_exit_probertt(rack, us_cts);
			}
		}

	}
	rack->rc_in_persist = 0;
	rack->r_ctl.rc_went_idle_time = 0;
	tp->t_rxtshift = 0;
 	rack->r_ctl.rc_agg_delayed = 0;
	rack->r_early = 0;
	rack->r_late = 0;
	rack->r_ctl.rc_agg_early = 0;
}

static void
rack_log_hpts_diag(struct tcp_rack *rack, uint32_t cts,
		   struct hpts_diag *diag, struct timeval *tv)
{
	if (rack_verbose_logging && rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = diag->p_nxt_slot;
		log.u_bbr.flex2 = diag->p_cur_slot;
		log.u_bbr.flex3 = diag->slot_req;
		log.u_bbr.flex4 = diag->inp_hptsslot;
		log.u_bbr.flex5 = diag->slot_remaining;
		log.u_bbr.flex6 = diag->need_new_to;
		log.u_bbr.flex7 = diag->p_hpts_active;
		log.u_bbr.flex8 = diag->p_on_min_sleep;
		/* Hijack other fields as needed  */
		log.u_bbr.epoch = diag->have_slept;
		log.u_bbr.lt_epoch = diag->yet_to_sleep;
		log.u_bbr.pkts_out = diag->co_ret;
		log.u_bbr.applimited = diag->hpts_sleep_time;
		log.u_bbr.delivered = diag->p_prev_slot;
		log.u_bbr.inflight = diag->p_runningtick;
		log.u_bbr.bw_inuse = diag->wheel_tick;
		log.u_bbr.rttProp = diag->wheel_cts;
		log.u_bbr.timeStamp = cts;
		log.u_bbr.delRate = diag->maxticks;
		log.u_bbr.cur_del_rate = diag->p_curtick;
		log.u_bbr.cur_del_rate <<= 32;
		log.u_bbr.cur_del_rate |= diag->p_lasttick;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_HPTSDIAG, 0,
		    0, &log, false, tv);
	}

}

static void
rack_start_hpts_timer(struct tcp_rack *rack, struct tcpcb *tp, uint32_t cts,
      int32_t slot, uint32_t tot_len_this_send, int sup_rack)
{
	struct hpts_diag diag;
	struct inpcb *inp;
	struct timeval tv;
	uint32_t delayed_ack = 0;
	uint32_t hpts_timeout;
	uint8_t stopped;
	uint32_t left = 0;
	uint32_t us_cts;

	inp = tp->t_inpcb;
	if ((tp->t_state == TCPS_CLOSED) ||
	    (tp->t_state == TCPS_LISTEN)) {
		return;
	}
	if (inp->inp_in_hpts) {
		/* Already on the pacer */
		return;
	}
	stopped = rack->rc_tmr_stopped;
	if (stopped && TSTMP_GT(rack->r_ctl.rc_timer_exp, cts)) {
		left = rack->r_ctl.rc_timer_exp - cts;
	}
	rack->r_ctl.rc_timer_exp = 0;
	rack->r_ctl.rc_hpts_flags = 0;
	us_cts = tcp_get_usecs(&tv);
	/* Now early/late accounting */
	if (rack->r_early) {
		/*
		 * We have a early carry over set,
		 * we can always add more time so we
		 * can always make this compensation.
		 */
		slot += rack->r_ctl.rc_agg_early;
		rack->r_early = 0;
		rack->r_ctl.rc_agg_early = 0;
	}
	if (rack->r_late) {
		/*
		 * This is harder, we can
		 * compensate some but it
		 * really depends on what
		 * the current pacing time is.
		 */
		if (rack->r_ctl.rc_agg_delayed >= slot) {
			/*
			 * We can't compensate for it all.
			 * And we have to have some time
			 * on the clock. We always have a min
			 * 10 slots (10 x 10 i.e. 100 usecs).
			 */
			if (slot <= HPTS_TICKS_PER_USEC) {
				/* We gain delay */
				rack->r_ctl.rc_agg_delayed += (HPTS_TICKS_PER_USEC - slot);
				slot = HPTS_TICKS_PER_USEC;
			} else {
				/* We take off some */
				rack->r_ctl.rc_agg_delayed -= (slot - HPTS_TICKS_PER_USEC);
				slot = HPTS_TICKS_PER_USEC;
			}
		} else {

			slot -= rack->r_ctl.rc_agg_delayed;
			rack->r_ctl.rc_agg_delayed = 0;
			/* Make sure we have 100 useconds at minimum */
			if (slot < HPTS_TICKS_PER_USEC) {
				rack->r_ctl.rc_agg_delayed = HPTS_TICKS_PER_USEC - slot;
				slot = HPTS_TICKS_PER_USEC;
			}
			if (rack->r_ctl.rc_agg_delayed == 0)
				rack->r_late = 0;
		}
	}
	if (slot) {
		/* We are pacing too */
		rack->r_ctl.rc_hpts_flags |= PACE_PKT_OUTPUT;
	}
	hpts_timeout = rack_timer_start(tp, rack, cts, sup_rack);
#ifdef NETFLIX_EXP_DETECTION
	if (rack->sack_attack_disable &&
	    (slot < tcp_sad_pacing_interval)) {
		/*
		 * We have a potential attacker on
		 * the line. We have possibly some
		 * (or now) pacing time set. We want to
		 * slow down the processing of sacks by some
		 * amount (if it is an attacker). Set the default
		 * slot for attackers in place (unless the orginal
		 * interval is longer). Its stored in
		 * micro-seconds, so lets convert to msecs.
		 */
		slot = tcp_sad_pacing_interval;
	}
#endif
	if (tp->t_flags & TF_DELACK) {
		delayed_ack = TICKS_2_MSEC(tcp_delacktime);
		rack->r_ctl.rc_hpts_flags |= PACE_TMR_DELACK;
	}
	if (delayed_ack && ((hpts_timeout == 0) ||
			    (delayed_ack < hpts_timeout)))
		hpts_timeout = delayed_ack;
	else
		rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_DELACK;
	/*
	 * If no timers are going to run and we will fall off the hptsi
	 * wheel, we resort to a keep-alive timer if its configured.
	 */
	if ((hpts_timeout == 0) &&
	    (slot == 0)) {
		if ((V_tcp_always_keepalive || inp->inp_socket->so_options & SO_KEEPALIVE) &&
		    (tp->t_state <= TCPS_CLOSING)) {
			/*
			 * Ok we have no timer (persists, rack, tlp, rxt  or
			 * del-ack), we don't have segments being paced. So
			 * all that is left is the keepalive timer.
			 */
			if (TCPS_HAVEESTABLISHED(tp->t_state)) {
				/* Get the established keep-alive time */
				hpts_timeout = TP_KEEPIDLE(tp);
			} else {
				/* Get the initial setup keep-alive time */
				hpts_timeout = TP_KEEPINIT(tp);
			}
			rack->r_ctl.rc_hpts_flags |= PACE_TMR_KEEP;
			if (rack->in_probe_rtt) {
				/*
				 * We want to instead not wake up a long time from
				 * now but to wake up about the time we would
				 * exit probe-rtt and initiate a keep-alive ack.
				 * This will get us out of probe-rtt and update
				 * our min-rtt.
				 */
				hpts_timeout = (rack_min_probertt_hold / HPTS_USEC_IN_MSEC);
			}
		}
	}
	if (left && (stopped & (PACE_TMR_KEEP | PACE_TMR_DELACK)) ==
	    (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK)) {
		/*
		 * RACK, TLP, persists and RXT timers all are restartable
		 * based on actions input .. i.e we received a packet (ack
		 * or sack) and that changes things (rw, or snd_una etc).
		 * Thus we can restart them with a new value. For
		 * keep-alive, delayed_ack we keep track of what was left
		 * and restart the timer with a smaller value.
		 */
		if (left < hpts_timeout)
			hpts_timeout = left;
	}
	if (hpts_timeout) {
		/*
		 * Hack alert for now we can't time-out over 2,147,483
		 * seconds (a bit more than 596 hours), which is probably ok
		 * :).
		 */
		if (hpts_timeout > 0x7ffffffe)
			hpts_timeout = 0x7ffffffe;
		rack->r_ctl.rc_timer_exp = cts + hpts_timeout;
	}
	if ((rack->rc_gp_filled == 0) &&
	    (hpts_timeout < slot) &&
	    (rack->r_ctl.rc_hpts_flags & (PACE_TMR_TLP|PACE_TMR_RXT))) {
		/*
		 * We have no good estimate yet for the
		 * old clunky burst mitigation or the
		 * real pacing. And the tlp or rxt is smaller
		 * than the pacing calculation. Lets not
		 * pace that long since we know the calculation
		 * so far is not accurate.
		 */
		slot = hpts_timeout;
	}
	rack->r_ctl.last_pacing_time = slot;
	if (slot) {
		rack->r_ctl.rc_last_output_to = us_cts + slot;
		if (rack->rc_always_pace || rack->r_mbuf_queue) {
			if ((rack->rc_gp_filled == 0) ||
			    rack->pacing_longer_than_rtt) {
				inp->inp_flags2 &= ~(INP_DONT_SACK_QUEUE|INP_MBUF_QUEUE_READY);
			} else {
				inp->inp_flags2 |= INP_MBUF_QUEUE_READY;
				if ((rack->r_ctl.rc_hpts_flags & PACE_TMR_RACK) &&
				    (rack->r_rr_config != 3))
					inp->inp_flags2 |= INP_DONT_SACK_QUEUE;
				else
					inp->inp_flags2 &= ~INP_DONT_SACK_QUEUE;
			}
		}
		if ((rack->use_rack_rr) &&
		    (rack->r_rr_config < 2) &&
		    ((hpts_timeout) && ((hpts_timeout * HPTS_USEC_IN_MSEC) < slot))) {
			/*
			 * Arrange for the hpts to kick back in after the
			 * t-o if the t-o does not cause a send.
			 */
			(void)tcp_hpts_insert_diag(tp->t_inpcb, HPTS_MS_TO_SLOTS(hpts_timeout),
						   __LINE__, &diag);
			rack_log_hpts_diag(rack, us_cts, &diag, &tv);
			rack_log_to_start(rack, cts, hpts_timeout, slot, 0);
		} else {
			(void)tcp_hpts_insert_diag(tp->t_inpcb, HPTS_USEC_TO_SLOTS(slot),
						   __LINE__, &diag);
			rack_log_hpts_diag(rack, us_cts, &diag, &tv);
			rack_log_to_start(rack, cts, hpts_timeout, slot, 1);
		}
	} else if (hpts_timeout) {
		if (rack->rc_always_pace || rack->r_mbuf_queue) {
			if (rack->r_ctl.rc_hpts_flags & PACE_TMR_RACK)  {
				/* For a rack timer, don't wake us */
				inp->inp_flags2 |= INP_MBUF_QUEUE_READY;
				if  (rack->r_rr_config != 3)
					inp->inp_flags2 |= INP_DONT_SACK_QUEUE;
				else
					inp->inp_flags2 &= ~INP_DONT_SACK_QUEUE;
			} else {
				/* All other timers wake us up */
				inp->inp_flags2 &= ~INP_MBUF_QUEUE_READY;
				inp->inp_flags2 &= ~INP_DONT_SACK_QUEUE;
			}
		}
		(void)tcp_hpts_insert_diag(tp->t_inpcb, HPTS_MS_TO_SLOTS(hpts_timeout),
					   __LINE__, &diag);
		rack_log_hpts_diag(rack, us_cts, &diag, &tv);
		rack_log_to_start(rack, cts, hpts_timeout, slot, 0);
	} else {
		/* No timer starting */
#ifdef INVARIANTS
		if (SEQ_GT(tp->snd_max, tp->snd_una)) {
			panic("tp:%p rack:%p tlts:%d cts:%u slot:%u pto:%u -- no timer started?",
			    tp, rack, tot_len_this_send, cts, slot, hpts_timeout);
		}
#endif
	}
	rack->rc_tmr_stopped = 0;
	if (slot)
		rack_log_type_bbrsnd(rack, tot_len_this_send, slot, us_cts, &tv);
}

/*
 * RACK Timer, here we simply do logging and house keeping.
 * the normal rack_output() function will call the
 * appropriate thing to check if we need to do a RACK retransmit.
 * We return 1, saying don't proceed with rack_output only
 * when all timers have been stopped (destroyed PCB?).
 */
static int
rack_timeout_rack(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	/*
	 * This timer simply provides an internal trigger to send out data.
	 * The check_recovery_mode call will see if there are needed
	 * retransmissions, if so we will enter fast-recovery. The output
	 * call may or may not do the same thing depending on sysctl
	 * settings.
	 */
	struct rack_sendmap *rsm;
	int32_t recovery;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	recovery = IN_RECOVERY(tp->t_flags);
	counter_u64_add(rack_to_tot, 1);
	if (rack->r_state && (rack->r_state != tp->t_state))
		rack_set_state(tp, rack);
	rack->rc_on_min_to = 0;
	rsm = rack_check_recovery_mode(tp, cts);
	rack_log_to_event(rack, RACK_TO_FRM_RACK, rsm);
	if (rsm) {
		uint32_t rtt;

		rack->r_ctl.rc_resend = rsm;
		if (rack->use_rack_rr) {
			/*
			 * Don't accumulate extra pacing delay
			 * we are allowing the rack timer to
			 * over-ride pacing i.e. rrr takes precedence
			 * if the pacing interval is longer than the rrr
			 * time (in other words we get the min pacing
			 * time versus rrr pacing time).
			 */
			rack->r_timer_override = 1;
			rack->r_ctl.rc_hpts_flags &= ~PACE_PKT_OUTPUT;
		}
		rtt = rack->rc_rack_rtt;
		if (rtt == 0)
			rtt = 1;
		if (rack->rack_no_prr == 0) {
			if ((recovery == 0) &&
			    (rack->r_ctl.rc_prr_sndcnt < ctf_fixed_maxseg(tp))) {
				/*
				 * The rack-timeout that enter's us into recovery
				 * will force out one MSS and set us up so that we
				 * can do one more send in 2*rtt (transitioning the
				 * rack timeout into a rack-tlp).
				 */
				rack->r_ctl.rc_prr_sndcnt = ctf_fixed_maxseg(tp);
				rack->r_timer_override = 1;
				rack_log_to_prr(rack, 3, 0);
			} else if ((rack->r_ctl.rc_prr_sndcnt < (rsm->r_end - rsm->r_start)) &&
				   rack->use_rack_rr) {
				/*
				 * When a rack timer goes, if the rack rr is
				 * on, arrange it so we can send a full segment
				 * overriding prr (though we pay a price for this
				 * for future new sends).
				 */
				rack->r_ctl.rc_prr_sndcnt = ctf_fixed_maxseg(tp);
				rack_log_to_prr(rack, 4, 0);
			}
		}
	}
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_RACK;
	if (rsm == NULL) {
		/* restart a timer and return 1 */
		rack_start_hpts_timer(rack, tp, cts,
				      0, 0, 0);
		return (1);
	}
	return (0);
}

static __inline void
rack_clone_rsm(struct tcp_rack *rack, struct rack_sendmap *nrsm,
	       struct rack_sendmap *rsm, uint32_t start)
{
	int idx;

	nrsm->r_start = start;
	nrsm->r_end = rsm->r_end;
	nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
	nrsm->r_flags = rsm->r_flags;
	nrsm->r_dupack = rsm->r_dupack;
	nrsm->usec_orig_send = rsm->usec_orig_send;
	nrsm->r_rtr_bytes = 0;
	rsm->r_end = nrsm->r_start;
	nrsm->r_just_ret = rsm->r_just_ret;
	for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
		nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
	}
}

static struct rack_sendmap *
rack_merge_rsm(struct tcp_rack *rack,
	       struct rack_sendmap *l_rsm,
	       struct rack_sendmap *r_rsm)
{
	/*
	 * We are merging two ack'd RSM's,
	 * the l_rsm is on the left (lower seq
	 * values) and the r_rsm is on the right
	 * (higher seq value). The simplest way
	 * to merge these is to move the right
	 * one into the left. I don't think there
	 * is any reason we need to try to find
	 * the oldest (or last oldest retransmitted).
	 */
	struct rack_sendmap *rm;

	l_rsm->r_end = r_rsm->r_end;
	if (l_rsm->r_dupack < r_rsm->r_dupack)
		l_rsm->r_dupack = r_rsm->r_dupack;
	if (r_rsm->r_rtr_bytes)
		l_rsm->r_rtr_bytes += r_rsm->r_rtr_bytes;
	if (r_rsm->r_in_tmap) {
		/* This really should not happen */
		TAILQ_REMOVE(&rack->r_ctl.rc_tmap, r_rsm, r_tnext);
		r_rsm->r_in_tmap = 0;
	}

	/* Now the flags */
	if (r_rsm->r_flags & RACK_HAS_FIN)
		l_rsm->r_flags |= RACK_HAS_FIN;
	if (r_rsm->r_flags & RACK_TLP)
		l_rsm->r_flags |= RACK_TLP;
	if (r_rsm->r_flags & RACK_RWND_COLLAPSED)
		l_rsm->r_flags |= RACK_RWND_COLLAPSED;
	if ((r_rsm->r_flags & RACK_APP_LIMITED)  &&
	    ((l_rsm->r_flags & RACK_APP_LIMITED) == 0)) {
		/*
		 * If both are app-limited then let the
		 * free lower the count. If right is app
		 * limited and left is not, transfer.
		 */
		l_rsm->r_flags |= RACK_APP_LIMITED;
		r_rsm->r_flags &= ~RACK_APP_LIMITED;
		if (r_rsm == rack->r_ctl.rc_first_appl)
			rack->r_ctl.rc_first_appl = l_rsm;
	}
	rm = RB_REMOVE(rack_rb_tree_head, &rack->r_ctl.rc_mtree, r_rsm);
#ifdef INVARIANTS
	if (rm != r_rsm) {
		panic("removing head in rack:%p rsm:%p rm:%p",
		      rack, r_rsm, rm);
	}
#endif
	if ((r_rsm->r_limit_type == 0) && (l_rsm->r_limit_type != 0)) {
		/* Transfer the split limit to the map we free */
		r_rsm->r_limit_type = l_rsm->r_limit_type;
		l_rsm->r_limit_type = 0;
	}
	rack_free(rack, r_rsm);
	return(l_rsm);
}

/*
 * TLP Timer, here we simply setup what segment we want to
 * have the TLP expire on, the normal rack_output() will then
 * send it out.
 *
 * We return 1, saying don't proceed with rack_output only
 * when all timers have been stopped (destroyed PCB?).
 */
static int
rack_timeout_tlp(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	/*
	 * Tail Loss Probe.
	 */
	struct rack_sendmap *rsm = NULL;
	struct rack_sendmap *insret;
	struct socket *so;
	uint32_t amm, old_prr_snd = 0;
	uint32_t out, avail;
	int collapsed_win = 0;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (TSTMP_LT(cts, rack->r_ctl.rc_timer_exp)) {
		/* Its not time yet */
		return (0);
	}
	if (ctf_progress_timeout_check(tp, true)) {
		rack_log_progress_event(rack, tp, tick, PROGRESS_DROP, __LINE__);
		tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
		return (1);
	}
	/*
	 * A TLP timer has expired. We have been idle for 2 rtts. So we now
	 * need to figure out how to force a full MSS segment out.
	 */
	rack_log_to_event(rack, RACK_TO_FRM_TLP, NULL);
	counter_u64_add(rack_tlp_tot, 1);
	if (rack->r_state && (rack->r_state != tp->t_state))
		rack_set_state(tp, rack);
	so = tp->t_inpcb->inp_socket;
#ifdef KERN_TLS
	if (rack->rc_inp->inp_socket->so_snd.sb_flags & SB_TLS_IFNET) {
		/*
		 * For hardware TLS we do *not* want to send
		 * new data, lets instead just do a retransmission.
		 */
		goto need_retran;
	}
#endif
	avail = sbavail(&so->so_snd);
	out = tp->snd_max - tp->snd_una;
	if (out > tp->snd_wnd) {
		/* special case, we need a retransmission */
		collapsed_win = 1;
		goto need_retran;
	}
	/*
	 * Check our send oldest always settings, and if
	 * there is an oldest to send jump to the need_retran.
	 */
	if (rack_always_send_oldest && (TAILQ_EMPTY(&rack->r_ctl.rc_tmap) == 0))
		goto need_retran;

	if (avail > out) {
		/* New data is available */
		amm = avail - out;
		if (amm > ctf_fixed_maxseg(tp)) {
			amm = ctf_fixed_maxseg(tp);
			if ((amm + out) > tp->snd_wnd) {
				/* We are rwnd limited */
				goto need_retran;
			}
		} else if (amm < ctf_fixed_maxseg(tp)) {
			/* not enough to fill a MTU */
			goto need_retran;
		}
		if (IN_RECOVERY(tp->t_flags)) {
			/* Unlikely */
			if (rack->rack_no_prr == 0) {
				old_prr_snd = rack->r_ctl.rc_prr_sndcnt;
				if (out + amm <= tp->snd_wnd) {
					rack->r_ctl.rc_prr_sndcnt = amm;
					rack_log_to_prr(rack, 4, 0);
				}
			} else
				goto need_retran;
		} else {
			/* Set the send-new override */
			if (out + amm <= tp->snd_wnd)
				rack->r_ctl.rc_tlp_new_data = amm;
			else
				goto need_retran;
		}
		rack->r_ctl.rc_tlpsend = NULL;
		counter_u64_add(rack_tlp_newdata, 1);
		goto send;
	}
need_retran:
	/*
	 * Ok we need to arrange the last un-acked segment to be re-sent, or
	 * optionally the first un-acked segment.
	 */
	if (collapsed_win == 0) {
		if (rack_always_send_oldest)
			rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
		else {
			rsm = RB_MAX(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
			if (rsm && (rsm->r_flags & (RACK_ACKED | RACK_HAS_FIN))) {
				rsm = rack_find_high_nonack(rack, rsm);
			}
		}
		if (rsm == NULL) {
			counter_u64_add(rack_tlp_does_nada, 1);
#ifdef TCP_BLACKBOX
			tcp_log_dump_tp_logbuf(tp, "nada counter trips", M_NOWAIT, true);
#endif
			goto out;
		}
	} else {
		/*
		 * We must find the last segment
		 * that was acceptable by the client.
		 */
		RB_FOREACH_REVERSE(rsm, rack_rb_tree_head, &rack->r_ctl.rc_mtree) {
			if ((rsm->r_flags & RACK_RWND_COLLAPSED) == 0) {
				/* Found one */
				break;
			}
		}
		if (rsm == NULL) {
			/* None? if so send the first */
			rsm = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
			if (rsm == NULL) {
				counter_u64_add(rack_tlp_does_nada, 1);
#ifdef TCP_BLACKBOX
				tcp_log_dump_tp_logbuf(tp, "nada counter trips", M_NOWAIT, true);
#endif
				goto out;
			}
		}
	}
	if ((rsm->r_end - rsm->r_start) > ctf_fixed_maxseg(tp)) {
		/*
		 * We need to split this the last segment in two.
		 */
		struct rack_sendmap *nrsm;


		nrsm = rack_alloc_full_limit(rack);
		if (nrsm == NULL) {
			/*
			 * No memory to split, we will just exit and punt
			 * off to the RXT timer.
			 */
			counter_u64_add(rack_tlp_does_nada, 1);
			goto out;
		}
		rack_clone_rsm(rack, nrsm, rsm,
			       (rsm->r_end - ctf_fixed_maxseg(tp)));
		insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm);
#ifdef INVARIANTS
		if (insret != NULL) {
			panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
			      nrsm, insret, rack, rsm);
		}
#endif
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
		rsm->r_flags &= (~RACK_HAS_FIN);
		rsm = nrsm;
	}
	rack->r_ctl.rc_tlpsend = rsm;
send:
	rack->r_timer_override = 1;
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_TLP;
	return (0);
out:
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_TLP;
	return (0);
}

/*
 * Delayed ack Timer, here we simply need to setup the
 * ACK_NOW flag and remove the DELACK flag. From there
 * the output routine will send the ack out.
 *
 * We only return 1, saying don't proceed, if all timers
 * are stopped (destroyed PCB?).
 */
static int
rack_timeout_delack(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	rack_log_to_event(rack, RACK_TO_FRM_DELACK, NULL);
	tp->t_flags &= ~TF_DELACK;
	tp->t_flags |= TF_ACKNOW;
	KMOD_TCPSTAT_INC(tcps_delack);
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_DELACK;
	return (0);
}

/*
 * Persists timer, here we simply send the
 * same thing as a keepalive will.
 * the one byte send.
 *
 * We only return 1, saying don't proceed, if all timers
 * are stopped (destroyed PCB?).
 */
static int
rack_timeout_persist(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	struct tcptemp *t_template;
	struct inpcb *inp;
	int32_t retval = 1;

	inp = tp->t_inpcb;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (rack->rc_in_persist == 0)
		return (0);
	if (ctf_progress_timeout_check(tp, false)) {
		tcp_log_end_status(tp, TCP_EI_STATUS_PERSIST_MAX);
		rack_log_progress_event(rack, tp, tick, PROGRESS_DROP, __LINE__);
		tcp_set_inp_to_drop(inp, ETIMEDOUT);
		return (1);
	}
	KASSERT(inp != NULL, ("%s: tp %p tp->t_inpcb == NULL", __func__, tp));
	/*
	 * Persistence timer into zero window. Force a byte to be output, if
	 * possible.
	 */
	KMOD_TCPSTAT_INC(tcps_persisttimeo);
	/*
	 * Hack: if the peer is dead/unreachable, we do not time out if the
	 * window is closed.  After a full backoff, drop the connection if
	 * the idle time (no responses to probes) reaches the maximum
	 * backoff that we would use if retransmitting.
	 */
	if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
	    (ticks - tp->t_rcvtime >= tcp_maxpersistidle ||
	    ticks - tp->t_rcvtime >= TCP_REXMTVAL(tp) * tcp_totbackoff)) {
		KMOD_TCPSTAT_INC(tcps_persistdrop);
		retval = 1;
		tcp_log_end_status(tp, TCP_EI_STATUS_PERSIST_MAX);
		tcp_set_inp_to_drop(rack->rc_inp, ETIMEDOUT);
		goto out;
	}
	if ((sbavail(&rack->rc_inp->inp_socket->so_snd) == 0) &&
	    tp->snd_una == tp->snd_max)
		rack_exit_persist(tp, rack, cts);
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_PERSIT;
	/*
	 * If the user has closed the socket then drop a persisting
	 * connection after a much reduced timeout.
	 */
	if (tp->t_state > TCPS_CLOSE_WAIT &&
	    (ticks - tp->t_rcvtime) >= TCPTV_PERSMAX) {
		retval = 1;
		KMOD_TCPSTAT_INC(tcps_persistdrop);
		tcp_log_end_status(tp, TCP_EI_STATUS_PERSIST_MAX);
		tcp_set_inp_to_drop(rack->rc_inp, ETIMEDOUT);
		goto out;
	}
	t_template = tcpip_maketemplate(rack->rc_inp);
	if (t_template) {
		/* only set it if we were answered */
		if (rack->forced_ack == 0) {
			rack->forced_ack = 1;
			rack->r_ctl.forced_ack_ts = tcp_get_usecs(NULL);
		}
		tcp_respond(tp, t_template->tt_ipgen,
			    &t_template->tt_t, (struct mbuf *)NULL,
			    tp->rcv_nxt, tp->snd_una - 1, 0);
		/* This sends an ack */
		if (tp->t_flags & TF_DELACK)
			tp->t_flags &= ~TF_DELACK;
		free(t_template, M_TEMP);
	}
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
out:
	rack_log_to_event(rack, RACK_TO_FRM_PERSIST, NULL);
	rack_start_hpts_timer(rack, tp, cts,
			      0, 0, 0);
	return (retval);
}

/*
 * If a keepalive goes off, we had no other timers
 * happening. We always return 1 here since this
 * routine either drops the connection or sends
 * out a segment with respond.
 */
static int
rack_timeout_keepalive(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	struct tcptemp *t_template;
	struct inpcb *inp;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_KEEP;
	inp = tp->t_inpcb;
	rack_log_to_event(rack, RACK_TO_FRM_KEEP, NULL);
	/*
	 * Keep-alive timer went off; send something or drop connection if
	 * idle for too long.
	 */
	KMOD_TCPSTAT_INC(tcps_keeptimeo);
	if (tp->t_state < TCPS_ESTABLISHED)
		goto dropit;
	if ((V_tcp_always_keepalive || inp->inp_socket->so_options & SO_KEEPALIVE) &&
	    tp->t_state <= TCPS_CLOSING) {
		if (ticks - tp->t_rcvtime >= TP_KEEPIDLE(tp) + TP_MAXIDLE(tp))
			goto dropit;
		/*
		 * Send a packet designed to force a response if the peer is
		 * up and reachable: either an ACK if the connection is
		 * still alive, or an RST if the peer has closed the
		 * connection due to timeout or reboot. Using sequence
		 * number tp->snd_una-1 causes the transmitted zero-length
		 * segment to lie outside the receive window; by the
		 * protocol spec, this requires the correspondent TCP to
		 * respond.
		 */
		KMOD_TCPSTAT_INC(tcps_keepprobe);
		t_template = tcpip_maketemplate(inp);
		if (t_template) {
			if (rack->forced_ack == 0) {
				rack->forced_ack = 1;
				rack->r_ctl.forced_ack_ts = tcp_get_usecs(NULL);
			}
			tcp_respond(tp, t_template->tt_ipgen,
			    &t_template->tt_t, (struct mbuf *)NULL,
			    tp->rcv_nxt, tp->snd_una - 1, 0);
			free(t_template, M_TEMP);
		}
	}
	rack_start_hpts_timer(rack, tp, cts, 0, 0, 0);
	return (1);
dropit:
	KMOD_TCPSTAT_INC(tcps_keepdrops);
	tcp_log_end_status(tp, TCP_EI_STATUS_KEEP_MAX);
	tcp_set_inp_to_drop(rack->rc_inp, ETIMEDOUT);
	return (1);
}

/*
 * Retransmit helper function, clear up all the ack
 * flags and take care of important book keeping.
 */
static void
rack_remxt_tmr(struct tcpcb *tp)
{
	/*
	 * The retransmit timer went off, all sack'd blocks must be
	 * un-acked.
	 */
	struct rack_sendmap *rsm, *trsm = NULL;
	struct tcp_rack *rack;
	int32_t cnt = 0;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	rack_timer_cancel(tp, rack, tcp_ts_getticks(), __LINE__);
	rack_log_to_event(rack, RACK_TO_FRM_TMR, NULL);
	if (rack->r_state && (rack->r_state != tp->t_state))
		rack_set_state(tp, rack);
	/*
	 * Ideally we would like to be able to
	 * mark SACK-PASS on anything not acked here.
	 * However, if we do that we would burst out
	 * all that data 1ms apart. This would be unwise,
	 * so for now we will just let the normal rxt timer
	 * and tlp timer take care of it.
	 */
	RB_FOREACH(rsm, rack_rb_tree_head, &rack->r_ctl.rc_mtree) {
		if (rsm->r_flags & RACK_ACKED) {
			cnt++;
			rsm->r_dupack = 0;
			rack_log_retran_reason(rack, rsm, __LINE__, 0, 2);
			if (rsm->r_in_tmap == 0) {
				/* We must re-add it back to the tlist */
				if (trsm == NULL) {
					TAILQ_INSERT_HEAD(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				} else {
					TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, trsm, rsm, r_tnext);
				}
				rsm->r_in_tmap = 1;
			}
		}
		trsm = rsm;
		if (rsm->r_flags & RACK_ACKED)
			rsm->r_flags |= RACK_WAS_ACKED;
		rsm->r_flags &= ~(RACK_ACKED | RACK_SACK_PASSED | RACK_WAS_SACKPASS);
	}
	/* Clear the count (we just un-acked them) */
	rack->r_ctl.rc_sacked = 0;
	rack->r_ctl.rc_agg_delayed = 0;
	rack->r_early = 0;
	rack->r_ctl.rc_agg_early = 0;
	rack->r_late = 0;
	/* Clear the tlp rtx mark */
	rack->r_ctl.rc_resend = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
	rack->r_ctl.rc_prr_sndcnt = 0;
	rack_log_to_prr(rack, 6, 0);
	rack->r_timer_override = 1;
}

static void
rack_cc_conn_init(struct tcpcb *tp)
{
	struct tcp_rack *rack;


	rack = (struct tcp_rack *)tp->t_fb_ptr;
	cc_conn_init(tp);
	/*
	 * We want a chance to stay in slowstart as
	 * we create a connection. TCP spec says that
	 * initially ssthresh is infinite. For our
	 * purposes that is the snd_wnd.
	 */
	if (tp->snd_ssthresh < tp->snd_wnd) {
		tp->snd_ssthresh = tp->snd_wnd;
	}
	/*
	 * We also want to assure a IW worth of
	 * data can get inflight.
	 */
	if (rc_init_window(rack) < tp->snd_cwnd)
		tp->snd_cwnd = rc_init_window(rack);
}

/*
 * Re-transmit timeout! If we drop the PCB we will return 1, otherwise
 * we will setup to retransmit the lowest seq number outstanding.
 */
static int
rack_timeout_rxt(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	int32_t rexmt;
	struct inpcb *inp;
	int32_t retval = 0;
	bool isipv6;

	inp = tp->t_inpcb;
	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (ctf_progress_timeout_check(tp, false)) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RETRAN);
		rack_log_progress_event(rack, tp, tick, PROGRESS_DROP, __LINE__);
		tcp_set_inp_to_drop(inp, ETIMEDOUT);
		return (1);
	}
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_RXT;
	if (TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->snd_una == tp->snd_max)) {
		/* Nothing outstanding .. nothing to do */
		return (0);
	}
	/*
	 * Retransmission timer went off.  Message has not been acked within
	 * retransmit interval.  Back off to a longer retransmit interval
	 * and retransmit one segment.
	 */
	rack_remxt_tmr(tp);
	if ((rack->r_ctl.rc_resend == NULL) ||
	    ((rack->r_ctl.rc_resend->r_flags & RACK_RWND_COLLAPSED) == 0)) {
		/*
		 * If the rwnd collapsed on
		 * the one we are retransmitting
		 * it does not count against the
		 * rxt count.
		 */
		tp->t_rxtshift++;
	}
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT) {
		tp->t_rxtshift = TCP_MAXRXTSHIFT;
		KMOD_TCPSTAT_INC(tcps_timeoutdrop);
		retval = 1;
		tcp_log_end_status(tp, TCP_EI_STATUS_RETRAN);
		tcp_set_inp_to_drop(rack->rc_inp,
		    (tp->t_softerror ? (uint16_t) tp->t_softerror : ETIMEDOUT));
		goto out;
	}
	if (tp->t_state == TCPS_SYN_SENT) {
		/*
		 * If the SYN was retransmitted, indicate CWND to be limited
		 * to 1 segment in cc_conn_init().
		 */
		tp->snd_cwnd = 1;
	} else if (tp->t_rxtshift == 1) {
		/*
		 * first retransmit; record ssthresh and cwnd so they can be
		 * recovered if this turns out to be a "bad" retransmit. A
		 * retransmit is considered "bad" if an ACK for this segment
		 * is received within RTT/2 interval; the assumption here is
		 * that the ACK was already in flight.  See "On Estimating
		 * End-to-End Network Path Properties" by Allman and Paxson
		 * for more details.
		 */
		tp->snd_cwnd_prev = tp->snd_cwnd;
		tp->snd_ssthresh_prev = tp->snd_ssthresh;
		tp->snd_recover_prev = tp->snd_recover;
		if (IN_FASTRECOVERY(tp->t_flags))
			tp->t_flags |= TF_WASFRECOVERY;
		else
			tp->t_flags &= ~TF_WASFRECOVERY;
		if (IN_CONGRECOVERY(tp->t_flags))
			tp->t_flags |= TF_WASCRECOVERY;
		else
			tp->t_flags &= ~TF_WASCRECOVERY;
		tp->t_badrxtwin = ticks + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
		tp->t_flags |= TF_PREVVALID;
	} else
		tp->t_flags &= ~TF_PREVVALID;
	KMOD_TCPSTAT_INC(tcps_rexmttimeo);
	if ((tp->t_state == TCPS_SYN_SENT) ||
	    (tp->t_state == TCPS_SYN_RECEIVED))
		rexmt = MSEC_2_TICKS(RACK_INITIAL_RTO * tcp_backoff[tp->t_rxtshift]);
	else
		rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
	TCPT_RANGESET(tp->t_rxtcur, rexmt,
	   max(MSEC_2_TICKS(rack_rto_min), rexmt),
	   MSEC_2_TICKS(rack_rto_max));
	/*
	 * We enter the path for PLMTUD if connection is established or, if
	 * connection is FIN_WAIT_1 status, reason for the last is that if
	 * amount of data we send is very small, we could send it in couple
	 * of packets and process straight to FIN. In that case we won't
	 * catch ESTABLISHED state.
	 */
#ifdef INET6
	isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV6) ? true : false;
#else
	isipv6 = false;
#endif
	if (((V_tcp_pmtud_blackhole_detect == 1) ||
	    (V_tcp_pmtud_blackhole_detect == 2 && !isipv6) ||
	    (V_tcp_pmtud_blackhole_detect == 3 && isipv6)) &&
	    ((tp->t_state == TCPS_ESTABLISHED) ||
	    (tp->t_state == TCPS_FIN_WAIT_1))) {

		/*
		 * Idea here is that at each stage of mtu probe (usually,
		 * 1448 -> 1188 -> 524) should be given 2 chances to recover
		 * before further clamping down. 'tp->t_rxtshift % 2 == 0'
		 * should take care of that.
		 */
		if (((tp->t_flags2 & (TF2_PLPMTU_PMTUD | TF2_PLPMTU_MAXSEGSNT)) ==
		    (TF2_PLPMTU_PMTUD | TF2_PLPMTU_MAXSEGSNT)) &&
		    (tp->t_rxtshift >= 2 && tp->t_rxtshift < 6 &&
		    tp->t_rxtshift % 2 == 0)) {
			/*
			 * Enter Path MTU Black-hole Detection mechanism: -
			 * Disable Path MTU Discovery (IP "DF" bit). -
			 * Reduce MTU to lower value than what we negotiated
			 * with peer.
			 */
			if ((tp->t_flags2 & TF2_PLPMTU_BLACKHOLE) == 0) {
				/* Record that we may have found a black hole. */
				tp->t_flags2 |= TF2_PLPMTU_BLACKHOLE;
				/* Keep track of previous MSS. */
				tp->t_pmtud_saved_maxseg = tp->t_maxseg;
			}

			/*
			 * Reduce the MSS to blackhole value or to the
			 * default in an attempt to retransmit.
			 */
#ifdef INET6
			if (isipv6 &&
			    tp->t_maxseg > V_tcp_v6pmtud_blackhole_mss) {
				/* Use the sysctl tuneable blackhole MSS. */
				tp->t_maxseg = V_tcp_v6pmtud_blackhole_mss;
				KMOD_TCPSTAT_INC(tcps_pmtud_blackhole_activated);
			} else if (isipv6) {
				/* Use the default MSS. */
				tp->t_maxseg = V_tcp_v6mssdflt;
				/*
				 * Disable Path MTU Discovery when we switch
				 * to minmss.
				 */
				tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;
				KMOD_TCPSTAT_INC(tcps_pmtud_blackhole_activated_min_mss);
			}
#endif
#if defined(INET6) && defined(INET)
			else
#endif
#ifdef INET
			if (tp->t_maxseg > V_tcp_pmtud_blackhole_mss) {
				/* Use the sysctl tuneable blackhole MSS. */
				tp->t_maxseg = V_tcp_pmtud_blackhole_mss;
				KMOD_TCPSTAT_INC(tcps_pmtud_blackhole_activated);
			} else {
				/* Use the default MSS. */
				tp->t_maxseg = V_tcp_mssdflt;
				/*
				 * Disable Path MTU Discovery when we switch
				 * to minmss.
				 */
				tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;
				KMOD_TCPSTAT_INC(tcps_pmtud_blackhole_activated_min_mss);
			}
#endif
		} else {
			/*
			 * If further retransmissions are still unsuccessful
			 * with a lowered MTU, maybe this isn't a blackhole
			 * and we restore the previous MSS and blackhole
			 * detection flags. The limit '6' is determined by
			 * giving each probe stage (1448, 1188, 524) 2
			 * chances to recover.
			 */
			if ((tp->t_flags2 & TF2_PLPMTU_BLACKHOLE) &&
			    (tp->t_rxtshift >= 6)) {
				tp->t_flags2 |= TF2_PLPMTU_PMTUD;
				tp->t_flags2 &= ~TF2_PLPMTU_BLACKHOLE;
				tp->t_maxseg = tp->t_pmtud_saved_maxseg;
				KMOD_TCPSTAT_INC(tcps_pmtud_blackhole_failed);
			}
		}
	}
	/*
	 * If we backed off this far, our srtt estimate is probably bogus.
	 * Clobber it so we'll take the next rtt measurement as our srtt;
	 * move the current srtt into rttvar to keep the current retransmit
	 * times until then.
	 */
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
#ifdef INET6
		if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0)
			in6_losing(tp->t_inpcb);
		else
#endif
			in_losing(tp->t_inpcb);
		tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
		tp->t_srtt = 0;
	}
	sack_filter_clear(&rack->r_ctl.rack_sf, tp->snd_una);
	tp->snd_recover = tp->snd_max;
	tp->t_flags |= TF_ACKNOW;
	tp->t_rtttime = 0;
	rack_cong_signal(tp, NULL, CC_RTO);
out:
	return (retval);
}

static int
rack_process_timers(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, uint8_t hpts_calling)
{
	int32_t ret = 0;
	int32_t timers = (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK);

	if (timers == 0) {
		return (0);
	}
	if (tp->t_state == TCPS_LISTEN) {
		/* no timers on listen sockets */
		if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)
			return (0);
		return (1);
	}
	if ((timers & PACE_TMR_RACK) &&
	    rack->rc_on_min_to) {
		/*
		 * For the rack timer when we
		 * are on a min-timeout (which means rrr_conf = 3)
		 * we don't want to check the timer. It may
		 * be going off for a pace and thats ok we
		 * want to send the retransmit (if its ready).
		 *
		 * If its on a normal rack timer (non-min) then
		 * we will check if its expired.
		 */
		goto skip_time_check;
	}
	if (TSTMP_LT(cts, rack->r_ctl.rc_timer_exp)) {
		uint32_t left;

		if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) {
			ret = -1;
			rack_log_to_processing(rack, cts, ret, 0);
			return (0);
		}
		if (hpts_calling == 0) {
			/*
			 * A user send or queued mbuf (sack) has called us? We
			 * return 0 and let the pacing guards
			 * deal with it if they should or
			 * should not cause a send.
			 */
			ret = -2;
			rack_log_to_processing(rack, cts, ret, 0);
			return (0);
		}
		/*
		 * Ok our timer went off early and we are not paced false
		 * alarm, go back to sleep.
		 */
		ret = -3;
		left = rack->r_ctl.rc_timer_exp - cts;
		tcp_hpts_insert(tp->t_inpcb, HPTS_MS_TO_SLOTS(left));
		rack_log_to_processing(rack, cts, ret, left);
		return (1);
	}
skip_time_check:
	rack->rc_tmr_stopped = 0;
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_MASK;
	if (timers & PACE_TMR_DELACK) {
		ret = rack_timeout_delack(tp, rack, cts);
	} else if (timers & PACE_TMR_RACK) {
		rack->r_ctl.rc_tlp_rxt_last_time = cts;
		ret = rack_timeout_rack(tp, rack, cts);
	} else if (timers & PACE_TMR_TLP) {
		rack->r_ctl.rc_tlp_rxt_last_time = cts;
		ret = rack_timeout_tlp(tp, rack, cts);
	} else if (timers & PACE_TMR_RXT) {
		rack->r_ctl.rc_tlp_rxt_last_time = cts;
		ret = rack_timeout_rxt(tp, rack, cts);
	} else if (timers & PACE_TMR_PERSIT) {
		ret = rack_timeout_persist(tp, rack, cts);
	} else if (timers & PACE_TMR_KEEP) {
		ret = rack_timeout_keepalive(tp, rack, cts);
	}
	rack_log_to_processing(rack, cts, ret, timers);
	return (ret);
}

static void
rack_timer_cancel(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, int line)
{
	struct timeval tv;
	uint32_t us_cts, flags_on_entry;
	uint8_t hpts_removed = 0;


	flags_on_entry = rack->r_ctl.rc_hpts_flags;
	us_cts = tcp_get_usecs(&tv);
	if ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) &&
	    ((TSTMP_GEQ(us_cts, rack->r_ctl.rc_last_output_to)) ||
	     ((tp->snd_max - tp->snd_una) == 0))) {
		tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
		hpts_removed = 1;
		/* If we were not delayed cancel out the flag. */
		if ((tp->snd_max - tp->snd_una) == 0)
			rack->r_ctl.rc_hpts_flags &= ~PACE_PKT_OUTPUT;
		rack_log_to_cancel(rack, hpts_removed, line, us_cts, &tv, flags_on_entry);
	}
	if (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK) {
		rack->rc_tmr_stopped = rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK;
		if (rack->rc_inp->inp_in_hpts &&
		    ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0)) {
			/*
			 * Canceling timer's when we have no output being
			 * paced. We also must remove ourselves from the
			 * hpts.
			 */
			tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
			hpts_removed = 1;
		}
		rack->r_ctl.rc_hpts_flags &= ~(PACE_TMR_MASK);
	}
	if (hpts_removed == 0)
		rack_log_to_cancel(rack, hpts_removed, line, us_cts, &tv, flags_on_entry);
}

static void
rack_timer_stop(struct tcpcb *tp, uint32_t timer_type)
{
	return;
}

static int
rack_stopall(struct tcpcb *tp)
{
	struct tcp_rack *rack;
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	rack->t_timers_stopped = 1;
	return (0);
}

static void
rack_timer_activate(struct tcpcb *tp, uint32_t timer_type, uint32_t delta)
{
	return;
}

static int
rack_timer_active(struct tcpcb *tp, uint32_t timer_type)
{
	return (0);
}

static void
rack_stop_all_timers(struct tcpcb *tp)
{
	struct tcp_rack *rack;

	/*
	 * Assure no timers are running.
	 */
	if (tcp_timer_active(tp, TT_PERSIST)) {
		/* We enter in persists, set the flag appropriately */
		rack = (struct tcp_rack *)tp->t_fb_ptr;
		rack->rc_in_persist = 1;
	}
	tcp_timer_suspend(tp, TT_PERSIST);
	tcp_timer_suspend(tp, TT_REXMT);
	tcp_timer_suspend(tp, TT_KEEP);
	tcp_timer_suspend(tp, TT_DELACK);
}

static void
rack_update_rsm(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm, uint32_t ts)
{
	int32_t idx;

	rsm->r_rtr_cnt++;
	rack_log_retran_reason(rack, rsm, __LINE__, 0, 2);
	rsm->r_dupack = 0;
	if (rsm->r_rtr_cnt > RACK_NUM_OF_RETRANS) {
		rsm->r_rtr_cnt = RACK_NUM_OF_RETRANS;
		rsm->r_flags |= RACK_OVERMAX;
	}
	if ((rsm->r_rtr_cnt > 1) && ((rsm->r_flags & RACK_TLP) == 0)) {
		rack->r_ctl.rc_holes_rxt += (rsm->r_end - rsm->r_start);
		rsm->r_rtr_bytes += (rsm->r_end - rsm->r_start);
	}
	idx = rsm->r_rtr_cnt - 1;
	rsm->r_tim_lastsent[idx] = ts;
	if (rsm->r_flags & RACK_ACKED) {
		/* Problably MTU discovery messing with us */
		rsm->r_flags &= ~RACK_ACKED;
		rack->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
	}
	if (rsm->r_in_tmap) {
		TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 0;
	}
	TAILQ_INSERT_TAIL(&rack->r_ctl.rc_tmap, rsm, r_tnext);
	rsm->r_in_tmap = 1;
	if (rsm->r_flags & RACK_SACK_PASSED) {
		/* We have retransmitted due to the SACK pass */
		rsm->r_flags &= ~RACK_SACK_PASSED;
		rsm->r_flags |= RACK_WAS_SACKPASS;
	}
}


static uint32_t
rack_update_entry(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm, uint32_t ts, int32_t *lenp)
{
	/*
	 * We (re-)transmitted starting at rsm->r_start for some length
	 * (possibly less than r_end.
	 */
	struct rack_sendmap *nrsm, *insret;
	uint32_t c_end;
	int32_t len;

	len = *lenp;
	c_end = rsm->r_start + len;
	if (SEQ_GEQ(c_end, rsm->r_end)) {
		/*
		 * We retransmitted the whole piece or more than the whole
		 * slopping into the next rsm.
		 */
		rack_update_rsm(tp, rack, rsm, ts);
		if (c_end == rsm->r_end) {
			*lenp = 0;
			return (0);
		} else {
			int32_t act_len;

			/* Hangs over the end return whats left */
			act_len = rsm->r_end - rsm->r_start;
			*lenp = (len - act_len);
			return (rsm->r_end);
		}
		/* We don't get out of this block. */
	}
	/*
	 * Here we retransmitted less than the whole thing which means we
	 * have to split this into what was transmitted and what was not.
	 */
	nrsm = rack_alloc_full_limit(rack);
	if (nrsm == NULL) {
		/*
		 * We can't get memory, so lets not proceed.
		 */
		*lenp = 0;
		return (0);
	}
	/*
	 * So here we are going to take the original rsm and make it what we
	 * retransmitted. nrsm will be the tail portion we did not
	 * retransmit. For example say the chunk was 1, 11 (10 bytes). And
	 * we retransmitted 5 bytes i.e. 1, 5. The original piece shrinks to
	 * 1, 6 and the new piece will be 6, 11.
	 */
	rack_clone_rsm(rack, nrsm, rsm, c_end);
	nrsm->r_dupack = 0;
	rack_log_retran_reason(rack, nrsm, __LINE__, 0, 2);
	insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm);
#ifdef INVARIANTS
	if (insret != NULL) {
		panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
		      nrsm, insret, rack, rsm);
	}
#endif
	if (rsm->r_in_tmap) {
		TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
		nrsm->r_in_tmap = 1;
	}
	rsm->r_flags &= (~RACK_HAS_FIN);
	rack_update_rsm(tp, rack, rsm, ts);
	*lenp = 0;
	return (0);
}


static void
rack_log_output(struct tcpcb *tp, struct tcpopt *to, int32_t len,
    uint32_t seq_out, uint8_t th_flags, int32_t err, uint32_t ts,
    uint8_t pass, struct rack_sendmap *hintrsm, uint32_t us_cts)
{
	struct tcp_rack *rack;
	struct rack_sendmap *rsm, *nrsm, *insret, fe;
	register uint32_t snd_max, snd_una;

	/*
	 * Add to the RACK log of packets in flight or retransmitted. If
	 * there is a TS option we will use the TS echoed, if not we will
	 * grab a TS.
	 *
	 * Retransmissions will increment the count and move the ts to its
	 * proper place. Note that if options do not include TS's then we
	 * won't be able to effectively use the ACK for an RTT on a retran.
	 *
	 * Notes about r_start and r_end. Lets consider a send starting at
	 * sequence 1 for 10 bytes. In such an example the r_start would be
	 * 1 (starting sequence) but the r_end would be r_start+len i.e. 11.
	 * This means that r_end is actually the first sequence for the next
	 * slot (11).
	 *
	 */
	/*
	 * If err is set what do we do XXXrrs? should we not add the thing?
	 * -- i.e. return if err != 0 or should we pretend we sent it? --
	 * i.e. proceed with add ** do this for now.
	 */
	INP_WLOCK_ASSERT(tp->t_inpcb);
	if (err)
		/*
		 * We don't log errors -- we could but snd_max does not
		 * advance in this case either.
		 */
		return;

	if (th_flags & TH_RST) {
		/*
		 * We don't log resets and we return immediately from
		 * sending
		 */
		return;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	snd_una = tp->snd_una;
	if (SEQ_LEQ((seq_out + len), snd_una)) {
		/* Are sending an old segment to induce an ack (keep-alive)? */
		return;
	}
	if (SEQ_LT(seq_out, snd_una)) {
		/* huh? should we panic? */
		uint32_t end;

		end = seq_out + len;
		seq_out = snd_una;
		if (SEQ_GEQ(end, seq_out))
			len = end - seq_out;
		else
			len = 0;
	}
	snd_max = tp->snd_max;
	if (th_flags & (TH_SYN | TH_FIN)) {
		/*
		 * The call to rack_log_output is made before bumping
		 * snd_max. This means we can record one extra byte on a SYN
		 * or FIN if seq_out is adding more on and a FIN is present
		 * (and we are not resending).
		 */
		if (th_flags & TH_SYN)
			len++;
		if (th_flags & TH_FIN)
			len++;
		if (SEQ_LT(snd_max, tp->snd_nxt)) {
			/*
			 * The add/update as not been done for the FIN/SYN
			 * yet.
			 */
			snd_max = tp->snd_nxt;
		}
	}
	if (len == 0) {
		/* We don't log zero window probes */
		return;
	}
	rack->r_ctl.rc_time_last_sent = ts;
	if (IN_RECOVERY(tp->t_flags)) {
		rack->r_ctl.rc_prr_out += len;
	}
	/* First question is it a retransmission or new? */
	if (seq_out == snd_max) {
		/* Its new */
again:
		rsm = rack_alloc(rack);
		if (rsm == NULL) {
			/*
			 * Hmm out of memory and the tcb got destroyed while
			 * we tried to wait.
			 */
			return;
		}
		if (th_flags & TH_FIN) {
			rsm->r_flags = RACK_HAS_FIN;
		} else {
			rsm->r_flags = 0;
		}
		rsm->r_tim_lastsent[0] = ts;
		rsm->r_rtr_cnt = 1;
		rsm->r_rtr_bytes = 0;
		rsm->usec_orig_send = us_cts;
		if (th_flags & TH_SYN) {
			/* The data space is one beyond snd_una */
			rsm->r_start = seq_out + 1;
			rsm->r_end = rsm->r_start + (len - 1);
		} else {
			/* Normal case */
			rsm->r_start = seq_out;
			rsm->r_end = rsm->r_start + len;
		}
		rsm->r_dupack = 0;
		rack_log_retran_reason(rack, rsm, __LINE__, 0, 2);
		insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
#ifdef INVARIANTS
		if (insret != NULL) {
			panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
			      nrsm, insret, rack, rsm);
		}
#endif
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 1;
		/*
		 * Special case detection, is there just a single
		 * packet outstanding when we are not in recovery?
		 *
		 * If this is true mark it so.
		 */
		if ((IN_RECOVERY(tp->t_flags) == 0) &&
		    (ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked) == ctf_fixed_maxseg(tp))) {
			struct rack_sendmap *prsm;

			prsm = RB_PREV(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
			if (prsm)
				prsm->r_one_out_nr = 1;
		}
		return;
	}
	/*
	 * If we reach here its a retransmission and we need to find it.
	 */
	memset(&fe, 0, sizeof(fe));
more:
	if (hintrsm && (hintrsm->r_start == seq_out)) {
		rsm = hintrsm;
		hintrsm = NULL;
	} else {
		/* No hints sorry */
		rsm = NULL;
	}
	if ((rsm) && (rsm->r_start == seq_out)) {
		seq_out = rack_update_entry(tp, rack, rsm, ts, &len);
		if (len == 0) {
			return;
		} else {
			goto more;
		}
	}
	/* Ok it was not the last pointer go through it the hard way. */
refind:
	fe.r_start = seq_out;
	rsm = RB_FIND(rack_rb_tree_head, &rack->r_ctl.rc_mtree, &fe);
	if (rsm) {
		if (rsm->r_start == seq_out) {
			seq_out = rack_update_entry(tp, rack, rsm, ts, &len);
			if (len == 0) {
				return;
			} else {
				goto refind;
			}
		}
		if (SEQ_GEQ(seq_out, rsm->r_start) && SEQ_LT(seq_out, rsm->r_end)) {
			/* Transmitted within this piece */
			/*
			 * Ok we must split off the front and then let the
			 * update do the rest
			 */
			nrsm = rack_alloc_full_limit(rack);
			if (nrsm == NULL) {
				rack_update_rsm(tp, rack, rsm, ts);
				return;
			}
			/*
			 * copy rsm to nrsm and then trim the front of rsm
			 * to not include this part.
			 */
			rack_clone_rsm(rack, nrsm, rsm, seq_out);
			insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm);
#ifdef INVARIANTS
			if (insret != NULL) {
				panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
				      nrsm, insret, rack, rsm);
			}
#endif
			if (rsm->r_in_tmap) {
				TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
				nrsm->r_in_tmap = 1;
			}
			rsm->r_flags &= (~RACK_HAS_FIN);
			seq_out = rack_update_entry(tp, rack, nrsm, ts, &len);
			if (len == 0) {
				return;
			} else if (len > 0)
				goto refind;
		}
	}
	/*
	 * Hmm not found in map did they retransmit both old and on into the
	 * new?
	 */
	if (seq_out == tp->snd_max) {
		goto again;
	} else if (SEQ_LT(seq_out, tp->snd_max)) {
#ifdef INVARIANTS
		printf("seq_out:%u len:%d snd_una:%u snd_max:%u -- but rsm not found?\n",
		    seq_out, len, tp->snd_una, tp->snd_max);
		printf("Starting Dump of all rack entries\n");
		RB_FOREACH(rsm, rack_rb_tree_head, &rack->r_ctl.rc_mtree) {
			printf("rsm:%p start:%u end:%u\n",
			    rsm, rsm->r_start, rsm->r_end);
		}
		printf("Dump complete\n");
		panic("seq_out not found rack:%p tp:%p",
		    rack, tp);
#endif
	} else {
#ifdef INVARIANTS
		/*
		 * Hmm beyond sndmax? (only if we are using the new rtt-pack
		 * flag)
		 */
		panic("seq_out:%u(%d) is beyond snd_max:%u tp:%p",
		    seq_out, len, tp->snd_max, tp);
#endif
	}
}

/*
 * Record one of the RTT updates from an ack into
 * our sample structure.
 */

static void
tcp_rack_xmit_timer(struct tcp_rack *rack, int32_t rtt, uint32_t len, uint32_t us_rtt,
		    int confidence, struct rack_sendmap *rsm, uint16_t rtrcnt)
{
	if ((rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY) ||
	    (rack->r_ctl.rack_rs.rs_rtt_lowest > rtt)) {
		rack->r_ctl.rack_rs.rs_rtt_lowest = rtt;
	}
	if ((rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY) ||
	    (rack->r_ctl.rack_rs.rs_rtt_highest < rtt)) {
		rack->r_ctl.rack_rs.rs_rtt_highest = rtt;
	}
	if (rack->rc_tp->t_flags & TF_GPUTINPROG) {
	    if (us_rtt < rack->r_ctl.rc_gp_lowrtt)
		rack->r_ctl.rc_gp_lowrtt = us_rtt;
	    if (rack->rc_tp->snd_wnd > rack->r_ctl.rc_gp_high_rwnd)
		    rack->r_ctl.rc_gp_high_rwnd = rack->rc_tp->snd_wnd;
	}
	if ((confidence == 1) &&
	    ((rsm == NULL) ||
	     (rsm->r_just_ret) ||
	     (rsm->r_one_out_nr &&
	      len < (ctf_fixed_maxseg(rack->rc_tp) * 2)))) {
		/*
		 * If the rsm had a just return
		 * hit it then we can't trust the
		 * rtt measurement for buffer deterimination
		 * Note that a confidence of 2, indicates
		 * SACK'd which overrides the r_just_ret or
		 * the r_one_out_nr. If it was a CUM-ACK and
		 * we had only two outstanding, but get an
		 * ack for only 1. Then that also lowers our
		 * confidence.
		 */
		confidence = 0;
	}
	if ((rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY) ||
	    (rack->r_ctl.rack_rs.rs_us_rtt > us_rtt)) {
		if (rack->r_ctl.rack_rs.confidence == 0) {
			/*
			 * We take anything with no current confidence
			 * saved.
			 */
			rack->r_ctl.rack_rs.rs_us_rtt = us_rtt;
			rack->r_ctl.rack_rs.confidence = confidence;
			rack->r_ctl.rack_rs.rs_us_rtrcnt = rtrcnt;
		} else if (confidence || rack->r_ctl.rack_rs.confidence) {
			/*
			 * Once we have a confident number,
			 * we can update it with a smaller
			 * value since this confident number
			 * may include the DSACK time until
			 * the next segment (the second one) arrived.
			 */
			rack->r_ctl.rack_rs.rs_us_rtt = us_rtt;
			rack->r_ctl.rack_rs.confidence = confidence;
			rack->r_ctl.rack_rs.rs_us_rtrcnt = rtrcnt;
		}

	}
	rack_log_rtt_upd(rack->rc_tp, rack, us_rtt, len, rsm, confidence);
	rack->r_ctl.rack_rs.rs_flags = RACK_RTT_VALID;
	rack->r_ctl.rack_rs.rs_rtt_tot += rtt;
	rack->r_ctl.rack_rs.rs_rtt_cnt++;
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
static void
tcp_rack_xmit_timer_commit(struct tcp_rack *rack, struct tcpcb *tp)
{
	int32_t delta;
	uint32_t o_srtt, o_var;
	int32_t hrtt_up = 0;
	int32_t rtt;

	if (rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY)
		/* No valid sample */
		return;
	if (rack->r_ctl.rc_rate_sample_method == USE_RTT_LOW) {
		/* We are to use the lowest RTT seen in a single ack */
		rtt = rack->r_ctl.rack_rs.rs_rtt_lowest;
	} else if (rack->r_ctl.rc_rate_sample_method == USE_RTT_HIGH) {
		/* We are to use the highest RTT seen in a single ack */
		rtt = rack->r_ctl.rack_rs.rs_rtt_highest;
	} else if (rack->r_ctl.rc_rate_sample_method == USE_RTT_AVG) {
		/* We are to use the average RTT seen in a single ack */
		rtt = (int32_t)(rack->r_ctl.rack_rs.rs_rtt_tot /
				(uint64_t)rack->r_ctl.rack_rs.rs_rtt_cnt);
	} else {
#ifdef INVARIANTS
		panic("Unknown rtt variant %d", rack->r_ctl.rc_rate_sample_method);
#endif
		return;
	}
	if (rtt == 0)
		rtt = 1;
	if (rack->rc_gp_rtt_set == 0) {
		/*
		 * With no RTT we have to accept
		 * even one we are not confident of.
		 */
		rack->r_ctl.rc_gp_srtt = rack->r_ctl.rack_rs.rs_us_rtt;
		rack->rc_gp_rtt_set = 1;
	} else if (rack->r_ctl.rack_rs.confidence) {
		/* update the running gp srtt */
		rack->r_ctl.rc_gp_srtt -= (rack->r_ctl.rc_gp_srtt/8);
		rack->r_ctl.rc_gp_srtt += rack->r_ctl.rack_rs.rs_us_rtt / 8;
	}
	if (rack->r_ctl.rack_rs.confidence) {
		/*
		 * record the low and high for highly buffered path computation,
		 * we only do this if we are confident (not a retransmission).
		 */
		if (rack->r_ctl.rc_highest_us_rtt < rack->r_ctl.rack_rs.rs_us_rtt) {
			rack->r_ctl.rc_highest_us_rtt = rack->r_ctl.rack_rs.rs_us_rtt;
			hrtt_up = 1;
		}
		if (rack->rc_highly_buffered == 0) {
			/*
			 * Currently once we declare a path has
			 * highly buffered there is no going
			 * back, which may be a problem...
			 */
			if ((rack->r_ctl.rc_highest_us_rtt / rack->r_ctl.rc_lowest_us_rtt) > rack_hbp_thresh) {
				rack_log_rtt_shrinks(rack, rack->r_ctl.rack_rs.rs_us_rtt,
						     rack->r_ctl.rc_highest_us_rtt,
						     rack->r_ctl.rc_lowest_us_rtt,
						     RACK_RTTS_SEEHBP);
				rack->rc_highly_buffered = 1;
			}
		}
	}
	if ((rack->r_ctl.rack_rs.confidence) ||
	    (rack->r_ctl.rack_rs.rs_us_rtrcnt == 1)) {
		/*
		 * If we are highly confident of it <or> it was
		 * never retransmitted we accept it as the last us_rtt.
		 */
		rack->r_ctl.rc_last_us_rtt = rack->r_ctl.rack_rs.rs_us_rtt;
		/* The lowest rtt can be set if its was not retransmited */
		if (rack->r_ctl.rc_lowest_us_rtt > rack->r_ctl.rack_rs.rs_us_rtt) {
			rack->r_ctl.rc_lowest_us_rtt = rack->r_ctl.rack_rs.rs_us_rtt;
			if (rack->r_ctl.rc_lowest_us_rtt == 0)
				rack->r_ctl.rc_lowest_us_rtt = 1;
		}
	}
	rack_log_rtt_sample(rack, rtt);
	o_srtt = tp->t_srtt;
	o_var = tp->t_rttvar;
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (tp->t_srtt != 0) {
		/*
		 * srtt is stored as fixed point with 5 bits after the
		 * binary point (i.e., scaled by 8).  The following magic is
		 * equivalent to the smoothing algorithm in rfc793 with an
		 * alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed point).
		 * Adjust rtt to origin 0.
		 */
		delta = ((rtt - 1) << TCP_DELTA_SHIFT)
		    - (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

		tp->t_srtt += delta;
		if (tp->t_srtt <= 0)
			tp->t_srtt = 1;

		/*
		 * We accumulate a smoothed rtt variance (actually, a
		 * smoothed mean difference), then set the retransmit timer
		 * to smoothed rtt + 4 times the smoothed variance. rttvar
		 * is stored as fixed point with 4 bits after the binary
		 * point (scaled by 16).  The following is equivalent to
		 * rfc793 smoothing with an alpha of .75 (rttvar =
		 * rttvar*3/4 + |delta| / 4).  This replaces rfc793's
		 * wired-in beta.
		 */
		if (delta < 0)
			delta = -delta;
		delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
		tp->t_rttvar += delta;
		if (tp->t_rttvar <= 0)
			tp->t_rttvar = 1;
		if (tp->t_rttbest > tp->t_srtt + tp->t_rttvar)
			tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	} else {
		/*
		 * No rtt measurement yet - use the unsmoothed rtt. Set the
		 * variance to half the rtt (so our first retransmit happens
		 * at 3*rtt).
		 */
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
		tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	}
	KMOD_TCPSTAT_INC(tcps_rttupdated);
	tp->t_rttupdated++;
#ifdef STATS
	stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_RTT, imax(0, rtt));
#endif
	tp->t_rxtshift = 0;

	/*
	 * the retransmit should happen at rtt + 4 * rttvar. Because of the
	 * way we do the smoothing, srtt and rttvar will each average +1/2
	 * tick of bias.  When we compute the retransmit timer, we want 1/2
	 * tick of rounding and 1 extra tick because of +-1/2 tick
	 * uncertainty in the firing of the timer.  The bias will give us
	 * exactly the 1.5 tick we need.  But, because the bias is
	 * statistical, we have to test that we don't drop below the minimum
	 * feasible timer (which is 2 ticks).
	 */
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
	   max(MSEC_2_TICKS(rack_rto_min), rtt + 2), MSEC_2_TICKS(rack_rto_max));
	tp->t_softerror = 0;
}

static void
rack_earlier_retran(struct tcpcb *tp, struct rack_sendmap *rsm,
    uint32_t t, uint32_t cts)
{
	/*
	 * For this RSM, we acknowledged the data from a previous
	 * transmission, not the last one we made. This means we did a false
	 * retransmit.
	 */
	struct tcp_rack *rack;

	if (rsm->r_flags & RACK_HAS_FIN) {
		/*
		 * The sending of the FIN often is multiple sent when we
		 * have everything outstanding ack'd. We ignore this case
		 * since its over now.
		 */
		return;
	}
	if (rsm->r_flags & RACK_TLP) {
		/*
		 * We expect TLP's to have this occur.
		 */
		return;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	/* should we undo cc changes and exit recovery? */
	if (IN_RECOVERY(tp->t_flags)) {
		if (rack->r_ctl.rc_rsm_start == rsm->r_start) {
			/*
			 * Undo what we ratched down and exit recovery if
			 * possible
			 */
			EXIT_RECOVERY(tp->t_flags);
			tp->snd_recover = tp->snd_una;
			if (rack->r_ctl.rc_cwnd_at > tp->snd_cwnd)
				tp->snd_cwnd = rack->r_ctl.rc_cwnd_at;
			if (rack->r_ctl.rc_ssthresh_at > tp->snd_ssthresh)
				tp->snd_ssthresh = rack->r_ctl.rc_ssthresh_at;
		}
	}
	if (rsm->r_flags & RACK_WAS_SACKPASS) {
		/*
		 * We retransmitted based on a sack and the earlier
		 * retransmission ack'd it - re-ordering is occuring.
		 */
		counter_u64_add(rack_reorder_seen, 1);
		rack->r_ctl.rc_reorder_ts = cts;
	}
	counter_u64_add(rack_badfr, 1);
	counter_u64_add(rack_badfr_bytes, (rsm->r_end - rsm->r_start));
}

static void
rack_apply_updated_usrtt(struct tcp_rack *rack, uint32_t us_rtt, uint32_t us_cts)
{
	/*
	 * Apply to filter the inbound us-rtt at us_cts.
	 */
	uint32_t old_rtt;

	old_rtt = get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt);
	apply_filter_min_small(&rack->r_ctl.rc_gp_min_rtt,
			       us_rtt, us_cts);
	if (rack->r_ctl.last_pacing_time &&
	    rack->rc_gp_dyn_mul &&
	    (rack->r_ctl.last_pacing_time > us_rtt))
		rack->pacing_longer_than_rtt = 1;
	else
		rack->pacing_longer_than_rtt = 0;
	if (old_rtt > us_rtt) {
		/* We just hit a new lower rtt time */
		rack_log_rtt_shrinks(rack,  us_cts,  old_rtt,
				     __LINE__, RACK_RTTS_NEWRTT);
		/*
		 * Only count it if its lower than what we saw within our
		 * calculated range.
		 */
		if ((old_rtt - us_rtt) > rack_min_rtt_movement) {
			if (rack_probertt_lower_within &&
			    rack->rc_gp_dyn_mul &&
			    (rack->use_fixed_rate == 0) &&
			    (rack->rc_always_pace)) {
				/*
				 * We are seeing a new lower rtt very close
				 * to the time that we would have entered probe-rtt.
				 * This is probably due to the fact that a peer flow
				 * has entered probe-rtt. Lets go in now too.
				 */
				uint32_t val;

				val = rack_probertt_lower_within * rack_time_between_probertt;
				val /= 100;
				if ((rack->in_probe_rtt == 0)  &&
				    ((us_cts - rack->r_ctl.rc_lower_rtt_us_cts) >= (rack_time_between_probertt - val)))	{
					rack_enter_probertt(rack, us_cts);
				}
			}
			rack->r_ctl.rc_lower_rtt_us_cts = us_cts;
		}
	}
}

static int
rack_update_rtt(struct tcpcb *tp, struct tcp_rack *rack,
    struct rack_sendmap *rsm, struct tcpopt *to, uint32_t cts, int32_t ack_type, tcp_seq th_ack)
{
	int32_t i;
	uint32_t t, len_acked;

	if ((rsm->r_flags & RACK_ACKED) ||
	    (rsm->r_flags & RACK_WAS_ACKED))
		/* Already done */
		return (0);

	if (ack_type == CUM_ACKED) {
		if (SEQ_GT(th_ack, rsm->r_end))
			len_acked = rsm->r_end - rsm->r_start;
		else
			len_acked = th_ack - rsm->r_start;
	} else
		len_acked = rsm->r_end - rsm->r_start;
	if (rsm->r_rtr_cnt == 1) {
		uint32_t us_rtt;

		t = cts - rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)];
		if ((int)t <= 0)
			t = 1;
		if (!tp->t_rttlow || tp->t_rttlow > t)
			tp->t_rttlow = t;
		if (!rack->r_ctl.rc_rack_min_rtt ||
		    SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
			rack->r_ctl.rc_rack_min_rtt = t;
			if (rack->r_ctl.rc_rack_min_rtt == 0) {
				rack->r_ctl.rc_rack_min_rtt = 1;
			}
		}
		us_rtt = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time) - rsm->usec_orig_send;
		if (us_rtt == 0)
			us_rtt = 1;
		rack_apply_updated_usrtt(rack, us_rtt, tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time));
		if (ack_type == SACKED)
			tcp_rack_xmit_timer(rack, t + 1, len_acked, us_rtt, 2 , rsm, rsm->r_rtr_cnt);
		else {
			/*
			 * For cum-ack we are only confident if what
			 * is being acked is included in a measurement.
			 * Otherwise it could be an idle period that
			 * includes Delayed-ack time.
			 */
			tcp_rack_xmit_timer(rack, t + 1, len_acked, us_rtt,
					    (rack->app_limited_needs_set ? 0 : 1), rsm, rsm->r_rtr_cnt);
		}
		if ((rsm->r_flags & RACK_TLP) &&
		    (!IN_RECOVERY(tp->t_flags))) {
			/* Segment was a TLP and our retrans matched */
			if (rack->r_ctl.rc_tlp_cwnd_reduce) {
				rack->r_ctl.rc_rsm_start = tp->snd_max;
				rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
				rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
				rack_cong_signal(tp, NULL, CC_NDUPACK);
				/*
				 * When we enter recovery we need to assure
				 * we send one packet.
				 */
				if (rack->rack_no_prr == 0) {
					rack->r_ctl.rc_prr_sndcnt = ctf_fixed_maxseg(tp);
					rack_log_to_prr(rack, 7, 0);
				}
			}
		}
		if (SEQ_LT(rack->r_ctl.rc_rack_tmit_time, rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)])) {
			/* New more recent rack_tmit_time */
			rack->r_ctl.rc_rack_tmit_time = rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)];
			rack->rc_rack_rtt = t;
		}
		return (1);
	}
	/*
	 * We clear the soft/rxtshift since we got an ack.
	 * There is no assurance we will call the commit() function
	 * so we need to clear these to avoid incorrect handling.
	 */
	tp->t_rxtshift = 0;
	tp->t_softerror = 0;
	if ((to->to_flags & TOF_TS) &&
	    (ack_type == CUM_ACKED) &&
	    (to->to_tsecr) &&
	    ((rsm->r_flags & RACK_OVERMAX) == 0)) {
		/*
		 * Now which timestamp does it match? In this block the ACK
		 * must be coming from a previous transmission.
		 */
		for (i = 0; i < rsm->r_rtr_cnt; i++) {
			if (rsm->r_tim_lastsent[i] == to->to_tsecr) {
				t = cts - rsm->r_tim_lastsent[i];
				if ((int)t <= 0)
					t = 1;
				if ((i + 1) < rsm->r_rtr_cnt) {
					/* Likely */
					rack_earlier_retran(tp, rsm, t, cts);
				}
				if (!tp->t_rttlow || tp->t_rttlow > t)
					tp->t_rttlow = t;
				if (!rack->r_ctl.rc_rack_min_rtt || SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
					rack->r_ctl.rc_rack_min_rtt = t;
					if (rack->r_ctl.rc_rack_min_rtt == 0) {
						rack->r_ctl.rc_rack_min_rtt = 1;
					}
				}
				if (SEQ_LT(rack->r_ctl.rc_rack_tmit_time,
				    rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)])) {
					/* New more recent rack_tmit_time */
					rack->r_ctl.rc_rack_tmit_time = rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)];
					rack->rc_rack_rtt = t;
				}
				tcp_rack_xmit_timer(rack, t + 1, len_acked, (t * HPTS_USEC_IN_MSEC), 0, rsm,
						    rsm->r_rtr_cnt);
				return (1);
			}
		}
		goto ts_not_found;
	} else {
		/*
		 * Ok its a SACK block that we retransmitted. or a windows
		 * machine without timestamps. We can tell nothing from the
		 * time-stamp since its not there or the time the peer last
		 * recieved a segment that moved forward its cum-ack point.
		 */
ts_not_found:
		i = rsm->r_rtr_cnt - 1;
		t = cts - rsm->r_tim_lastsent[i];
		if ((int)t <= 0)
			t = 1;
		if (rack->r_ctl.rc_rack_min_rtt && SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
			/*
			 * We retransmitted and the ack came back in less
			 * than the smallest rtt we have observed. We most
			 * likey did an improper retransmit as outlined in
			 * 4.2 Step 3 point 2 in the rack-draft.
			 */
			i = rsm->r_rtr_cnt - 2;
			t = cts - rsm->r_tim_lastsent[i];
			rack_earlier_retran(tp, rsm, t, cts);
		} else if (rack->r_ctl.rc_rack_min_rtt) {
			/*
			 * We retransmitted it and the retransmit did the
			 * job.
			 */
			if (!rack->r_ctl.rc_rack_min_rtt ||
			    SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
				rack->r_ctl.rc_rack_min_rtt = t;
				if (rack->r_ctl.rc_rack_min_rtt == 0) {
					rack->r_ctl.rc_rack_min_rtt = 1;
				}
			}
			if (SEQ_LT(rack->r_ctl.rc_rack_tmit_time, rsm->r_tim_lastsent[i])) {
				/* New more recent rack_tmit_time */
				rack->r_ctl.rc_rack_tmit_time = rsm->r_tim_lastsent[i];
				rack->rc_rack_rtt = t;
			}
			return (1);
		}
	}
	return (0);
}

/*
 * Mark the SACK_PASSED flag on all entries prior to rsm send wise.
 */
static void
rack_log_sack_passed(struct tcpcb *tp,
    struct tcp_rack *rack, struct rack_sendmap *rsm)
{
	struct rack_sendmap *nrsm;

	nrsm = rsm;
	TAILQ_FOREACH_REVERSE_FROM(nrsm, &rack->r_ctl.rc_tmap,
	    rack_head, r_tnext) {
		if (nrsm == rsm) {
			/* Skip orginal segment he is acked */
			continue;
		}
		if (nrsm->r_flags & RACK_ACKED) {
			/*
			 * Skip ack'd segments, though we
			 * should not see these, since tmap
			 * should not have ack'd segments.
			 */
			continue;
		}
		if (nrsm->r_flags & RACK_SACK_PASSED) {
			/*
			 * We found one that is already marked
			 * passed, we have been here before and
			 * so all others below this are marked.
			 */
			break;
		}
		nrsm->r_flags |= RACK_SACK_PASSED;
		nrsm->r_flags &= ~RACK_WAS_SACKPASS;
	}
}

static void
rack_need_set_test(struct tcpcb *tp,
		   struct tcp_rack *rack,
		   struct rack_sendmap *rsm,
		   tcp_seq th_ack,
		   int line,
		   int use_which)
{

	if ((tp->t_flags & TF_GPUTINPROG) &&
	    SEQ_GEQ(rsm->r_end, tp->gput_seq)) {
		/*
		 * We were app limited, and this ack
		 * butts up or goes beyond the point where we want
		 * to start our next measurement. We need
		 * to record the new gput_ts as here and
		 * possibly update the start sequence.
		 */
		uint32_t seq, ts;

		if (rsm->r_rtr_cnt > 1) {
			/*
			 * This is a retransmit, can we
			 * really make any assessment at this
			 * point?  We are not really sure of
			 * the timestamp, is it this or the
			 * previous transmission?
			 *
			 * Lets wait for something better that
			 * is not retransmitted.
			 */
			return;
		}
		seq = tp->gput_seq;
		ts = tp->gput_ts;
		rack->app_limited_needs_set = 0;
		tp->gput_ts = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
		/* Do we start at a new end? */
		if ((use_which == RACK_USE_BEG) &&
		    SEQ_GEQ(rsm->r_start, tp->gput_seq)) {
			/*
			 * When we get an ACK that just eats
			 * up some of the rsm, we set RACK_USE_BEG
			 * since whats at r_start (i.e. th_ack)
			 * is left unacked and thats where the
			 * measurement not starts.
			 */
			tp->gput_seq = rsm->r_start;
			rack->r_ctl.rc_gp_output_ts = rsm->usec_orig_send;
		}
		if ((use_which == RACK_USE_END) &&
		    SEQ_GEQ(rsm->r_end, tp->gput_seq)) {
			    /*
			     * We use the end when the cumack
			     * is moving forward and completely
			     * deleting the rsm passed so basically
			     * r_end holds th_ack.
			     *
			     * For SACK's we also want to use the end
			     * since this piece just got sacked and
			     * we want to target anything after that
			     * in our measurement.
			     */
			    tp->gput_seq = rsm->r_end;
			    rack->r_ctl.rc_gp_output_ts = rsm->usec_orig_send;
		}
		if (use_which == RACK_USE_END_OR_THACK) {
			/*
			 * special case for ack moving forward,
			 * not a sack, we need to move all the
			 * way up to where this ack cum-ack moves
			 * to.
			 */
			if (SEQ_GT(th_ack, rsm->r_end))
				tp->gput_seq = th_ack;
			else
				tp->gput_seq = rsm->r_end;
			rack->r_ctl.rc_gp_output_ts = rsm->usec_orig_send;
		}
		if (SEQ_GT(tp->gput_seq, tp->gput_ack)) {
			/*
			 * We moved beyond this guy's range, re-calculate
			 * the new end point.
			 */
			if (rack->rc_gp_filled == 0) {
				tp->gput_ack = tp->gput_seq + max(rc_init_window(rack), (MIN_GP_WIN * ctf_fixed_maxseg(tp)));
			} else {
				tp->gput_ack = tp->gput_seq + rack_get_measure_window(tp, rack);
			}
		}
		/*
		 * We are moving the goal post, we may be able to clear the
		 * measure_saw_probe_rtt flag.
		 */
		if ((rack->in_probe_rtt == 0) &&
		    (rack->measure_saw_probe_rtt) &&
		    (SEQ_GEQ(tp->gput_seq, rack->r_ctl.rc_probertt_sndmax_atexit)))
			rack->measure_saw_probe_rtt = 0;
		rack_log_pacing_delay_calc(rack, ts, tp->gput_ts,
					   seq, tp->gput_seq, 0, 5, line, NULL);
		if (rack->rc_gp_filled &&
		    ((tp->gput_ack - tp->gput_seq) <
		     max(rc_init_window(rack), (MIN_GP_WIN *
						ctf_fixed_maxseg(tp))))) {
			/*
			 * There is no sense of continuing this measurement
			 * because its too small to gain us anything we
			 * trust. Skip it and that way we can start a new
			 * measurement quicker.
			 */
			rack_log_pacing_delay_calc(rack, tp->gput_ack, tp->gput_seq,
						   0, 0, 0, 6, __LINE__, NULL);
			tp->t_flags &= ~TF_GPUTINPROG;
		}
	}
}

static uint32_t
rack_proc_sack_blk(struct tcpcb *tp, struct tcp_rack *rack, struct sackblk *sack,
		   struct tcpopt *to, struct rack_sendmap **prsm, uint32_t cts, int *moved_two)
{
	uint32_t start, end, changed = 0;
	struct rack_sendmap stack_map;
	struct rack_sendmap *rsm, *nrsm, fe, *insret, *prev, *next;
	int32_t used_ref = 1;
	int moved = 0;

	start = sack->start;
	end = sack->end;
	rsm = *prsm;
	memset(&fe, 0, sizeof(fe));
do_rest_ofb:
	if ((rsm == NULL) ||
	    (SEQ_LT(end, rsm->r_start)) ||
	    (SEQ_GEQ(start, rsm->r_end)) ||
	    (SEQ_LT(start, rsm->r_start))) {
		/*
		 * We are not in the right spot,
		 * find the correct spot in the tree.
		 */
		used_ref = 0;
		fe.r_start = start;
		rsm = RB_FIND(rack_rb_tree_head, &rack->r_ctl.rc_mtree, &fe);
		moved++;
	}
	if (rsm == NULL) {
		/* TSNH */
		goto out;
	}
	/* Ok we have an ACK for some piece of this rsm */
	if (rsm->r_start != start) {
		if ((rsm->r_flags & RACK_ACKED) == 0) {
			/**
			 * Need to split this in two pieces the before and after,
			 * the before remains in the map, the after must be
			 * added. In other words we have:
			 * rsm        |--------------|
			 * sackblk        |------->
			 * rsm will become
			 *     rsm    |---|
			 * and nrsm will be  the sacked piece
			 *     nrsm       |----------|
			 *
			 * But before we start down that path lets
			 * see if the sack spans over on top of
			 * the next guy and it is already sacked.
			 */
			next = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
			if (next && (next->r_flags & RACK_ACKED) &&
			    SEQ_GEQ(end, next->r_start)) {
				/**
				 * So the next one is already acked, and
				 * we can thus by hookery use our stack_map
				 * to reflect the piece being sacked and
				 * then adjust the two tree entries moving
				 * the start and ends around. So we start like:
				 *  rsm     |------------|             (not-acked)
				 *  next                 |-----------| (acked)
				 *  sackblk        |-------->
				 *  We want to end like so:
				 *  rsm     |------|                   (not-acked)
				 *  next           |-----------------| (acked)
				 *  nrsm           |-----|
				 * Where nrsm is a temporary stack piece we
				 * use to update all the gizmos.
				 */
				/* Copy up our fudge block */
				nrsm = &stack_map;
				memcpy(nrsm, rsm, sizeof(struct rack_sendmap));
				/* Now adjust our tree blocks */
				rsm->r_end = start;
				next->r_start = start;
				/* Clear out the dup ack count of the remainder */
				rsm->r_dupack = 0;
				rsm->r_just_ret = 0;
				rack_log_retran_reason(rack, rsm, __LINE__, 0, 2);
				/* Now lets make sure our fudge block is right */
				nrsm->r_start = start;
				/* Now lets update all the stats and such */
				rack_update_rtt(tp, rack, nrsm, to, cts, SACKED, 0);
				if (rack->app_limited_needs_set)
					rack_need_set_test(tp, rack, nrsm, tp->snd_una, __LINE__, RACK_USE_END);
				changed += (nrsm->r_end - nrsm->r_start);
				rack->r_ctl.rc_sacked += (nrsm->r_end - nrsm->r_start);
				if (nrsm->r_flags & RACK_SACK_PASSED) {
					counter_u64_add(rack_reorder_seen, 1);
					rack->r_ctl.rc_reorder_ts = cts;
				}
				/*
				 * Now we want to go up from rsm (the
				 * one left un-acked) to the next one
				 * in the tmap. We do this so when
				 * we walk backwards we include marking
				 * sack-passed on rsm (The one passed in
				 * is skipped since it is generally called
				 * on something sacked before removing it
				 * from the tmap).
				 */
				if (rsm->r_in_tmap) {
					nrsm = TAILQ_NEXT(rsm, r_tnext);
					/*
					 * Now that we have the next
					 * one walk backwards from there.
					 */
					if (nrsm && nrsm->r_in_tmap)
						rack_log_sack_passed(tp, rack, nrsm);
				}
				/* Now are we done? */
				if (SEQ_LT(end, next->r_end) ||
				    (end == next->r_end)) {
					/* Done with block */
					goto out;
				}
				counter_u64_add(rack_sack_used_next_merge, 1);
				/* Postion for the next block */
				start = next->r_end;
				rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, next);
				if (rsm == NULL)
					goto out;
			} else {
				/**
				 * We can't use any hookery here, so we
				 * need to split the map. We enter like
				 * so:
				 *  rsm      |--------|
				 *  sackblk       |----->
				 * We will add the new block nrsm and
				 * that will be the new portion, and then
				 * fall through after reseting rsm. So we
				 * split and look like this:
				 *  rsm      |----|
				 *  sackblk       |----->
				 *  nrsm          |---|
				 * We then fall through reseting
				 * rsm to nrsm, so the next block
				 * picks it up.
				 */
				nrsm = rack_alloc_limit(rack, RACK_LIMIT_TYPE_SPLIT);
				if (nrsm == NULL) {
					/*
					 * failed XXXrrs what can we do but loose the sack
					 * info?
					 */
					goto out;
				}
				counter_u64_add(rack_sack_splits, 1);
				rack_clone_rsm(rack, nrsm, rsm, start);
				rsm->r_just_ret = 0;
				insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm);
#ifdef INVARIANTS
				if (insret != NULL) {
					panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
					      nrsm, insret, rack, rsm);
				}
#endif
				if (rsm->r_in_tmap) {
					TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
					nrsm->r_in_tmap = 1;
				}
				rsm->r_flags &= (~RACK_HAS_FIN);
				/* Position us to point to the new nrsm that starts the sack blk */
				rsm = nrsm;
			}
		} else {
			/* Already sacked this piece */
			counter_u64_add(rack_sack_skipped_acked, 1);
			moved++;
			if (end == rsm->r_end) {
				/* Done with block */
				rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
				goto out;
			} else if (SEQ_LT(end, rsm->r_end)) {
				/* A partial sack to a already sacked block */
				moved++;
				rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
				goto out;
			} else {
				/*
				 * The end goes beyond this guy
				 * repostion the start to the
				 * next block.
				 */
				start = rsm->r_end;
				rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
				if (rsm == NULL)
					goto out;
			}
		}
	}
	if (SEQ_GEQ(end, rsm->r_end)) {
		/**
		 * The end of this block is either beyond this guy or right
		 * at this guy. I.e.:
		 *  rsm ---                 |-----|
		 *  end                     |-----|
		 *  <or>
		 *  end                     |---------|
		 */
		if ((rsm->r_flags & RACK_ACKED) == 0) {
			rack_update_rtt(tp, rack, rsm, to, cts, SACKED, 0);
			changed += (rsm->r_end - rsm->r_start);
			rack->r_ctl.rc_sacked += (rsm->r_end - rsm->r_start);
			if (rsm->r_in_tmap) /* should be true */
				rack_log_sack_passed(tp, rack, rsm);
			/* Is Reordering occuring? */
			if (rsm->r_flags & RACK_SACK_PASSED) {
				rsm->r_flags &= ~RACK_SACK_PASSED;
				counter_u64_add(rack_reorder_seen, 1);
				rack->r_ctl.rc_reorder_ts = cts;
			}
			if (rack->app_limited_needs_set)
				rack_need_set_test(tp, rack, rsm, tp->snd_una, __LINE__, RACK_USE_END);
			rsm->r_ack_arrival = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
			rsm->r_flags |= RACK_ACKED;
			rsm->r_flags &= ~RACK_TLP;
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
		} else {
			counter_u64_add(rack_sack_skipped_acked, 1);
			moved++;
		}
		if (end == rsm->r_end) {
			/* This block only - done, setup for next  */
			goto out;
		}
		/*
		 * There is more not coverend by this rsm move on
		 * to the next block in the RB tree.
		 */
		nrsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
		start = rsm->r_end;
		rsm = nrsm;
		if (rsm == NULL)
			goto out;
		goto do_rest_ofb;
	}
	/**
	 * The end of this sack block is smaller than
	 * our rsm i.e.:
	 *  rsm ---                 |-----|
	 *  end                     |--|
	 */
	if ((rsm->r_flags & RACK_ACKED) == 0) {
		prev = RB_PREV(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
		if (prev && (prev->r_flags & RACK_ACKED)) {
			/**
			 * Goal, we want the right remainder of rsm to shrink
			 * in place and span from (rsm->r_start = end) to rsm->r_end.
			 * We want to expand prev to go all the way
			 * to prev->r_end <- end.
			 * so in the tree we have before:
			 *   prev     |--------|         (acked)
			 *   rsm               |-------| (non-acked)
			 *   sackblk           |-|
			 * We churn it so we end up with
			 *   prev     |----------|       (acked)
			 *   rsm                 |-----| (non-acked)
			 *   nrsm              |-| (temporary)
			 */
			nrsm = &stack_map;
			memcpy(nrsm, rsm, sizeof(struct rack_sendmap));
			prev->r_end = end;
			rsm->r_start = end;
			/* Now adjust nrsm (stack copy) to be
			 * the one that is the small
			 * piece that was "sacked".
			 */
			nrsm->r_end = end;
			rsm->r_dupack = 0;
			rack_log_retran_reason(rack, rsm, __LINE__, 0, 2);
			/*
			 * Now nrsm is our new little piece
			 * that is acked (which was merged
			 * to prev). Update the rtt and changed
			 * based on that. Also check for reordering.
			 */
			rack_update_rtt(tp, rack, nrsm, to, cts, SACKED, 0);
			if (rack->app_limited_needs_set)
				rack_need_set_test(tp, rack, nrsm, tp->snd_una, __LINE__, RACK_USE_END);
			changed += (nrsm->r_end - nrsm->r_start);
			rack->r_ctl.rc_sacked += (nrsm->r_end - nrsm->r_start);
			if (nrsm->r_flags & RACK_SACK_PASSED) {
				counter_u64_add(rack_reorder_seen, 1);
				rack->r_ctl.rc_reorder_ts = cts;
			}
			rsm = prev;
			counter_u64_add(rack_sack_used_prev_merge, 1);
		} else {
			/**
			 * This is the case where our previous
			 * block is not acked either, so we must
			 * split the block in two.
			 */
			nrsm = rack_alloc_limit(rack, RACK_LIMIT_TYPE_SPLIT);
			if (nrsm == NULL) {
				/* failed rrs what can we do but loose the sack info? */
				goto out;
			}
			/**
			 * In this case nrsm becomes
			 * nrsm->r_start = end;
			 * nrsm->r_end = rsm->r_end;
			 * which is un-acked.
			 * <and>
			 * rsm->r_end = nrsm->r_start;
			 * i.e. the remaining un-acked
			 * piece is left on the left
			 * hand side.
			 *
			 * So we start like this
			 * rsm      |----------| (not acked)
			 * sackblk  |---|
			 * build it so we have
			 * rsm      |---|         (acked)
			 * nrsm         |------|  (not acked)
			 */
			counter_u64_add(rack_sack_splits, 1);
			rack_clone_rsm(rack, nrsm, rsm, end);
			rsm->r_flags &= (~RACK_HAS_FIN);
			rsm->r_just_ret = 0;
			insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm);
#ifdef INVARIANTS
			if (insret != NULL) {
				panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
				      nrsm, insret, rack, rsm);
			}
#endif
			if (rsm->r_in_tmap) {
				TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
				nrsm->r_in_tmap = 1;
			}
			nrsm->r_dupack = 0;
			rack_log_retran_reason(rack, nrsm, __LINE__, 0, 2);
			rack_update_rtt(tp, rack, rsm, to, cts, SACKED, 0);
			changed += (rsm->r_end - rsm->r_start);
			rack->r_ctl.rc_sacked += (rsm->r_end - rsm->r_start);
			if (rsm->r_in_tmap) /* should be true */
				rack_log_sack_passed(tp, rack, rsm);
			/* Is Reordering occuring? */
			if (rsm->r_flags & RACK_SACK_PASSED) {
				rsm->r_flags &= ~RACK_SACK_PASSED;
				counter_u64_add(rack_reorder_seen, 1);
				rack->r_ctl.rc_reorder_ts = cts;
			}
			if (rack->app_limited_needs_set)
				rack_need_set_test(tp, rack, rsm, tp->snd_una, __LINE__, RACK_USE_END);
			rsm->r_ack_arrival = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
			rsm->r_flags |= RACK_ACKED;
			rsm->r_flags &= ~RACK_TLP;
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
		}
	} else if (start != end){
		/*
		 * The block was already acked.
		 */
		counter_u64_add(rack_sack_skipped_acked, 1);
		moved++;
	}
out:
	if (rsm && (rsm->r_flags & RACK_ACKED)) {
		/*
		 * Now can we merge where we worked
		 * with either the previous or
		 * next block?
		 */
		next = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
		while (next) {
		    if (next->r_flags & RACK_ACKED) {
			/* yep this and next can be merged */
			rsm = rack_merge_rsm(rack, rsm, next);
			next = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
		    } else
			    break;
		}
		/* Now what about the previous? */
		prev = RB_PREV(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
		while (prev) {
		    if (prev->r_flags & RACK_ACKED) {
			/* yep the previous and this can be merged */
			rsm = rack_merge_rsm(rack, prev, rsm);
			prev = RB_PREV(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
		    } else
			    break;
		}
	}
	if (used_ref == 0) {
		counter_u64_add(rack_sack_proc_all, 1);
	} else {
		counter_u64_add(rack_sack_proc_short, 1);
	}
	/* Save off the next one for quick reference. */
	if (rsm)
		nrsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
	else
		nrsm = NULL;
	*prsm = rack->r_ctl.rc_sacklast = nrsm;
	/* Pass back the moved. */
	*moved_two = moved;
	return (changed);
}

static void inline
rack_peer_reneges(struct tcp_rack *rack, struct rack_sendmap *rsm, tcp_seq th_ack)
{
	struct rack_sendmap *tmap;

	tmap = NULL;
	while (rsm && (rsm->r_flags & RACK_ACKED)) {
		/* Its no longer sacked, mark it so */
		rack->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
#ifdef INVARIANTS
		if (rsm->r_in_tmap) {
			panic("rack:%p rsm:%p flags:0x%x in tmap?",
			      rack, rsm, rsm->r_flags);
		}
#endif
		rsm->r_flags &= ~(RACK_ACKED|RACK_SACK_PASSED|RACK_WAS_SACKPASS);
		/* Rebuild it into our tmap */
		if (tmap == NULL) {
			TAILQ_INSERT_HEAD(&rack->r_ctl.rc_tmap, rsm, r_tnext);
			tmap = rsm;
		} else {
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, tmap, rsm, r_tnext);
			tmap = rsm;
		}
		tmap->r_in_tmap = 1;
		rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
	}
	/*
	 * Now lets possibly clear the sack filter so we start
	 * recognizing sacks that cover this area.
	 */
	sack_filter_clear(&rack->r_ctl.rack_sf, th_ack);

}

static void
rack_do_decay(struct tcp_rack *rack)
{
	struct timeval res;

#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)

	timersub(&rack->r_ctl.act_rcv_time, &rack->r_ctl.rc_last_time_decay, &res);
#undef timersub

	rack->r_ctl.input_pkt++;
	if ((rack->rc_in_persist) ||
	    (res.tv_sec >= 1) ||
	    (rack->rc_tp->snd_max == rack->rc_tp->snd_una)) {
		/*
		 * Check for decay of non-SAD,
		 * we want all SAD detection metrics to
		 * decay 1/4 per second (or more) passed.
		 */
		uint32_t pkt_delta;

		pkt_delta = rack->r_ctl.input_pkt - rack->r_ctl.saved_input_pkt;
		/* Update our saved tracking values */
		rack->r_ctl.saved_input_pkt = rack->r_ctl.input_pkt;
		rack->r_ctl.rc_last_time_decay = rack->r_ctl.act_rcv_time;
		/* Now do we escape without decay? */
#ifdef NETFLIX_EXP_DETECTION
		if (rack->rc_in_persist ||
		    (rack->rc_tp->snd_max == rack->rc_tp->snd_una) ||
		    (pkt_delta < tcp_sad_low_pps)){
			/*
			 * We don't decay idle connections
			 * or ones that have a low input pps.
			 */
			return;
		}
		/* Decay the counters */
		rack->r_ctl.ack_count = ctf_decay_count(rack->r_ctl.ack_count,
							tcp_sad_decay_val);
		rack->r_ctl.sack_count = ctf_decay_count(rack->r_ctl.sack_count,
							 tcp_sad_decay_val);
		rack->r_ctl.sack_moved_extra = ctf_decay_count(rack->r_ctl.sack_moved_extra,
							       tcp_sad_decay_val);
		rack->r_ctl.sack_noextra_move = ctf_decay_count(rack->r_ctl.sack_noextra_move,
								tcp_sad_decay_val);
#endif
	}
}

static void
rack_log_ack(struct tcpcb *tp, struct tcpopt *to, struct tcphdr *th)
{
	uint32_t changed, entered_recovery = 0;
	struct tcp_rack *rack;
	struct rack_sendmap *rsm, *rm;
	struct sackblk sack, sack_blocks[TCP_MAX_SACK + 1];
	register uint32_t th_ack;
	int32_t i, j, k, num_sack_blks = 0;
	uint32_t cts, acked, ack_point, sack_changed = 0;
	int loop_start = 0, moved_two = 0;
	uint32_t tsused;


	INP_WLOCK_ASSERT(tp->t_inpcb);
	if (th->th_flags & TH_RST) {
		/* We don't log resets */
		return;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	cts = tcp_ts_getticks();
	rsm = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
	changed = 0;
	th_ack = th->th_ack;
	if (rack->sack_attack_disable == 0)
		rack_do_decay(rack);
	if (BYTES_THIS_ACK(tp, th) >= ctf_fixed_maxseg(rack->rc_tp)) {
		/*
		 * You only get credit for
		 * MSS and greater (and you get extra
		 * credit for larger cum-ack moves).
		 */
		int ac;

		ac = BYTES_THIS_ACK(tp, th) / ctf_fixed_maxseg(rack->rc_tp);
		rack->r_ctl.ack_count += ac;
		counter_u64_add(rack_ack_total, ac);
	}
	if (rack->r_ctl.ack_count > 0xfff00000) {
		/*
		 * reduce the number to keep us under
		 * a uint32_t.
		 */
		rack->r_ctl.ack_count /= 2;
		rack->r_ctl.sack_count /= 2;
	}
	if (SEQ_GT(th_ack, tp->snd_una)) {
		rack_log_progress_event(rack, tp, ticks, PROGRESS_UPDATE, __LINE__);
		tp->t_acktime = ticks;
	}
	if (rsm && SEQ_GT(th_ack, rsm->r_start))
		changed = th_ack - rsm->r_start;
	if (changed) {
		/*
		 * The ACK point is advancing to th_ack, we must drop off
		 * the packets in the rack log and calculate any eligble
		 * RTT's.
		 */
		rack->r_wanted_output = 1;
more:
		rsm = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
		if (rsm == NULL) {
			if ((th_ack - 1) == tp->iss) {
				/*
				 * For the SYN incoming case we will not
				 * have called tcp_output for the sending of
				 * the SYN, so there will be no map. All
				 * other cases should probably be a panic.
				 */
				goto proc_sack;
			}
			if (tp->t_flags & TF_SENTFIN) {
				/* if we send a FIN we will not hav a map */
				goto proc_sack;
			}
#ifdef INVARIANTS
			panic("No rack map tp:%p for th:%p state:%d rack:%p snd_una:%u snd_max:%u snd_nxt:%u chg:%d\n",
			      tp,
			      th, tp->t_state, rack,
			      tp->snd_una, tp->snd_max, tp->snd_nxt, changed);
#endif
			goto proc_sack;
		}
		if (SEQ_LT(th_ack, rsm->r_start)) {
			/* Huh map is missing this */
#ifdef INVARIANTS
			printf("Rack map starts at r_start:%u for th_ack:%u huh? ts:%d rs:%d\n",
			       rsm->r_start,
			       th_ack, tp->t_state, rack->r_state);
#endif
			goto proc_sack;
		}
		rack_update_rtt(tp, rack, rsm, to, cts, CUM_ACKED, th_ack);
		/* Now do we consume the whole thing? */
		if (SEQ_GEQ(th_ack, rsm->r_end)) {
			/* Its all consumed. */
			uint32_t left;
			uint8_t newly_acked;

			rack->r_ctl.rc_holes_rxt -= rsm->r_rtr_bytes;
			rsm->r_rtr_bytes = 0;
			/* Record the time of highest cumack sent */
			rack->r_ctl.rc_gp_cumack_ts = rsm->usec_orig_send;
			rm = RB_REMOVE(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
#ifdef INVARIANTS
			if (rm != rsm) {
				panic("removing head in rack:%p rsm:%p rm:%p",
				      rack, rsm, rm);
			}
#endif
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
			newly_acked = 1;
			if (rsm->r_flags & RACK_ACKED) {
				/*
				 * It was acked on the scoreboard -- remove
				 * it from total
				 */
				rack->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
				newly_acked = 0;
			} else if (rsm->r_flags & RACK_SACK_PASSED) {
				/*
				 * There are segments ACKED on the
				 * scoreboard further up. We are seeing
				 * reordering.
				 */
				rsm->r_flags &= ~RACK_SACK_PASSED;
				counter_u64_add(rack_reorder_seen, 1);
				rsm->r_ack_arrival = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
				rsm->r_flags |= RACK_ACKED;
				rack->r_ctl.rc_reorder_ts = cts;
			}
			left = th_ack - rsm->r_end;
			if (rack->app_limited_needs_set && newly_acked)
				rack_need_set_test(tp, rack, rsm, th_ack, __LINE__, RACK_USE_END_OR_THACK);
			/* Free back to zone */
			rack_free(rack, rsm);
			if (left) {
				goto more;
			}
			goto proc_sack;
		}
		if (rsm->r_flags & RACK_ACKED) {
			/*
			 * It was acked on the scoreboard -- remove it from
			 * total for the part being cum-acked.
			 */
			rack->r_ctl.rc_sacked -= (th_ack - rsm->r_start);
		}
		/*
		 * Clear the dup ack count for
		 * the piece that remains.
		 */
		rsm->r_dupack = 0;
		rack_log_retran_reason(rack, rsm, __LINE__, 0, 2);
		if (rsm->r_rtr_bytes) {
			/*
			 * It was retransmitted adjust the
			 * sack holes for what was acked.
			 */
			int ack_am;

			ack_am = (th_ack - rsm->r_start);
			if (ack_am >= rsm->r_rtr_bytes) {
				rack->r_ctl.rc_holes_rxt -= ack_am;
				rsm->r_rtr_bytes -= ack_am;
			}
		}
		/*
		 * Update where the piece starts and record
		 * the time of send of highest cumack sent.
		 */
		rack->r_ctl.rc_gp_cumack_ts = rsm->usec_orig_send;
		rsm->r_start = th_ack;
		if (rack->app_limited_needs_set)
			rack_need_set_test(tp, rack, rsm, tp->snd_una, __LINE__, RACK_USE_BEG);

	}
proc_sack:
	/* Check for reneging */
	rsm = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
	if (rsm && (rsm->r_flags & RACK_ACKED) && (th_ack == rsm->r_start)) {
		/*
		 * The peer has moved snd_una up to
		 * the edge of this send, i.e. one
		 * that it had previously acked. The only
		 * way that can be true if the peer threw
		 * away data (space issues) that it had
		 * previously sacked (else it would have
		 * given us snd_una up to (rsm->r_end).
		 * We need to undo the acked markings here.
		 *
		 * Note we have to look to make sure th_ack is
		 * our rsm->r_start in case we get an old ack
		 * where th_ack is behind snd_una.
		 */
		rack_peer_reneges(rack, rsm, th->th_ack);
	}
	if ((to->to_flags & TOF_SACK) == 0) {
		/* We are done nothing left */
		goto out;
	}
	/* Sack block processing */
	if (SEQ_GT(th_ack, tp->snd_una))
		ack_point = th_ack;
	else
		ack_point = tp->snd_una;
	for (i = 0; i < to->to_nsacks; i++) {
		bcopy((to->to_sacks + i * TCPOLEN_SACK),
		      &sack, sizeof(sack));
		sack.start = ntohl(sack.start);
		sack.end = ntohl(sack.end);
		if (SEQ_GT(sack.end, sack.start) &&
		    SEQ_GT(sack.start, ack_point) &&
		    SEQ_LT(sack.start, tp->snd_max) &&
		    SEQ_GT(sack.end, ack_point) &&
		    SEQ_LEQ(sack.end, tp->snd_max)) {
			sack_blocks[num_sack_blks] = sack;
			num_sack_blks++;
#ifdef NETFLIX_STATS
		} else if (SEQ_LEQ(sack.start, th_ack) &&
			   SEQ_LEQ(sack.end, th_ack)) {
			/*
			 * Its a D-SACK block.
			 */
			tcp_record_dsack(sack.start, sack.end);
#endif
		}

	}
	/*
	 * Sort the SACK blocks so we can update the rack scoreboard with
	 * just one pass.
	 */
	num_sack_blks = sack_filter_blks(&rack->r_ctl.rack_sf, sack_blocks,
					 num_sack_blks, th->th_ack);
	ctf_log_sack_filter(rack->rc_tp, num_sack_blks, sack_blocks);
	if (num_sack_blks == 0)  {
		/* Nothing to sack (DSACKs?) */
		goto out_with_totals;
	}
	if (num_sack_blks < 2) {
		/* Only one, we don't need to sort */
		goto do_sack_work;
	}
	/* Sort the sacks */
	for (i = 0; i < num_sack_blks; i++) {
		for (j = i + 1; j < num_sack_blks; j++) {
			if (SEQ_GT(sack_blocks[i].end, sack_blocks[j].end)) {
				sack = sack_blocks[i];
				sack_blocks[i] = sack_blocks[j];
				sack_blocks[j] = sack;
			}
		}
	}
	/*
	 * Now are any of the sack block ends the same (yes some
	 * implementations send these)?
	 */
again:
	if (num_sack_blks == 0)
		goto out_with_totals;
	if (num_sack_blks > 1) {
		for (i = 0; i < num_sack_blks; i++) {
			for (j = i + 1; j < num_sack_blks; j++) {
				if (sack_blocks[i].end == sack_blocks[j].end) {
					/*
					 * Ok these two have the same end we
					 * want the smallest end and then
					 * throw away the larger and start
					 * again.
					 */
					if (SEQ_LT(sack_blocks[j].start, sack_blocks[i].start)) {
						/*
						 * The second block covers
						 * more area use that
						 */
						sack_blocks[i].start = sack_blocks[j].start;
					}
					/*
					 * Now collapse out the dup-sack and
					 * lower the count
					 */
					for (k = (j + 1); k < num_sack_blks; k++) {
						sack_blocks[j].start = sack_blocks[k].start;
						sack_blocks[j].end = sack_blocks[k].end;
						j++;
					}
					num_sack_blks--;
					goto again;
				}
			}
		}
	}
do_sack_work:
	/*
	 * First lets look to see if
	 * we have retransmitted and
	 * can use the transmit next?
	 */
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm &&
	    SEQ_GT(sack_blocks[0].end, rsm->r_start) &&
	    SEQ_LT(sack_blocks[0].start, rsm->r_end)) {
		/*
		 * We probably did the FR and the next
		 * SACK in continues as we would expect.
		 */
		acked = rack_proc_sack_blk(tp, rack, &sack_blocks[0], to, &rsm, cts, &moved_two);
		if (acked) {
			rack->r_wanted_output = 1;
			changed += acked;
			sack_changed += acked;
		}
		if (num_sack_blks == 1) {
			/*
			 * This is what we would expect from
			 * a normal implementation to happen
			 * after we have retransmitted the FR,
			 * i.e the sack-filter pushes down
			 * to 1 block and the next to be retransmitted
			 * is the sequence in the sack block (has more
			 * are acked). Count this as ACK'd data to boost
			 * up the chances of recovering any false positives.
			 */
			rack->r_ctl.ack_count += (acked / ctf_fixed_maxseg(rack->rc_tp));
			counter_u64_add(rack_ack_total, (acked / ctf_fixed_maxseg(rack->rc_tp)));
			counter_u64_add(rack_express_sack, 1);
			if (rack->r_ctl.ack_count > 0xfff00000) {
				/*
				 * reduce the number to keep us under
				 * a uint32_t.
				 */
				rack->r_ctl.ack_count /= 2;
				rack->r_ctl.sack_count /= 2;
			}
			goto out_with_totals;
		} else {
			/*
			 * Start the loop through the
			 * rest of blocks, past the first block.
			 */
			moved_two = 0;
			loop_start = 1;
		}
	}
	/* Its a sack of some sort */
	rack->r_ctl.sack_count++;
	if (rack->r_ctl.sack_count > 0xfff00000) {
		/*
		 * reduce the number to keep us under
		 * a uint32_t.
		 */
		rack->r_ctl.ack_count /= 2;
		rack->r_ctl.sack_count /= 2;
	}
	counter_u64_add(rack_sack_total, 1);
	if (rack->sack_attack_disable) {
		/* An attacker disablement is in place */
		if (num_sack_blks > 1) {
			rack->r_ctl.sack_count += (num_sack_blks - 1);
			rack->r_ctl.sack_moved_extra++;
			counter_u64_add(rack_move_some, 1);
			if (rack->r_ctl.sack_moved_extra > 0xfff00000) {
				rack->r_ctl.sack_moved_extra /= 2;
				rack->r_ctl.sack_noextra_move /= 2;
			}
		}
		goto out;
	}
	rsm = rack->r_ctl.rc_sacklast;
	for (i = loop_start; i < num_sack_blks; i++) {
		acked = rack_proc_sack_blk(tp, rack, &sack_blocks[i], to, &rsm, cts, &moved_two);
		if (acked) {
			rack->r_wanted_output = 1;
			changed += acked;
			sack_changed += acked;
		}
		if (moved_two) {
			/*
			 * If we did not get a SACK for at least a MSS and
			 * had to move at all, or if we moved more than our
			 * threshold, it counts against the "extra" move.
			 */
			rack->r_ctl.sack_moved_extra += moved_two;
			counter_u64_add(rack_move_some, 1);
		} else {
			/*
			 * else we did not have to move
			 * any more than we would expect.
			 */
			rack->r_ctl.sack_noextra_move++;
			counter_u64_add(rack_move_none, 1);
		}
		if (moved_two && (acked < ctf_fixed_maxseg(rack->rc_tp))) {
			/*
			 * If the SACK was not a full MSS then
			 * we add to sack_count the number of
			 * MSS's (or possibly more than
			 * a MSS if its a TSO send) we had to skip by.
			 */
			rack->r_ctl.sack_count += moved_two;
			counter_u64_add(rack_sack_total, moved_two);
		}
		/*
		 * Now we need to setup for the next
		 * round. First we make sure we won't
		 * exceed the size of our uint32_t on
		 * the various counts, and then clear out
		 * moved_two.
		 */
		if ((rack->r_ctl.sack_moved_extra > 0xfff00000) ||
		    (rack->r_ctl.sack_noextra_move > 0xfff00000)) {
			rack->r_ctl.sack_moved_extra /= 2;
			rack->r_ctl.sack_noextra_move /= 2;
		}
		if (rack->r_ctl.sack_count > 0xfff00000) {
			rack->r_ctl.ack_count /= 2;
			rack->r_ctl.sack_count /= 2;
		}
		moved_two = 0;
	}
out_with_totals:
	if (num_sack_blks > 1) {
		/*
		 * You get an extra stroke if
		 * you have more than one sack-blk, this
		 * could be where we are skipping forward
		 * and the sack-filter is still working, or
		 * it could be an attacker constantly
		 * moving us.
		 */
		rack->r_ctl.sack_moved_extra++;
		counter_u64_add(rack_move_some, 1);
	}
out:
#ifdef NETFLIX_EXP_DETECTION
	if ((rack->do_detection || tcp_force_detection) &&
	    tcp_sack_to_ack_thresh &&
	    tcp_sack_to_move_thresh &&
	    ((rack->r_ctl.rc_num_maps_alloced > tcp_map_minimum) || rack->sack_attack_disable)) {
		/*
		 * We have thresholds set to find
		 * possible attackers and disable sack.
		 * Check them.
		 */
		uint64_t ackratio, moveratio, movetotal;

		/* Log detecting */
		rack_log_sad(rack, 1);
		ackratio = (uint64_t)(rack->r_ctl.sack_count);
		ackratio *= (uint64_t)(1000);
		if (rack->r_ctl.ack_count)
			ackratio /= (uint64_t)(rack->r_ctl.ack_count);
		else {
			/* We really should not hit here */
			ackratio = 1000;
		}
		if ((rack->sack_attack_disable  == 0) &&
		    (ackratio > rack_highest_sack_thresh_seen))
			rack_highest_sack_thresh_seen = (uint32_t)ackratio;
		movetotal = rack->r_ctl.sack_moved_extra;
		movetotal += rack->r_ctl.sack_noextra_move;
		moveratio = rack->r_ctl.sack_moved_extra;
		moveratio *= (uint64_t)1000;
		if (movetotal)
			moveratio /= movetotal;
		else {
			/* No moves, thats pretty good */
			moveratio = 0;
		}
		if ((rack->sack_attack_disable == 0) &&
		    (moveratio > rack_highest_move_thresh_seen))
			rack_highest_move_thresh_seen = (uint32_t)moveratio;
		if (rack->sack_attack_disable == 0) {
			if ((ackratio > tcp_sack_to_ack_thresh) &&
			    (moveratio > tcp_sack_to_move_thresh)) {
				/* Disable sack processing */
				rack->sack_attack_disable = 1;
				if (rack->r_rep_attack == 0) {
					rack->r_rep_attack = 1;
					counter_u64_add(rack_sack_attacks_detected, 1);
				}
				if (tcp_attack_on_turns_on_logging) {
					/*
					 * Turn on logging, used for debugging
					 * false positives.
					 */
					rack->rc_tp->t_logstate = tcp_attack_on_turns_on_logging;
				}
				/* Clamp the cwnd at flight size */
				rack->r_ctl.rc_saved_cwnd = rack->rc_tp->snd_cwnd;
				rack->rc_tp->snd_cwnd = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
				rack_log_sad(rack, 2);
			}
		} else {
			/* We are sack-disabled check for false positives */
			if ((ackratio <= tcp_restoral_thresh) ||
			    (rack->r_ctl.rc_num_maps_alloced  < tcp_map_minimum)) {
				rack->sack_attack_disable  = 0;
				rack_log_sad(rack, 3);
				/* Restart counting */
				rack->r_ctl.sack_count = 0;
				rack->r_ctl.sack_moved_extra = 0;
				rack->r_ctl.sack_noextra_move = 1;
				rack->r_ctl.ack_count = max(1,
				      (BYTES_THIS_ACK(tp, th)/ctf_fixed_maxseg(rack->rc_tp)));

				if (rack->r_rep_reverse == 0) {
					rack->r_rep_reverse = 1;
					counter_u64_add(rack_sack_attacks_reversed, 1);
				}
				/* Restore the cwnd */
				if (rack->r_ctl.rc_saved_cwnd > rack->rc_tp->snd_cwnd)
					rack->rc_tp->snd_cwnd = rack->r_ctl.rc_saved_cwnd;
			}
		}
	}
#endif
	if (changed) {
		/* Something changed cancel the rack timer */
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
	}
	tsused = tcp_ts_getticks();
	rsm = tcp_rack_output(tp, rack, tsused);
	if ((!IN_RECOVERY(tp->t_flags)) &&
	    rsm) {
		/* Enter recovery */
		rack->r_ctl.rc_rsm_start = rsm->r_start;
		rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
		rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
		entered_recovery = 1;
		rack_cong_signal(tp, NULL, CC_NDUPACK);
		/*
		 * When we enter recovery we need to assure we send
		 * one packet.
		 */
		if (rack->rack_no_prr == 0) {
			rack->r_ctl.rc_prr_sndcnt = ctf_fixed_maxseg(tp);
			rack_log_to_prr(rack, 8, 0);
		}
		rack->r_timer_override = 1;
		rack->r_early = 0;
		rack->r_ctl.rc_agg_early = 0;
	} else if (IN_RECOVERY(tp->t_flags) &&
		   rsm &&
 		   (rack->r_rr_config == 3)) {
		/*
		 * Assure we can output and we get no
		 * remembered pace time except the retransmit.
		 */
		rack->r_timer_override = 1;
		rack->r_ctl.rc_hpts_flags &= ~PACE_PKT_OUTPUT;
		rack->r_ctl.rc_resend = rsm;
	}
	if (IN_RECOVERY(tp->t_flags) &&
	    (rack->rack_no_prr == 0) &&
	    (entered_recovery == 0)) {
		/* Deal with PRR here (in recovery only) */
		uint32_t pipe, snd_una;

		rack->r_ctl.rc_prr_delivered += changed;
		/* Compute prr_sndcnt */
		if (SEQ_GT(tp->snd_una, th_ack)) {
			snd_una = tp->snd_una;
		} else {
			snd_una = th_ack;
		}
		pipe = ((tp->snd_max - snd_una) - rack->r_ctl.rc_sacked) + rack->r_ctl.rc_holes_rxt;
		if (pipe > tp->snd_ssthresh) {
			long sndcnt;

			sndcnt = rack->r_ctl.rc_prr_delivered * tp->snd_ssthresh;
			if (rack->r_ctl.rc_prr_recovery_fs > 0)
				sndcnt /= (long)rack->r_ctl.rc_prr_recovery_fs;
			else {
				rack->r_ctl.rc_prr_sndcnt = 0;
				rack_log_to_prr(rack, 9, 0);
				sndcnt = 0;
			}
			sndcnt++;
			if (sndcnt > (long)rack->r_ctl.rc_prr_out)
				sndcnt -= rack->r_ctl.rc_prr_out;
			else
				sndcnt = 0;
			rack->r_ctl.rc_prr_sndcnt = sndcnt;
			rack_log_to_prr(rack, 10, 0);
		} else {
			uint32_t limit;

			if (rack->r_ctl.rc_prr_delivered > rack->r_ctl.rc_prr_out)
				limit = (rack->r_ctl.rc_prr_delivered - rack->r_ctl.rc_prr_out);
			else
				limit = 0;
			if (changed > limit)
				limit = changed;
			limit += ctf_fixed_maxseg(tp);
			if (tp->snd_ssthresh > pipe) {
				rack->r_ctl.rc_prr_sndcnt = min((tp->snd_ssthresh - pipe), limit);
				rack_log_to_prr(rack, 11, 0);
			} else {
				rack->r_ctl.rc_prr_sndcnt = min(0, limit);
				rack_log_to_prr(rack, 12, 0);
			}
		}
		if ((rsm && (rack->r_ctl.rc_prr_sndcnt >= ctf_fixed_maxseg(tp)) &&
		     ((rack->rc_inp->inp_in_hpts == 0) &&
		      ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0)))) {
			/*
			 * If you are pacing output you don't want
			 * to override.
			 */
			rack->r_early = 0;
			rack->r_ctl.rc_agg_early = 0;
			rack->r_timer_override = 1;
		}
	}
}

static void
rack_strike_dupack(struct tcp_rack *rack)
{
	struct rack_sendmap *rsm;

	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm && (rsm->r_dupack < 0xff)) {
		rsm->r_dupack++;
		if (rsm->r_dupack >= DUP_ACK_THRESHOLD) {
			rack->r_wanted_output = 1;
			rack_log_retran_reason(rack, rsm, __LINE__, 1, 3);
		} else {
			rack_log_retran_reason(rack, rsm, __LINE__, 0, 3);
		}
	}
}

static void
rack_check_bottom_drag(struct tcpcb *tp,
		       struct tcp_rack *rack,
		       struct socket *so, int32_t acked)
{
	uint32_t segsiz, minseg;

	segsiz = ctf_fixed_maxseg(tp);
	if (so->so_snd.sb_flags & SB_TLS_IFNET) {
		minseg = rack->r_ctl.rc_pace_min_segs;
	} else {
		minseg = segsiz;
	}
	if (tp->snd_max == tp->snd_una) {
		/*
		 * We are doing dynamic pacing and we are way
		 * under. Basically everything got acked while
		 * we were still waiting on the pacer to expire.
		 *
		 * This means we need to boost the b/w in
		 * addition to any earlier boosting of
		 * the multipler.
		 */
		rack->rc_dragged_bottom = 1;
		rack_validate_multipliers_at_or_above100(rack);
		/*
		 * Lets use the segment bytes acked plus
		 * the lowest RTT seen as the basis to
		 * form a b/w estimate. This will be off
		 * due to the fact that the true estimate
		 * should be around 1/2 the time of the RTT
		 * but we can settle for that.
		 */
		if ((rack->r_ctl.rack_rs.rs_flags & RACK_RTT_VALID) &&
		    acked) {
			uint64_t bw, calc_bw, rtt;

			rtt = rack->r_ctl.rack_rs.rs_us_rtt;
			bw = acked;
			calc_bw = bw * 1000000;
			calc_bw /= rtt;
			if (rack->r_ctl.last_max_bw &&
			    (rack->r_ctl.last_max_bw < calc_bw)) {
				/*
				 * If we have a last calculated max bw
				 * enforce it.
				 */
				calc_bw = rack->r_ctl.last_max_bw;
			}
			/* now plop it in */
			if (rack->rc_gp_filled == 0) {
				if (calc_bw > ONE_POINT_TWO_MEG) {
					/*
					 * If we have no measurement
					 * don't let us set in more than
					 * 1.2Mbps. If we are still too
					 * low after pacing with this we
					 * will hopefully have a max b/w
					 * available to sanity check things.
					 */
					calc_bw = ONE_POINT_TWO_MEG;
				}
				rack->r_ctl.rc_rtt_diff = 0;
				rack->r_ctl.gp_bw = calc_bw;
				rack->rc_gp_filled = 1;
				rack->r_ctl.num_avg = RACK_REQ_AVG;
				rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
			} else if (calc_bw > rack->r_ctl.gp_bw) {
				rack->r_ctl.rc_rtt_diff = 0;
				rack->r_ctl.num_avg = RACK_REQ_AVG;
				rack->r_ctl.gp_bw = calc_bw;
				rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
			} else
				rack_increase_bw_mul(rack, -1, 0, 0, 1);
			/*
			 * For acks over 1mss we do a extra boost to simulate
			 * where we would get 2 acks (we want 110 for the mul).
			 */
			if (acked > segsiz)
				rack_increase_bw_mul(rack, -1, 0, 0, 1);
		} else {
			/*
			 * Huh, this should not be, settle
			 * for just an old increase.
			 */
			rack_increase_bw_mul(rack, -1, 0, 0, 1);
		}
	} else if ((IN_RECOVERY(tp->t_flags) == 0) &&
		   (sbavail(&so->so_snd) > max((segsiz * (4 + rack_req_segs)),
					       minseg)) &&
		   (rack->r_ctl.cwnd_to_use > max((segsiz * (rack_req_segs + 2)), minseg)) &&
		   (tp->snd_wnd > max((segsiz * (rack_req_segs + 2)), minseg)) &&
		   (ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked) <=
		    (segsiz * rack_req_segs))) {
		/*
		 * We are doing dynamic GP pacing and
		 * we have everything except 1MSS or less
		 * bytes left out. We are still pacing away.
		 * And there is data that could be sent, This
		 * means we are inserting delayed ack time in
		 * our measurements because we are pacing too slow.
		 */
		rack_validate_multipliers_at_or_above100(rack);
		rack->rc_dragged_bottom = 1;
		rack_increase_bw_mul(rack, -1, 0, 0, 1);
	}
}

/*
 * Return value of 1, we do not need to call rack_process_data().
 * return value of 0, rack_process_data can be called.
 * For ret_val if its 0 the TCP is locked, if its non-zero
 * its unlocked and probably unsafe to touch the TCB.
 */
static int
rack_process_ack(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to,
    uint32_t tiwin, int32_t tlen,
    int32_t * ofia, int32_t thflags, int32_t * ret_val)
{
	int32_t ourfinisacked = 0;
	int32_t nsegs, acked_amount;
	int32_t acked;
	struct mbuf *mfree;
	struct tcp_rack *rack;
	int32_t under_pacing = 0;
	int32_t recovery = 0;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (SEQ_GT(th->th_ack, tp->snd_max)) {
		ctf_do_dropafterack(m, tp, th, thflags, tlen, ret_val);
		rack->r_wanted_output = 1;
		return (1);
	}
	if (rack->rc_gp_filled &&
	    (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {
		under_pacing = 1;
	}
	if (SEQ_GEQ(th->th_ack, tp->snd_una) || to->to_nsacks) {
		if (rack->rc_in_persist)
			tp->t_rxtshift = 0;
		if ((th->th_ack == tp->snd_una) && (tiwin == tp->snd_wnd))
			rack_strike_dupack(rack);
		rack_log_ack(tp, to, th);
	}
	if (__predict_false(SEQ_LEQ(th->th_ack, tp->snd_una))) {
		/*
		 * Old ack, behind (or duplicate to) the last one rcv'd
		 * Note: Should mark reordering is occuring! We should also
		 * look for sack blocks arriving e.g. ack 1, 4-4 then ack 1,
		 * 3-3, 4-4 would be reording. As well as ack 1, 3-3 <no
		 * retran and> ack 3
		 */
		return (0);
	}
	/*
	 * If we reach this point, ACK is not a duplicate, i.e., it ACKs
	 * something we sent.
	 */
	if (tp->t_flags & TF_NEEDSYN) {
		/*
		 * T/TCP: Connection was half-synchronized, and our SYN has
		 * been ACK'd (so connection is now fully synchronized).  Go
		 * to non-starred state, increment snd_una for ACK of SYN,
		 * and check if we can do window scaling.
		 */
		tp->t_flags &= ~TF_NEEDSYN;
		tp->snd_una++;
		/* Do window scaling? */
		if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
		    (TF_RCVD_SCALE | TF_REQ_SCALE)) {
			tp->rcv_scale = tp->request_r_scale;
			/* Send window already scaled. */
		}
	}
	nsegs = max(1, m->m_pkthdr.lro_nsegs);
	INP_WLOCK_ASSERT(tp->t_inpcb);

	acked = BYTES_THIS_ACK(tp, th);
	KMOD_TCPSTAT_ADD(tcps_rcvackpack, nsegs);
	KMOD_TCPSTAT_ADD(tcps_rcvackbyte, acked);
	/*
	 * If we just performed our first retransmit, and the ACK arrives
	 * within our recovery window, then it was a mistake to do the
	 * retransmit in the first place.  Recover our original cwnd and
	 * ssthresh, and proceed to transmit where we left off.
	 */
	if (tp->t_flags & TF_PREVVALID) {
		tp->t_flags &= ~TF_PREVVALID;
		if (tp->t_rxtshift == 1 &&
		    (int)(ticks - tp->t_badrxtwin) < 0)
			rack_cong_signal(tp, th, CC_RTO_ERR);
	}
	if (acked) {
		/* assure we are not backed off */
		tp->t_rxtshift = 0;
		rack->rc_tlp_in_progress = 0;
		rack->r_ctl.rc_tlp_cnt_out = 0;
		/*
		 * If it is the RXT timer we want to
		 * stop it, so we can restart a TLP.
		 */
		if (rack->r_ctl.rc_hpts_flags & PACE_TMR_RXT)
			rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
#ifdef NETFLIX_HTTP_LOGGING
		tcp_http_check_for_comp(rack->rc_tp, th->th_ack);
#endif
	}
	/*
	 * If we have a timestamp reply, update smoothed round trip time. If
	 * no timestamp is present but transmit timer is running and timed
	 * sequence number was acked, update smoothed round trip time. Since
	 * we now have an rtt measurement, cancel the timer backoff (cf.,
	 * Phil Karn's retransmit alg.). Recompute the initial retransmit
	 * timer.
	 *
	 * Some boxes send broken timestamp replies during the SYN+ACK
	 * phase, ignore timestamps of 0 or we could calculate a huge RTT
	 * and blow up the retransmit timer.
	 */
	/*
	 * If all outstanding data is acked, stop retransmit timer and
	 * remember to restart (more output or persist). If there is more
	 * data to be acked, restart retransmit timer, using current
	 * (possibly backed-off) value.
	 */
	if (acked == 0) {
		if (ofia)
			*ofia = ourfinisacked;
		return (0);
	}
	if (rack->r_ctl.rc_early_recovery) {
		if (IN_RECOVERY(tp->t_flags)) {
			if (SEQ_LT(th->th_ack, tp->snd_recover) &&
			    (SEQ_LT(th->th_ack, tp->snd_max))) {
				tcp_rack_partialack(tp, th);
			} else {
				rack_post_recovery(tp, th);
				recovery = 1;
			}
		}
	}
	/*
	 * Let the congestion control algorithm update congestion control
	 * related information. This typically means increasing the
	 * congestion window.
	 */
	rack_ack_received(tp, rack, th, nsegs, CC_ACK, recovery);
	SOCKBUF_LOCK(&so->so_snd);
	acked_amount = min(acked, (int)sbavail(&so->so_snd));
	tp->snd_wnd -= acked_amount;
	mfree = sbcut_locked(&so->so_snd, acked_amount);
	if ((sbused(&so->so_snd) == 0) &&
	    (acked > acked_amount) &&
	    (tp->t_state >= TCPS_FIN_WAIT_1) &&
	    (tp->t_flags & TF_SENTFIN)) {
		/*
		 * We must be sure our fin
		 * was sent and acked (we can be
		 * in FIN_WAIT_1 without having
		 * sent the fin).
		 */
		ourfinisacked = 1;
	}
	/* NB: sowwakeup_locked() does an implicit unlock. */
	sowwakeup_locked(so);
	m_freem(mfree);
	if (rack->r_ctl.rc_early_recovery == 0) {
		if (IN_RECOVERY(tp->t_flags)) {
			if (SEQ_LT(th->th_ack, tp->snd_recover) &&
			    (SEQ_LT(th->th_ack, tp->snd_max))) {
				tcp_rack_partialack(tp, th);
			} else {
				rack_post_recovery(tp, th);
			}
		}
	}
	tp->snd_una = th->th_ack;
	if (SEQ_GT(tp->snd_una, tp->snd_recover))
		tp->snd_recover = tp->snd_una;

	if (SEQ_LT(tp->snd_nxt, tp->snd_una)) {
		tp->snd_nxt = tp->snd_una;
	}
	if (under_pacing &&
	    (rack->use_fixed_rate == 0) &&
	    (rack->in_probe_rtt == 0) &&
	    rack->rc_gp_dyn_mul &&
	    rack->rc_always_pace) {
		/* Check if we are dragging bottom */
		rack_check_bottom_drag(tp, rack, so, acked);
	}
	if (tp->snd_una == tp->snd_max) {
		/* Nothing left outstanding */
		rack->r_ctl.rc_went_idle_time = tcp_get_usecs(NULL);
		if (rack->r_ctl.rc_went_idle_time == 0)
			rack->r_ctl.rc_went_idle_time = 1;
		rack_log_progress_event(rack, tp, 0, PROGRESS_CLEAR, __LINE__);
		if (sbavail(&tp->t_inpcb->inp_socket->so_snd) == 0)
			tp->t_acktime = 0;
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
		/* Set need output so persist might get set */
		rack->r_wanted_output = 1;
		sack_filter_clear(&rack->r_ctl.rack_sf, tp->snd_una);
		if ((tp->t_state >= TCPS_FIN_WAIT_1) &&
		    (sbavail(&so->so_snd) == 0) &&
		    (tp->t_flags2 & TF2_DROP_AF_DATA)) {
			/*
			 * The socket was gone and the
			 * peer sent data, time to
			 * reset him.
			 */
			*ret_val = 1;
			/* tcp_close will kill the inp pre-log the Reset */
			tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_RST);
			tp = tcp_close(tp);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_UNLIMITED, tlen);
			return (1);

		}
	}
	if (ofia)
		*ofia = ourfinisacked;
	return (0);
}

static void
rack_collapsed_window(struct tcp_rack *rack)
{
	/*
	 * Now we must walk the
	 * send map and divide the
	 * ones left stranded. These
	 * guys can't cause us to abort
	 * the connection and are really
	 * "unsent". However if a buggy
	 * client actually did keep some
	 * of the data i.e. collapsed the win
	 * and refused to ack and then opened
	 * the win and acked that data. We would
	 * get into an ack war, the simplier
	 * method then of just pretending we
	 * did not send those segments something
	 * won't work.
	 */
	struct rack_sendmap *rsm, *nrsm, fe, *insret;
	tcp_seq max_seq;

	max_seq = rack->rc_tp->snd_una + rack->rc_tp->snd_wnd;
	memset(&fe, 0, sizeof(fe));
	fe.r_start = max_seq;
	/* Find the first seq past or at maxseq */
	rsm = RB_FIND(rack_rb_tree_head, &rack->r_ctl.rc_mtree, &fe);
	if (rsm == NULL) {
		/* Nothing to do strange */
		rack->rc_has_collapsed = 0;
		return;
	}
	/*
	 * Now do we need to split at
	 * the collapse point?
	 */
	if (SEQ_GT(max_seq, rsm->r_start)) {
		nrsm = rack_alloc_limit(rack, RACK_LIMIT_TYPE_SPLIT);
		if (nrsm == NULL) {
			/* We can't get a rsm, mark all? */
			nrsm = rsm;
			goto no_split;
		}
		/* Clone it */
		rack_clone_rsm(rack, nrsm, rsm, max_seq);
		insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm);
#ifdef INVARIANTS
		if (insret != NULL) {
			panic("Insert in rb tree of %p fails ret:%p rack:%p rsm:%p",
			      nrsm, insret, rack, rsm);
		}
#endif
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
		/*
		 * Set in the new RSM as the
		 * collapsed starting point
		 */
		rsm = nrsm;
	}
no_split:
	counter_u64_add(rack_collapsed_win, 1);
	RB_FOREACH_FROM(nrsm, rack_rb_tree_head, rsm) {
		nrsm->r_flags |= RACK_RWND_COLLAPSED;
		rack->rc_has_collapsed = 1;
	}
}

static void
rack_un_collapse_window(struct tcp_rack *rack)
{
	struct rack_sendmap *rsm;

	RB_FOREACH_REVERSE(rsm, rack_rb_tree_head, &rack->r_ctl.rc_mtree) {
		if (rsm->r_flags & RACK_RWND_COLLAPSED)
			rsm->r_flags &= ~RACK_RWND_COLLAPSED;
		else
			break;
	}
	rack->rc_has_collapsed = 0;
}

static void
rack_handle_delayed_ack(struct tcpcb *tp, struct tcp_rack *rack,
			int32_t tlen, int32_t tfo_syn)
{
	if (DELAY_ACK(tp, tlen) || tfo_syn) {
		if (rack->rc_dack_mode &&
		    (tlen > 500) &&
		    (rack->rc_dack_toggle == 1)) {
			goto no_delayed_ack;
		}
		rack_timer_cancel(tp, rack,
				  rack->r_ctl.rc_rcvtime, __LINE__);
		tp->t_flags |= TF_DELACK;
	} else {
no_delayed_ack:
		rack->r_wanted_output = 1;
		tp->t_flags |= TF_ACKNOW;
		if (rack->rc_dack_mode) {
			if (tp->t_flags & TF_DELACK)
				rack->rc_dack_toggle = 1;
			else
				rack->rc_dack_toggle = 0;
		}
	}
}
/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_process_data(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)
{
	/*
	 * Update window information. Don't look at window if no ACK: TAC's
	 * send garbage on first SYN.
	 */
	int32_t nsegs;
	int32_t tfo_syn;
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	INP_WLOCK_ASSERT(tp->t_inpcb);
	nsegs = max(1, m->m_pkthdr.lro_nsegs);
	if ((thflags & TH_ACK) &&
	    (SEQ_LT(tp->snd_wl1, th->th_seq) ||
	    (tp->snd_wl1 == th->th_seq && (SEQ_LT(tp->snd_wl2, th->th_ack) ||
	    (tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd))))) {
		/* keep track of pure window updates */
		if (tlen == 0 &&
		    tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd)
			KMOD_TCPSTAT_INC(tcps_rcvwinupd);
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		tp->snd_wl2 = th->th_ack;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		rack->r_wanted_output = 1;
	} else if (thflags & TH_ACK) {
		if ((tp->snd_wl2 == th->th_ack) && (tiwin < tp->snd_wnd)) {
			tp->snd_wnd = tiwin;
			tp->snd_wl1 = th->th_seq;
			tp->snd_wl2 = th->th_ack;
		}
	}
	if (tp->snd_wnd < ctf_outstanding(tp))
		/* The peer collapsed the window */
		rack_collapsed_window(rack);
	else if (rack->rc_has_collapsed)
		rack_un_collapse_window(rack);
	/* Was persist timer active and now we have window space? */
	if ((rack->rc_in_persist != 0) &&
	    (tp->snd_wnd >= min((rack->r_ctl.rc_high_rwnd/2),
				rack->r_ctl.rc_pace_min_segs))) {
		rack_exit_persist(tp, rack, rack->r_ctl.rc_rcvtime);
		tp->snd_nxt = tp->snd_max;
		/* Make sure we output to start the timer */
		rack->r_wanted_output = 1;
	}
	/* Do we enter persists? */
	if ((rack->rc_in_persist == 0) &&
	    (tp->snd_wnd < min((rack->r_ctl.rc_high_rwnd/2), rack->r_ctl.rc_pace_min_segs)) &&
	    TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->snd_max == tp->snd_una) &&
	    sbavail(&tp->t_inpcb->inp_socket->so_snd) &&
	    (sbavail(&tp->t_inpcb->inp_socket->so_snd) > tp->snd_wnd)) {
		/*
		 * Here the rwnd is less than
		 * the pacing size, we are established,
		 * nothing is outstanding, and there is
		 * data to send. Enter persists.
		 */
		tp->snd_nxt = tp->snd_una;
		rack_enter_persist(tp, rack, rack->r_ctl.rc_rcvtime);
	}
	if (tp->t_flags2 & TF2_DROP_AF_DATA) {
		m_freem(m);
		return (0);
	}
	/*
	 * don't process the URG bit, ignore them drag
	 * along the up.
	 */
	tp->rcv_up = tp->rcv_nxt;
	INP_WLOCK_ASSERT(tp->t_inpcb);

	/*
	 * Process the segment text, merging it into the TCP sequencing
	 * queue, and arranging for acknowledgment of receipt if necessary.
	 * This process logically involves adjusting tp->rcv_wnd as data is
	 * presented to the user (this happens in tcp_usrreq.c, case
	 * PRU_RCVD).  If a FIN has already been received on this connection
	 * then we just ignore the text.
	 */
	tfo_syn = ((tp->t_state == TCPS_SYN_RECEIVED) &&
		   IS_FASTOPEN(tp->t_flags));
	if ((tlen || (thflags & TH_FIN) || tfo_syn) &&
	    TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		tcp_seq save_start = th->th_seq;
		tcp_seq save_rnxt  = tp->rcv_nxt;
		int     save_tlen  = tlen;

		m_adj(m, drop_hdrlen);	/* delayed header drop */
		/*
		 * Insert segment which includes th into TCP reassembly
		 * queue with control block tp.  Set thflags to whether
		 * reassembly now includes a segment with FIN.  This handles
		 * the common case inline (segment is the next to be
		 * received on an established connection, and the queue is
		 * empty), avoiding linkage into and removal from the queue
		 * and repetition of various conversions. Set DELACK for
		 * segments received in order, but ack immediately when
		 * segments are out of order (so fast retransmit can work).
		 */
		if (th->th_seq == tp->rcv_nxt &&
		    SEGQ_EMPTY(tp) &&
		    (TCPS_HAVEESTABLISHED(tp->t_state) ||
		    tfo_syn)) {
#ifdef NETFLIX_SB_LIMITS
			u_int mcnt, appended;

			if (so->so_rcv.sb_shlim) {
				mcnt = m_memcnt(m);
				appended = 0;
				if (counter_fo_get(so->so_rcv.sb_shlim, mcnt,
				    CFO_NOSLEEP, NULL) == false) {
					counter_u64_add(tcp_sb_shlim_fails, 1);
					m_freem(m);
					return (0);
				}
			}
#endif
			rack_handle_delayed_ack(tp, rack, tlen, tfo_syn);
			tp->rcv_nxt += tlen;
			thflags = th->th_flags & TH_FIN;
			KMOD_TCPSTAT_ADD(tcps_rcvpack, nsegs);
			KMOD_TCPSTAT_ADD(tcps_rcvbyte, tlen);
			SOCKBUF_LOCK(&so->so_rcv);
			if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
				m_freem(m);
			} else
#ifdef NETFLIX_SB_LIMITS
				appended =
#endif
					sbappendstream_locked(&so->so_rcv, m, 0);
			/* NB: sorwakeup_locked() does an implicit unlock. */
			sorwakeup_locked(so);
#ifdef NETFLIX_SB_LIMITS
			if (so->so_rcv.sb_shlim && appended != mcnt)
				counter_fo_release(so->so_rcv.sb_shlim,
				    mcnt - appended);
#endif
		} else {
			/*
			 * XXX: Due to the header drop above "th" is
			 * theoretically invalid by now.  Fortunately
			 * m_adj() doesn't actually frees any mbufs when
			 * trimming from the head.
			 */
			tcp_seq temp = save_start;
			thflags = tcp_reass(tp, th, &temp, &tlen, m);
			tp->t_flags |= TF_ACKNOW;
		}
                if ((tp->t_flags & TF_SACK_PERMIT) && (save_tlen > 0)) {
                        if ((tlen == 0) && (SEQ_LT(save_start, save_rnxt))) {
                                /*
                                 * DSACK actually handled in the fastpath
                                 * above.
                                 */
				RACK_OPTS_INC(tcp_sack_path_1);
                                tcp_update_sack_list(tp, save_start,
                                    save_start + save_tlen);
                        } else if ((tlen > 0) && SEQ_GT(tp->rcv_nxt, save_rnxt)) {
                                if ((tp->rcv_numsacks >= 1) &&
                                    (tp->sackblks[0].end == save_start)) {
                                        /*
                                         * Partial overlap, recorded at todrop
                                         * above.
                                         */
					RACK_OPTS_INC(tcp_sack_path_2a);
                                        tcp_update_sack_list(tp,
                                            tp->sackblks[0].start,
                                            tp->sackblks[0].end);
                                } else {
					RACK_OPTS_INC(tcp_sack_path_2b);
                                        tcp_update_dsack_list(tp, save_start,
                                            save_start + save_tlen);
                                }
                        } else if (tlen >= save_tlen) {
                                /* Update of sackblks. */
				RACK_OPTS_INC(tcp_sack_path_3);
                                tcp_update_dsack_list(tp, save_start,
                                    save_start + save_tlen);
                        } else if (tlen > 0) {
				RACK_OPTS_INC(tcp_sack_path_4);
                                tcp_update_dsack_list(tp, save_start,
                                    save_start + tlen);
                        }
                }
	} else {
		m_freem(m);
		thflags &= ~TH_FIN;
	}

	/*
	 * If FIN is received ACK the FIN and let the user know that the
	 * connection is closing.
	 */
	if (thflags & TH_FIN) {
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			socantrcvmore(so);
			/*
			 * If connection is half-synchronized (ie NEEDSYN
			 * flag on) then delay ACK, so it may be piggybacked
			 * when SYN is sent. Otherwise, since we received a
			 * FIN then no more input can be expected, send ACK
			 * now.
			 */
			if (tp->t_flags & TF_NEEDSYN) {
				rack_timer_cancel(tp, rack,
				    rack->r_ctl.rc_rcvtime, __LINE__);
				tp->t_flags |= TF_DELACK;
			} else {
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt++;
		}
		switch (tp->t_state) {

			/*
			 * In SYN_RECEIVED and ESTABLISHED STATES enter the
			 * CLOSE_WAIT state.
			 */
		case TCPS_SYN_RECEIVED:
			tp->t_starttime = ticks;
			/* FALLTHROUGH */
		case TCPS_ESTABLISHED:
			rack_timer_cancel(tp, rack,
			    rack->r_ctl.rc_rcvtime, __LINE__);
			tcp_state_change(tp, TCPS_CLOSE_WAIT);
			break;

			/*
			 * If still in FIN_WAIT_1 STATE FIN has not been
			 * acked so enter the CLOSING state.
			 */
		case TCPS_FIN_WAIT_1:
			rack_timer_cancel(tp, rack,
			    rack->r_ctl.rc_rcvtime, __LINE__);
			tcp_state_change(tp, TCPS_CLOSING);
			break;

			/*
			 * In FIN_WAIT_2 state enter the TIME_WAIT state,
			 * starting the time-wait timer, turning off the
			 * other standard timers.
			 */
		case TCPS_FIN_WAIT_2:
			rack_timer_cancel(tp, rack,
			    rack->r_ctl.rc_rcvtime, __LINE__);
			tcp_twstart(tp);
			return (1);
		}
	}
	/*
	 * Return any desired output.
	 */
	if ((tp->t_flags & TF_ACKNOW) ||
	    (sbavail(&so->so_snd) > (tp->snd_max - tp->snd_una))) {
		rack->r_wanted_output = 1;
	}
	INP_WLOCK_ASSERT(tp->t_inpcb);
	return (0);
}

/*
 * Here nothing is really faster, its just that we
 * have broken out the fast-data path also just like
 * the fast-ack.
 */
static int
rack_do_fastnewdata(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t nsegs;
	int32_t newsize = 0;	/* automatic sockbuf scaling */
	struct tcp_rack *rack;
#ifdef NETFLIX_SB_LIMITS
	u_int mcnt, appended;
#endif
#ifdef TCPDEBUG
	/*
	 * The size of tcp_saveipgen must be the size of the max ip header,
	 * now IPv6.
	 */
	u_char tcp_saveipgen[IP6_HDR_LEN];
	struct tcphdr tcp_savetcp;
	short ostate = 0;

#endif
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * the timestamp. NOTE that the test is modified according to the
	 * latest proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 */
	if (__predict_false(th->th_seq != tp->rcv_nxt)) {
		return (0);
	}
	if (__predict_false(tp->snd_nxt != tp->snd_max)) {
		return (0);
	}
	if (tiwin && tiwin != tp->snd_wnd) {
		return (0);
	}
	if (__predict_false((tp->t_flags & (TF_NEEDSYN | TF_NEEDFIN)))) {
		return (0);
	}
	if (__predict_false((to->to_flags & TOF_TS) &&
	    (TSTMP_LT(to->to_tsval, tp->ts_recent)))) {
		return (0);
	}
	if (__predict_false((th->th_ack != tp->snd_una))) {
		return (0);
	}
	if (__predict_false(tlen > sbspace(&so->so_rcv))) {
		return (0);
	}
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	/*
	 * This is a pure, in-sequence data packet with nothing on the
	 * reassembly queue and we have enough buffer space to take it.
	 */
	nsegs = max(1, m->m_pkthdr.lro_nsegs);

#ifdef NETFLIX_SB_LIMITS
	if (so->so_rcv.sb_shlim) {
		mcnt = m_memcnt(m);
		appended = 0;
		if (counter_fo_get(so->so_rcv.sb_shlim, mcnt,
		    CFO_NOSLEEP, NULL) == false) {
			counter_u64_add(tcp_sb_shlim_fails, 1);
			m_freem(m);
			return (1);
		}
	}
#endif
	/* Clean receiver SACK report if present */
	if (tp->rcv_numsacks)
		tcp_clean_sackreport(tp);
	KMOD_TCPSTAT_INC(tcps_preddat);
	tp->rcv_nxt += tlen;
	/*
	 * Pull snd_wl1 up to prevent seq wrap relative to th_seq.
	 */
	tp->snd_wl1 = th->th_seq;
	/*
	 * Pull rcv_up up to prevent seq wrap relative to rcv_nxt.
	 */
	tp->rcv_up = tp->rcv_nxt;
	KMOD_TCPSTAT_ADD(tcps_rcvpack, nsegs);
	KMOD_TCPSTAT_ADD(tcps_rcvbyte, tlen);
#ifdef TCPDEBUG
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp,
		    (void *)tcp_saveipgen, &tcp_savetcp, 0);
#endif
	newsize = tcp_autorcvbuf(m, th, so, tp, tlen);

	/* Add data to socket buffer. */
	SOCKBUF_LOCK(&so->so_rcv);
	if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
		m_freem(m);
	} else {
		/*
		 * Set new socket buffer size. Give up when limit is
		 * reached.
		 */
		if (newsize)
			if (!sbreserve_locked(&so->so_rcv,
			    newsize, so, NULL))
				so->so_rcv.sb_flags &= ~SB_AUTOSIZE;
		m_adj(m, drop_hdrlen);	/* delayed header drop */
#ifdef NETFLIX_SB_LIMITS
		appended =
#endif
			sbappendstream_locked(&so->so_rcv, m, 0);
		ctf_calc_rwin(so, tp);
	}
	/* NB: sorwakeup_locked() does an implicit unlock. */
	sorwakeup_locked(so);
#ifdef NETFLIX_SB_LIMITS
	if (so->so_rcv.sb_shlim && mcnt != appended)
		counter_fo_release(so->so_rcv.sb_shlim, mcnt - appended);
#endif
	rack_handle_delayed_ack(tp, rack, tlen, 0);
	if (tp->snd_una == tp->snd_max)
		sack_filter_clear(&rack->r_ctl.rack_sf, tp->snd_una);
	return (1);
}

/*
 * This subfunction is used to try to highly optimize the
 * fast path. We again allow window updates that are
 * in sequence to remain in the fast-path. We also add
 * in the __predict's to attempt to help the compiler.
 * Note that if we return a 0, then we can *not* process
 * it and the caller should push the packet into the
 * slow-path.
 */
static int
rack_fastack(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t nxt_pkt, uint32_t cts)
{
	int32_t acked;
	int32_t nsegs;
#ifdef TCPDEBUG
	/*
	 * The size of tcp_saveipgen must be the size of the max ip header,
	 * now IPv6.
	 */
	u_char tcp_saveipgen[IP6_HDR_LEN];
	struct tcphdr tcp_savetcp;
	short ostate = 0;
#endif
	int32_t under_pacing = 0;
	struct tcp_rack *rack;

	if (__predict_false(SEQ_LEQ(th->th_ack, tp->snd_una))) {
		/* Old ack, behind (or duplicate to) the last one rcv'd */
		return (0);
	}
	if (__predict_false(SEQ_GT(th->th_ack, tp->snd_max))) {
		/* Above what we have sent? */
		return (0);
	}
	if (__predict_false(tp->snd_nxt != tp->snd_max)) {
		/* We are retransmitting */
		return (0);
	}
	if (__predict_false(tiwin == 0)) {
		/* zero window */
		return (0);
	}
	if (__predict_false(tp->t_flags & (TF_NEEDSYN | TF_NEEDFIN))) {
		/* We need a SYN or a FIN, unlikely.. */
		return (0);
	}
	if ((to->to_flags & TOF_TS) && __predict_false(TSTMP_LT(to->to_tsval, tp->ts_recent))) {
		/* Timestamp is behind .. old ack with seq wrap? */
		return (0);
	}
	if (__predict_false(IN_RECOVERY(tp->t_flags))) {
		/* Still recovering */
		return (0);
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack->r_ctl.rc_sacked) {
		/* We have sack holes on our scoreboard */
		return (0);
	}
	/* Ok if we reach here, we can process a fast-ack */
	if (rack->rc_gp_filled &&
	    (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {
		under_pacing = 1;
	}
	nsegs = max(1, m->m_pkthdr.lro_nsegs);
	rack_log_ack(tp, to, th);
	/* Did the window get updated? */
	if (tiwin != tp->snd_wnd) {
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
	}
	/* Do we exit persists? */
	if ((rack->rc_in_persist != 0) &&
	    (tp->snd_wnd >= min((rack->r_ctl.rc_high_rwnd/2),
			       rack->r_ctl.rc_pace_min_segs))) {
		rack_exit_persist(tp, rack, cts);
	}
	/* Do we enter persists? */
	if ((rack->rc_in_persist == 0) &&
	    (tp->snd_wnd < min((rack->r_ctl.rc_high_rwnd/2), rack->r_ctl.rc_pace_min_segs)) &&
	    TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->snd_max == tp->snd_una) &&
	    sbavail(&tp->t_inpcb->inp_socket->so_snd) &&
	    (sbavail(&tp->t_inpcb->inp_socket->so_snd) > tp->snd_wnd)) {
		/*
		 * Here the rwnd is less than
		 * the pacing size, we are established,
		 * nothing is outstanding, and there is
		 * data to send. Enter persists.
		 */
		tp->snd_nxt = tp->snd_una;
		rack_enter_persist(tp, rack, rack->r_ctl.rc_rcvtime);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * the timestamp. NOTE that the test is modified according to the
	 * latest proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * This is a pure ack for outstanding data.
	 */
	KMOD_TCPSTAT_INC(tcps_predack);

	/*
	 * "bad retransmit" recovery.
	 */
	if (tp->t_flags & TF_PREVVALID) {
		tp->t_flags &= ~TF_PREVVALID;
		if (tp->t_rxtshift == 1 &&
		    (int)(ticks - tp->t_badrxtwin) < 0)
			rack_cong_signal(tp, th, CC_RTO_ERR);
	}
	/*
	 * Recalculate the transmit timer / rtt.
	 *
	 * Some boxes send broken timestamp replies during the SYN+ACK
	 * phase, ignore timestamps of 0 or we could calculate a huge RTT
	 * and blow up the retransmit timer.
	 */
	acked = BYTES_THIS_ACK(tp, th);

#ifdef TCP_HHOOK
	/* Run HHOOK_TCP_ESTABLISHED_IN helper hooks. */
	hhook_run_tcp_est_in(tp, th, to);
#endif

	KMOD_TCPSTAT_ADD(tcps_rcvackpack, nsegs);
	KMOD_TCPSTAT_ADD(tcps_rcvackbyte, acked);
	sbdrop(&so->so_snd, acked);
	if (acked) {
		/* assure we are not backed off */
		tp->t_rxtshift = 0;
		rack->rc_tlp_in_progress = 0;
		rack->r_ctl.rc_tlp_cnt_out = 0;
		/*
		 * If it is the RXT timer we want to
		 * stop it, so we can restart a TLP.
		 */
		if (rack->r_ctl.rc_hpts_flags & PACE_TMR_RXT)
			rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
#ifdef NETFLIX_HTTP_LOGGING
		tcp_http_check_for_comp(rack->rc_tp, th->th_ack);
#endif
	}
	/*
	 * Let the congestion control algorithm update congestion control
	 * related information. This typically means increasing the
	 * congestion window.
	 */
	rack_ack_received(tp, rack, th, nsegs, CC_ACK, 0);

	tp->snd_una = th->th_ack;
	if (tp->snd_wnd < ctf_outstanding(tp)) {
		/* The peer collapsed the window */
		rack_collapsed_window(rack);
	} else if (rack->rc_has_collapsed)
		rack_un_collapse_window(rack);

	/*
	 * Pull snd_wl2 up to prevent seq wrap relative to th_ack.
	 */
	tp->snd_wl2 = th->th_ack;
	tp->t_dupacks = 0;
	m_freem(m);
	/* ND6_HINT(tp);	 *//* Some progress has been made. */

	/*
	 * If all outstanding data are acked, stop retransmit timer,
	 * otherwise restart timer using current (possibly backed-off)
	 * value. If process is waiting for space, wakeup/selwakeup/signal.
	 * If data are ready to send, let tcp_output decide between more
	 * output or persist.
	 */
#ifdef TCPDEBUG
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp,
		    (void *)tcp_saveipgen,
		    &tcp_savetcp, 0);
#endif
	if (under_pacing &&
	    (rack->use_fixed_rate == 0) &&
	    (rack->in_probe_rtt == 0) &&
	    rack->rc_gp_dyn_mul &&
	    rack->rc_always_pace) {
		/* Check if we are dragging bottom */
		rack_check_bottom_drag(tp, rack, so, acked);
	}
	if (tp->snd_una == tp->snd_max) {
		rack->r_ctl.rc_went_idle_time = tcp_get_usecs(NULL);
		if (rack->r_ctl.rc_went_idle_time == 0)
			rack->r_ctl.rc_went_idle_time = 1;
		rack_log_progress_event(rack, tp, 0, PROGRESS_CLEAR, __LINE__);
		if (sbavail(&tp->t_inpcb->inp_socket->so_snd) == 0)
			tp->t_acktime = 0;
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
	}
	/* Wake up the socket if we have room to write more */
	sowwakeup(so);
	if (sbavail(&so->so_snd)) {
		rack->r_wanted_output = 1;
	}
	return (1);
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_syn_sent(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;
	int32_t todrop;
	int32_t ourfinisacked = 0;
	struct tcp_rack *rack;

	ctf_calc_rwin(so, tp);
	/*
	 * If the state is SYN_SENT: if seg contains an ACK, but not for our
	 * SYN, drop the input. if seg contains a RST, then drop the
	 * connection. if seg does not contain SYN, then drop it. Otherwise
	 * this is an acceptable SYN segment initialize tp->rcv_nxt and
	 * tp->irs if seg contains ack then advance tp->snd_una if seg
	 * contains an ECE and ECN support is enabled, the stream is ECN
	 * capable. if SYN has been acked change to ESTABLISHED else
	 * SYN_RCVD state arrange for segment to be acked (eventually)
	 * continue processing rest of data/controls.
	 */
	if ((thflags & TH_ACK) &&
	    (SEQ_LEQ(th->th_ack, tp->iss) ||
	    SEQ_GT(th->th_ack, tp->snd_max))) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if ((thflags & (TH_ACK | TH_RST)) == (TH_ACK | TH_RST)) {
		TCP_PROBE5(connect__refused, NULL, tp,
		    mtod(m, const char *), tp, th);
		tp = tcp_drop(tp, ECONNREFUSED);
		ctf_do_drop(m, tp);
		return (1);
	}
	if (thflags & TH_RST) {
		ctf_do_drop(m, tp);
		return (1);
	}
	if (!(thflags & TH_SYN)) {
		ctf_do_drop(m, tp);
		return (1);
	}
	tp->irs = th->th_seq;
	tcp_rcvseqinit(tp);
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (thflags & TH_ACK) {
		int tfo_partial = 0;

		KMOD_TCPSTAT_INC(tcps_connects);
		soisconnected(so);
#ifdef MAC
		mac_socketpeer_set_from_mbuf(m, so);
#endif
		/* Do window scaling on this connection? */
		if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
		    (TF_RCVD_SCALE | TF_REQ_SCALE)) {
			tp->rcv_scale = tp->request_r_scale;
		}
		tp->rcv_adv += min(tp->rcv_wnd,
		    TCP_MAXWIN << tp->rcv_scale);
		/*
		 * If not all the data that was sent in the TFO SYN
		 * has been acked, resend the remainder right away.
		 */
		if (IS_FASTOPEN(tp->t_flags) &&
		    (tp->snd_una != tp->snd_max)) {
			tp->snd_nxt = th->th_ack;
			tfo_partial = 1;
		}
		/*
		 * If there's data, delay ACK; if there's also a FIN ACKNOW
		 * will be turned on later.
		 */
		if (DELAY_ACK(tp, tlen) && tlen != 0 && !tfo_partial) {
			rack_timer_cancel(tp, rack,
					  rack->r_ctl.rc_rcvtime, __LINE__);
			tp->t_flags |= TF_DELACK;
		} else {
			rack->r_wanted_output = 1;
			tp->t_flags |= TF_ACKNOW;
			rack->rc_dack_toggle = 0;
		}
		if (((thflags & (TH_CWR | TH_ECE)) == TH_ECE) &&
		    (V_tcp_do_ecn == 1)) {
			tp->t_flags2 |= TF2_ECN_PERMIT;
			KMOD_TCPSTAT_INC(tcps_ecn_shs);
		}
		if (SEQ_GT(th->th_ack, tp->snd_una)) {
			/*
			 * We advance snd_una for the
			 * fast open case. If th_ack is
			 * acknowledging data beyond
			 * snd_una we can't just call
			 * ack-processing since the
			 * data stream in our send-map
			 * will start at snd_una + 1 (one
			 * beyond the SYN). If its just
			 * equal we don't need to do that
			 * and there is no send_map.
			 */
			tp->snd_una++;
		}
		/*
		 * Received <SYN,ACK> in SYN_SENT[*] state. Transitions:
		 * SYN_SENT  --> ESTABLISHED SYN_SENT* --> FIN_WAIT_1
		 */
		tp->t_starttime = ticks;
		if (tp->t_flags & TF_NEEDFIN) {
			tcp_state_change(tp, TCPS_FIN_WAIT_1);
			tp->t_flags &= ~TF_NEEDFIN;
			thflags &= ~TH_SYN;
		} else {
			tcp_state_change(tp, TCPS_ESTABLISHED);
			TCP_PROBE5(connect__established, NULL, tp,
			    mtod(m, const char *), tp, th);
			rack_cc_conn_init(tp);
		}
	} else {
		/*
		 * Received initial SYN in SYN-SENT[*] state => simultaneous
		 * open.  If segment contains CC option and there is a
		 * cached CC, apply TAO test. If it succeeds, connection is *
		 * half-synchronized. Otherwise, do 3-way handshake:
		 * SYN-SENT -> SYN-RECEIVED SYN-SENT* -> SYN-RECEIVED* If
		 * there was no CC option, clear cached CC value.
		 */
		tp->t_flags |= (TF_ACKNOW | TF_NEEDSYN);
		tcp_state_change(tp, TCPS_SYN_RECEIVED);
	}
	INP_WLOCK_ASSERT(tp->t_inpcb);
	/*
	 * Advance th->th_seq to correspond to first data byte. If data,
	 * trim to stay within window, dropping FIN if necessary.
	 */
	th->th_seq++;
	if (tlen > tp->rcv_wnd) {
		todrop = tlen - tp->rcv_wnd;
		m_adj(m, -todrop);
		tlen = tp->rcv_wnd;
		thflags &= ~TH_FIN;
		KMOD_TCPSTAT_INC(tcps_rcvpackafterwin);
		KMOD_TCPSTAT_ADD(tcps_rcvbyteafterwin, todrop);
	}
	tp->snd_wl1 = th->th_seq - 1;
	tp->rcv_up = th->th_seq;
	/*
	 * Client side of transaction: already sent SYN and data. If the
	 * remote host used T/TCP to validate the SYN, our data will be
	 * ACK'd; if so, enter normal data segment processing in the middle
	 * of step 5, ack processing. Otherwise, goto step 6.
	 */
	if (thflags & TH_ACK) {
		/* For syn-sent we need to possibly update the rtt */
		if ((to->to_flags & TOF_TS) != 0 && to->to_tsecr) {
			uint32_t t;

			t = tcp_ts_getticks() - to->to_tsecr;
			if (!tp->t_rttlow || tp->t_rttlow > t)
				tp->t_rttlow = t;
			tcp_rack_xmit_timer(rack, t + 1, 1, (t * HPTS_USEC_IN_MSEC), 0, NULL, 2);
			tcp_rack_xmit_timer_commit(rack, tp);
		}
		if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val))
			return (ret_val);
		/* We may have changed to FIN_WAIT_1 above */
		if (tp->t_state == TCPS_FIN_WAIT_1) {
			/*
			 * In FIN_WAIT_1 STATE in addition to the processing
			 * for the ESTABLISHED state if our FIN is now
			 * acknowledged then enter FIN_WAIT_2.
			 */
			if (ourfinisacked) {
				/*
				 * If we can't receive any more data, then
				 * closing user can proceed. Starting the
				 * timer is contrary to the specification,
				 * but if we don't get a FIN we'll hang
				 * forever.
				 *
				 * XXXjl: we should release the tp also, and
				 * use a compressed state.
				 */
				if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
					soisdisconnected(so);
					tcp_timer_activate(tp, TT_2MSL,
					    (tcp_fast_finwait2_recycle ?
					    tcp_finwait2_timeout :
					    TP_MAXIDLE(tp)));
				}
				tcp_state_change(tp, TCPS_FIN_WAIT_2);
			}
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	   tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_syn_recv(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	struct tcp_rack *rack;
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	ctf_calc_rwin(so, tp);
	if ((thflags & TH_ACK) &&
	    (SEQ_LEQ(th->th_ack, tp->snd_una) ||
	    SEQ_GT(th->th_ack, tp->snd_max))) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (IS_FASTOPEN(tp->t_flags)) {
		/*
		 * When a TFO connection is in SYN_RECEIVED, the
		 * only valid packets are the initial SYN, a
		 * retransmit/copy of the initial SYN (possibly with
		 * a subset of the original data), a valid ACK, a
		 * FIN, or a RST.
		 */
		if ((thflags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
			tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		} else if (thflags & TH_SYN) {
			/* non-initial SYN is ignored */
			if ((rack->r_ctl.rc_hpts_flags & PACE_TMR_RXT) ||
			    (rack->r_ctl.rc_hpts_flags & PACE_TMR_TLP) ||
			    (rack->r_ctl.rc_hpts_flags & PACE_TMR_RACK)) {
				ctf_do_drop(m, NULL);
				return (0);
			}
		} else if (!(thflags & (TH_ACK | TH_FIN | TH_RST))) {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	/*
	 * In the SYN-RECEIVED state, validate that the packet belongs to
	 * this connection before trimming the data to fit the receive
	 * window.  Check the sequence number versus IRS since we know the
	 * sequence numbers haven't wrapped.  This is a partial fix for the
	 * "LAND" DoS attack.
	 */
	if (SEQ_LT(th->th_seq, tp->irs)) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	tp->snd_wnd = tiwin;
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (IS_FASTOPEN(tp->t_flags)) {
			rack_cc_conn_init(tp);
		}
		return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
		    tiwin, thflags, nxt_pkt));
	}
	KMOD_TCPSTAT_INC(tcps_connects);
	soisconnected(so);
	/* Do window scaling? */
	if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
	    (TF_RCVD_SCALE | TF_REQ_SCALE)) {
		tp->rcv_scale = tp->request_r_scale;
	}
	/*
	 * Make transitions: SYN-RECEIVED  -> ESTABLISHED SYN-RECEIVED* ->
	 * FIN-WAIT-1
	 */
	tp->t_starttime = ticks;
	if (IS_FASTOPEN(tp->t_flags) && tp->t_tfo_pending) {
		tcp_fastopen_decrement_counter(tp->t_tfo_pending);
		tp->t_tfo_pending = NULL;
	}
	if (tp->t_flags & TF_NEEDFIN) {
		tcp_state_change(tp, TCPS_FIN_WAIT_1);
		tp->t_flags &= ~TF_NEEDFIN;
	} else {
		tcp_state_change(tp, TCPS_ESTABLISHED);
		TCP_PROBE5(accept__established, NULL, tp,
		    mtod(m, const char *), tp, th);
		/*
		 * TFO connections call cc_conn_init() during SYN
		 * processing.  Calling it again here for such connections
		 * is not harmless as it would undo the snd_cwnd reduction
		 * that occurs when a TFO SYN|ACK is retransmitted.
		 */
		if (!IS_FASTOPEN(tp->t_flags))
			rack_cc_conn_init(tp);
	}
	/*
	 * Account for the ACK of our SYN prior to
	 * regular ACK processing below, except for
	 * simultaneous SYN, which is handled later.
	 */
	if (SEQ_GT(th->th_ack, tp->snd_una) && !(tp->t_flags & TF_NEEDSYN))
		tp->snd_una++;
	/*
	 * If segment contains data or ACK, will call tcp_reass() later; if
	 * not, do so now to pass queued data to user.
	 */
	if (tlen == 0 && (thflags & TH_FIN) == 0)
		(void) tcp_reass(tp, (struct tcphdr *)0, NULL, 0,
		    (struct mbuf *)0);
	tp->snd_wl1 = th->th_seq - 1;
	/* For syn-recv we need to possibly update the rtt */
	if ((to->to_flags & TOF_TS) != 0 && to->to_tsecr) {
		uint32_t t;

		t = tcp_ts_getticks() - to->to_tsecr;
		if (!tp->t_rttlow || tp->t_rttlow > t)
			tp->t_rttlow = t;
		tcp_rack_xmit_timer(rack, t + 1, 1, (t * HPTS_USEC_IN_MSEC), 0, NULL, 2);
		tcp_rack_xmit_timer_commit(rack, tp);
	}
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (tp->t_state == TCPS_FIN_WAIT_1) {
		/* We could have went to FIN_WAIT_1 (or EST) above */
		/*
		 * In FIN_WAIT_1 STATE in addition to the processing for the
		 * ESTABLISHED state if our FIN is now acknowledged then
		 * enter FIN_WAIT_2.
		 */
		if (ourfinisacked) {
			/*
			 * If we can't receive any more data, then closing
			 * user can proceed. Starting the timer is contrary
			 * to the specification, but if we don't get a FIN
			 * we'll hang forever.
			 *
			 * XXXjl: we should release the tp also, and use a
			 * compressed state.
			 */
			if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
				soisdisconnected(so);
				tcp_timer_activate(tp, TT_2MSL,
				    (tcp_fast_finwait2_recycle ?
				    tcp_finwait2_timeout :
				    TP_MAXIDLE(tp)));
			}
			tcp_state_change(tp, TCPS_FIN_WAIT_2);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_established(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;
	struct tcp_rack *rack;

	/*
	 * Header prediction: check for the two common cases of a
	 * uni-directional data xfer.  If the packet has no control flags,
	 * is in-sequence, the window didn't change and we're not
	 * retransmitting, it's a candidate.  If the length is zero and the
	 * ack moved forward, we're the sender side of the xfer.  Just free
	 * the data acked & wake any higher level process that was blocked
	 * waiting for space.  If the length is non-zero and the ack didn't
	 * move, we're the receiver side.  If we're getting packets in-order
	 * (the reassembly queue is empty), add the data toc The socket
	 * buffer and note that we need a delayed ack. Make sure that the
	 * hidden state-flags are also off. Since we check for
	 * TCPS_ESTABLISHED first, it can only be TH_NEEDSYN.
	 */
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (__predict_true(((to->to_flags & TOF_SACK) == 0)) &&
	    __predict_true((thflags & (TH_SYN | TH_FIN | TH_RST | TH_ACK)) == TH_ACK) &&
	    __predict_true(SEGQ_EMPTY(tp)) &&
	    __predict_true(th->th_seq == tp->rcv_nxt)) {
		if (tlen == 0) {
			if (rack_fastack(m, th, so, tp, to, drop_hdrlen, tlen,
			    tiwin, nxt_pkt, rack->r_ctl.rc_rcvtime)) {
				return (0);
			}
		} else {
			if (rack_do_fastnewdata(m, th, so, tp, to, drop_hdrlen, tlen,
			    tiwin, nxt_pkt, iptos)) {
				return (0);
			}
		}
	}
	ctf_calc_rwin(so, tp);

	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));

	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {

			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));

		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output= 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, NULL, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			rack_log_progress_event(rack, tp, tick, PROGRESS_DROP, __LINE__);
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	/* State changes only happen in rack_process_data() */
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_close_wait(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;

	ctf_calc_rwin(so, tp);
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));

		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, NULL, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			rack_log_progress_event((struct tcp_rack *)tp->t_fb_ptr,
						tp, tick, PROGRESS_DROP, __LINE__);
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

static int
rack_check_data_after_close(struct mbuf *m,
    struct tcpcb *tp, int32_t *tlen, struct tcphdr *th, struct socket *so)
{
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack->rc_allow_data_af_clo == 0) {
	close_now:
		tcp_log_end_status(tp, TCP_EI_STATUS_DATA_A_CLOSE);
		/* tcp_close will kill the inp pre-log the Reset */
		tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_RST);
		tp = tcp_close(tp);
		KMOD_TCPSTAT_INC(tcps_rcvafterclose);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_UNLIMITED, (*tlen));
		return (1);
	}
	if (sbavail(&so->so_snd) == 0)
		goto close_now;
	/* Ok we allow data that is ignored and a followup reset */
	tcp_log_end_status(tp, TCP_EI_STATUS_DATA_A_CLOSE);
	tp->rcv_nxt = th->th_seq + *tlen;
	tp->t_flags2 |= TF2_DROP_AF_DATA;
	rack->r_wanted_output = 1;
	*tlen = 0;
	return (0);
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_fin_wait_1(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	ctf_calc_rwin(so, tp);

	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		/*
		 * If we can't receive any more data, then closing user can
		 * proceed. Starting the timer is contrary to the
		 * specification, but if we don't get a FIN we'll hang
		 * forever.
		 *
		 * XXXjl: we should release the tp also, and use a
		 * compressed state.
		 */
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
			soisdisconnected(so);
			tcp_timer_activate(tp, TT_2MSL,
			    (tcp_fast_finwait2_recycle ?
			    tcp_finwait2_timeout :
			    TP_MAXIDLE(tp)));
		}
		tcp_state_change(tp, TCPS_FIN_WAIT_2);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			rack_log_progress_event((struct tcp_rack *)tp->t_fb_ptr,
						tp, tick, PROGRESS_DROP, __LINE__);
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_closing(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	ctf_calc_rwin(so, tp);

	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output= 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		tcp_twstart(tp);
		m_freem(m);
		return (1);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			rack_log_progress_event((struct tcp_rack *)tp->t_fb_ptr,
						tp, tick, PROGRESS_DROP, __LINE__);
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_lastack(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	ctf_calc_rwin(so, tp);

	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * case TCPS_LAST_ACK: Ack processing.
	 */
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		tp = tcp_close(tp);
		ctf_do_drop(m, tp);
		return (1);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			rack_log_progress_event((struct tcp_rack *)tp->t_fb_ptr,
						tp, tick, PROGRESS_DROP, __LINE__);
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}


/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCP is still
 * locked.
 */
static int
rack_do_fin_wait_2(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	ctf_calc_rwin(so, tp);

	/* Reset receive buffer auto scaling when not in bulk receive mode. */
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) &&
	    tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			rack_log_progress_event((struct tcp_rack *)tp->t_fb_ptr,
						tp, tick, PROGRESS_DROP, __LINE__);
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

static void inline
rack_clear_rate_sample(struct tcp_rack *rack)
{
	rack->r_ctl.rack_rs.rs_flags = RACK_RTT_EMPTY;
	rack->r_ctl.rack_rs.rs_rtt_cnt = 0;
	rack->r_ctl.rack_rs.rs_rtt_tot = 0;
}

static void
rack_set_pace_segments(struct tcpcb *tp, struct tcp_rack *rack, uint32_t line)
{
	uint64_t bw_est, rate_wanted;
	uint32_t tls_seg = 0;
	int chged = 0;
	uint32_t user_max;

	user_max = ctf_fixed_maxseg(tp) * rack->rc_user_set_max_segs;
#ifdef KERN_TLS
	if (rack->rc_inp->inp_socket->so_snd.sb_flags & SB_TLS_IFNET) {
		tls_seg = ctf_get_opt_tls_size(rack->rc_inp->inp_socket, rack->rc_tp->snd_wnd);
		if (tls_seg != rack->r_ctl.rc_pace_min_segs)
			chged = 1;
		rack->r_ctl.rc_pace_min_segs = tls_seg;
	} else
#endif
	{
		if (ctf_fixed_maxseg(tp) != rack->r_ctl.rc_pace_min_segs)
			chged = 1;
		rack->r_ctl.rc_pace_min_segs = ctf_fixed_maxseg(tp);
	}
	if (rack->use_fixed_rate || rack->rc_force_max_seg) {
		if (user_max != rack->r_ctl.rc_pace_max_segs)
			chged = 1;
	}
	if (rack->rc_force_max_seg) {
		rack->r_ctl.rc_pace_max_segs = user_max;
	} else if (rack->use_fixed_rate) {
		bw_est = rack_get_bw(rack);
		if ((rack->r_ctl.crte == NULL) ||
		    (bw_est != rack->r_ctl.crte->rate))  {
			rack->r_ctl.rc_pace_max_segs = user_max;
		} else {
			/* We are pacing right at the hardware rate */
			uint32_t segsiz;

			segsiz = min(ctf_fixed_maxseg(tp),
				     rack->r_ctl.rc_pace_min_segs);
			rack->r_ctl.rc_pace_max_segs = tcp_get_pacing_burst_size(
				                           bw_est, segsiz, 0,
							   rack->r_ctl.crte, NULL);
		}
	} else if (rack->rc_always_pace) {
		if (rack->r_ctl.gp_bw ||
#ifdef NETFLIX_PEAKRATE
		    rack->rc_tp->t_maxpeakrate ||
#endif
		    rack->r_ctl.init_rate) {
			/* We have a rate of some sort set */
			uint32_t  orig;

			bw_est = rack_get_bw(rack);
			orig = rack->r_ctl.rc_pace_max_segs;
			rate_wanted = rack_get_output_bw(rack, bw_est, NULL);
			if (rate_wanted) {
				/* We have something */
				rack->r_ctl.rc_pace_max_segs = rack_get_pacing_len(rack,
										   rate_wanted,
										   ctf_fixed_maxseg(rack->rc_tp));
			} else
				rack->r_ctl.rc_pace_max_segs = rack->r_ctl.rc_pace_min_segs;
			if (orig != rack->r_ctl.rc_pace_max_segs)
				chged = 1;
		} else if ((rack->r_ctl.gp_bw == 0) &&
			   (rack->r_ctl.rc_pace_max_segs == 0)) {
			/*
			 * If we have nothing limit us to bursting
			 * out IW sized pieces.
			 */
			chged = 1;
			rack->r_ctl.rc_pace_max_segs = rc_init_window(rack);
		}
	}
	if (rack->r_ctl.rc_pace_max_segs > PACE_MAX_IP_BYTES) {
		chged = 1;
		rack->r_ctl.rc_pace_max_segs = PACE_MAX_IP_BYTES;
	}
#ifdef KERN_TLS
	uint32_t orig;

	if (tls_seg != 0) {
		orig = rack->r_ctl.rc_pace_max_segs;
		if (rack_hw_tls_max_seg > 1) {
			rack->r_ctl.rc_pace_max_segs /= tls_seg;
			if (rack_hw_tls_max_seg > rack->r_ctl.rc_pace_max_segs)
				rack->r_ctl.rc_pace_max_segs = rack_hw_tls_max_seg;
		} else {
			rack->r_ctl.rc_pace_max_segs = 1;
		}
		if (rack->r_ctl.rc_pace_max_segs == 0)
			rack->r_ctl.rc_pace_max_segs = 1;
		rack->r_ctl.rc_pace_max_segs *= tls_seg;
		if (rack->r_ctl.rc_pace_max_segs > PACE_MAX_IP_BYTES) {
			/* We can't go over the max bytes (usually 64k) */
			rack->r_ctl.rc_pace_max_segs = ((PACE_MAX_IP_BYTES / tls_seg) * tls_seg);
		}
		if (orig != rack->r_ctl.rc_pace_max_segs)
			chged = 1;
	}
#endif
	if (chged)
		rack_log_type_hrdwtso(tp, rack, tls_seg, rack->rc_inp->inp_socket->so_snd.sb_flags, line, 2);
}

static int
rack_init(struct tcpcb *tp)
{
	struct tcp_rack *rack = NULL;
	struct rack_sendmap *insret;
	uint32_t iwin, snt, us_cts;

	tp->t_fb_ptr = uma_zalloc(rack_pcb_zone, M_NOWAIT);
	if (tp->t_fb_ptr == NULL) {
		/*
		 * We need to allocate memory but cant. The INP and INP_INFO
		 * locks and they are recusive (happens during setup. So a
		 * scheme to drop the locks fails :(
		 *
		 */
		return (ENOMEM);
	}
	memset(tp->t_fb_ptr, 0, sizeof(struct tcp_rack));

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	RB_INIT(&rack->r_ctl.rc_mtree);
	TAILQ_INIT(&rack->r_ctl.rc_free);
	TAILQ_INIT(&rack->r_ctl.rc_tmap);
	rack->rc_tp = tp;
	if (tp->t_inpcb) {
		rack->rc_inp = tp->t_inpcb;
	}
	/* Probably not needed but lets be sure */
	rack_clear_rate_sample(rack);
	rack->r_ctl.rc_reorder_fade = rack_reorder_fade;
	rack->rc_allow_data_af_clo = rack_ignore_data_after_close;
	rack->r_ctl.rc_tlp_threshold = rack_tlp_thresh;
	if (use_rack_rr)
		rack->use_rack_rr = 1;
	if (V_tcp_delack_enabled)
		tp->t_delayed_ack = 1;
	else
		tp->t_delayed_ack = 0;
	if (rack_enable_shared_cwnd)
		rack->rack_enable_scwnd = 1;
	rack->rc_user_set_max_segs = rack_hptsi_segments;
	rack->rc_force_max_seg = 0;
	if (rack_use_imac_dack)
		rack->rc_dack_mode = 1;
	rack->r_ctl.rc_reorder_shift = rack_reorder_thresh;
	rack->r_ctl.rc_pkt_delay = rack_pkt_delay;
	rack->r_ctl.rc_prop_reduce = rack_use_proportional_reduce;
	rack->r_ctl.rc_prop_rate = rack_proportional_rate;
	rack->r_ctl.rc_tlp_cwnd_reduce = rack_lower_cwnd_at_tlp;
	rack->r_ctl.rc_early_recovery = rack_early_recovery;
	rack->r_ctl.rc_lowest_us_rtt = 0xffffffff;
	rack->r_ctl.rc_highest_us_rtt = 0;
	if (rack_disable_prr)
		rack->rack_no_prr = 1;
	if (rack_gp_no_rec_chg)
		rack->rc_gp_no_rec_chg = 1;
	rack->rc_always_pace = rack_pace_every_seg;
	if (rack_enable_mqueue_for_nonpaced)
		rack->r_mbuf_queue = 1;
	else
		rack->r_mbuf_queue = 0;
	if  (rack->r_mbuf_queue || rack->rc_always_pace)
		tp->t_inpcb->inp_flags2 |= INP_SUPPORTS_MBUFQ;
	else
		tp->t_inpcb->inp_flags2 &= ~INP_SUPPORTS_MBUFQ;
	rack_set_pace_segments(tp, rack, __LINE__);
	if (rack_limits_scwnd)
		rack->r_limit_scw  = 1;
	else
		rack->r_limit_scw  = 0;
	rack->r_ctl.rc_high_rwnd = tp->snd_wnd;
	rack->r_ctl.cwnd_to_use = tp->snd_cwnd;
	rack->r_ctl.rc_rate_sample_method = rack_rate_sample_method;
	rack->rack_tlp_threshold_use = rack_tlp_threshold_use;
	rack->r_ctl.rc_prr_sendalot = rack_send_a_lot_in_prr;
	rack->r_ctl.rc_min_to = rack_min_to;
	microuptime(&rack->r_ctl.act_rcv_time);
	rack->r_ctl.rc_last_time_decay = rack->r_ctl.act_rcv_time;
	rack->r_running_late = 0;
	rack->r_running_early = 0;
	rack->rc_init_win = rack_default_init_window;
	rack->r_ctl.rack_per_of_gp_ss = rack_per_of_gp_ss;
	if (rack_do_dyn_mul) {
		/* When dynamic adjustment is on CA needs to start at 100% */
		rack->rc_gp_dyn_mul = 1;
		if (rack_do_dyn_mul >= 100)
			rack->r_ctl.rack_per_of_gp_ca = rack_do_dyn_mul;
	} else
		rack->r_ctl.rack_per_of_gp_ca = rack_per_of_gp_ca;
	rack->r_ctl.rack_per_of_gp_rec = rack_per_of_gp_rec;
	rack->r_ctl.rack_per_of_gp_probertt = rack_per_of_gp_probertt;
	rack->r_ctl.rc_tlp_rxt_last_time = tcp_tv_to_mssectick(&rack->r_ctl.act_rcv_time);
	setup_time_filter_small(&rack->r_ctl.rc_gp_min_rtt, FILTER_TYPE_MIN,
				rack_probertt_filter_life);
	us_cts = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
	rack->r_ctl.rc_lower_rtt_us_cts = us_cts;
	rack->r_ctl.rc_time_of_last_probertt = us_cts;
	rack->r_ctl.rc_time_probertt_starts = 0;
	/* Do we force on detection? */
#ifdef NETFLIX_EXP_DETECTION
	if (tcp_force_detection)
		rack->do_detection = 1;
	else
#endif
		rack->do_detection = 0;
	if (rack_non_rxt_use_cr)
		rack->rack_rec_nonrxt_use_cr = 1;
	if (tp->snd_una != tp->snd_max) {
		/* Create a send map for the current outstanding data */
		struct rack_sendmap *rsm;

		rsm = rack_alloc(rack);
		if (rsm == NULL) {
			uma_zfree(rack_pcb_zone, tp->t_fb_ptr);
			tp->t_fb_ptr = NULL;
			return (ENOMEM);
		}
		rsm->r_flags = RACK_OVERMAX;
		rsm->r_tim_lastsent[0] = rack->r_ctl.rc_tlp_rxt_last_time;
		rsm->r_rtr_cnt = 1;
		rsm->r_rtr_bytes = 0;
		rsm->r_start = tp->snd_una;
		rsm->r_end = tp->snd_max;
		rsm->usec_orig_send = us_cts;
		rsm->r_dupack = 0;
		insret = RB_INSERT(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
#ifdef INVARIANTS
		if (insret != NULL) {
			panic("Insert in rb tree fails ret:%p rack:%p rsm:%p",
			      insret, rack, rsm);
		}
#endif
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 1;
	}
	/* Cancel the GP measurement in progress */
	tp->t_flags &= ~TF_GPUTINPROG;
	if (SEQ_GT(tp->snd_max, tp->iss))
		snt = tp->snd_max - tp->iss;
	else
		snt = 0;
	iwin = rc_init_window(rack);
	if (snt < iwin) {
		/* We are not past the initial window
		 * so we need to make sure cwnd is
		 * correct.
		 */
		if (tp->snd_cwnd < iwin)
			tp->snd_cwnd = iwin;
		/*
		 * If we are within the initial window
		 * we want ssthresh to be unlimited. Setting
		 * it to the rwnd (which the default stack does
		 * and older racks) is not really a good idea
		 * since we want to be in SS and grow both the
		 * cwnd and the rwnd (via dynamic rwnd growth). If
		 * we set it to the rwnd then as the peer grows its
		 * rwnd we will be stuck in CA and never hit SS.
		 *
		 * Its far better to raise it up high (this takes the
		 * risk that there as been a loss already, probably
		 * we should have an indicator in all stacks of loss
		 * but we don't), but considering the normal use this
		 * is a risk worth taking. The consequences of not
		 * hitting SS are far worse than going one more time
		 * into it early on (before we have sent even a IW).
		 * It is highly unlikely that we will have had a loss
		 * before getting the IW out.
		 */
		tp->snd_ssthresh = 0xffffffff;
	}
	rack_stop_all_timers(tp);
	rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), 0, 0, 0);
	rack_log_rtt_shrinks(rack,  us_cts,  0,
			     __LINE__, RACK_RTTS_INIT);
	return (0);
}

static int
rack_handoff_ok(struct tcpcb *tp)
{
	if ((tp->t_state == TCPS_CLOSED) ||
	    (tp->t_state == TCPS_LISTEN)) {
		/* Sure no problem though it may not stick */
		return (0);
	}
	if ((tp->t_state == TCPS_SYN_SENT) ||
	    (tp->t_state == TCPS_SYN_RECEIVED)) {
		/*
		 * We really don't know you have to get to ESTAB or beyond
		 * to tell.
		 */
		return (EAGAIN);
	}
	if ((tp->t_flags & TF_SACK_PERMIT) || rack_sack_not_required){
		return (0);
	}
	/*
	 * If we reach here we don't do SACK on this connection so we can
	 * never do rack.
	 */
	return (EINVAL);
}

static void
rack_fini(struct tcpcb *tp, int32_t tcb_is_purged)
{
	if (tp->t_fb_ptr) {
		struct tcp_rack *rack;
		struct rack_sendmap *rsm, *nrsm, *rm;

		rack = (struct tcp_rack *)tp->t_fb_ptr;
#ifdef NETFLIX_SHARED_CWND
		if (rack->r_ctl.rc_scw) {
			uint32_t limit;

			if (rack->r_limit_scw)
				limit = max(1, rack->r_ctl.rc_lowest_us_rtt);
			else
				limit = 0;
			tcp_shared_cwnd_free_full(tp, rack->r_ctl.rc_scw,
						  rack->r_ctl.rc_scw_index,
						  limit);
			rack->r_ctl.rc_scw = NULL;
		}
#endif
		/* rack does not use force data but other stacks may clear it */
		tp->t_flags &= ~TF_FORCEDATA;
		if (tp->t_inpcb) {
			tp->t_inpcb->inp_flags2 &= ~INP_SUPPORTS_MBUFQ;
			tp->t_inpcb->inp_flags2 &= ~INP_MBUF_QUEUE_READY;
			tp->t_inpcb->inp_flags2 &= ~INP_DONT_SACK_QUEUE;
		}
#ifdef TCP_BLACKBOX
		tcp_log_flowend(tp);
#endif
		RB_FOREACH_SAFE(rsm, rack_rb_tree_head, &rack->r_ctl.rc_mtree, nrsm) {
			rm = RB_REMOVE(rack_rb_tree_head, &rack->r_ctl.rc_mtree, rsm);
#ifdef INVARIANTS
			if (rm != rsm) {
				panic("At fini, rack:%p rsm:%p rm:%p",
				      rack, rsm, rm);
			}
#endif
			uma_zfree(rack_zone, rsm);
		}
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_free);
		while (rsm) {
			TAILQ_REMOVE(&rack->r_ctl.rc_free, rsm, r_tnext);
			uma_zfree(rack_zone, rsm);
			rsm = TAILQ_FIRST(&rack->r_ctl.rc_free);
		}
		rack->rc_free_cnt = 0;
		uma_zfree(rack_pcb_zone, tp->t_fb_ptr);
		tp->t_fb_ptr = NULL;
	}
	/* Cancel the GP measurement in progress */
	tp->t_flags &= ~TF_GPUTINPROG;
	/* Make sure snd_nxt is correctly set */
	tp->snd_nxt = tp->snd_max;
}


static void
rack_set_state(struct tcpcb *tp, struct tcp_rack *rack)
{
	switch (tp->t_state) {
	case TCPS_SYN_SENT:
		rack->r_state = TCPS_SYN_SENT;
		rack->r_substate = rack_do_syn_sent;
		break;
	case TCPS_SYN_RECEIVED:
		rack->r_state = TCPS_SYN_RECEIVED;
		rack->r_substate = rack_do_syn_recv;
		break;
	case TCPS_ESTABLISHED:
		rack_set_pace_segments(tp, rack, __LINE__);
		rack->r_state = TCPS_ESTABLISHED;
		rack->r_substate = rack_do_established;
		break;
	case TCPS_CLOSE_WAIT:
		rack->r_state = TCPS_CLOSE_WAIT;
		rack->r_substate = rack_do_close_wait;
		break;
	case TCPS_FIN_WAIT_1:
		rack->r_state = TCPS_FIN_WAIT_1;
		rack->r_substate = rack_do_fin_wait_1;
		break;
	case TCPS_CLOSING:
		rack->r_state = TCPS_CLOSING;
		rack->r_substate = rack_do_closing;
		break;
	case TCPS_LAST_ACK:
		rack->r_state = TCPS_LAST_ACK;
		rack->r_substate = rack_do_lastack;
		break;
	case TCPS_FIN_WAIT_2:
		rack->r_state = TCPS_FIN_WAIT_2;
		rack->r_substate = rack_do_fin_wait_2;
		break;
	case TCPS_LISTEN:
	case TCPS_CLOSED:
	case TCPS_TIME_WAIT:
	default:
		break;
	};
}


static void
rack_timer_audit(struct tcpcb *tp, struct tcp_rack *rack, struct sockbuf *sb)
{
	/*
	 * We received an ack, and then did not
	 * call send or were bounced out due to the
	 * hpts was running. Now a timer is up as well, is
	 * it the right timer?
	 */
	struct rack_sendmap *rsm;
	int tmr_up;

	tmr_up = rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK;
	if (rack->rc_in_persist && (tmr_up == PACE_TMR_PERSIT))
		return;
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (((rsm == NULL) || (tp->t_state < TCPS_ESTABLISHED)) &&
	    (tmr_up == PACE_TMR_RXT)) {
		/* Should be an RXT */
		return;
	}
	if (rsm == NULL) {
		/* Nothing outstanding? */
		if (tp->t_flags & TF_DELACK) {
			if (tmr_up == PACE_TMR_DELACK)
				/* We are supposed to have delayed ack up and we do */
				return;
		} else if (sbavail(&tp->t_inpcb->inp_socket->so_snd) && (tmr_up == PACE_TMR_RXT)) {
			/*
			 * if we hit enobufs then we would expect the possiblity
			 * of nothing outstanding and the RXT up (and the hptsi timer).
			 */
			return;
		} else if (((V_tcp_always_keepalive ||
			     rack->rc_inp->inp_socket->so_options & SO_KEEPALIVE) &&
			    (tp->t_state <= TCPS_CLOSING)) &&
			   (tmr_up == PACE_TMR_KEEP) &&
			   (tp->snd_max == tp->snd_una)) {
			/* We should have keep alive up and we do */
			return;
		}
	}
	if (SEQ_GT(tp->snd_max, tp->snd_una) &&
		   ((tmr_up == PACE_TMR_TLP) ||
		    (tmr_up == PACE_TMR_RACK) ||
		    (tmr_up == PACE_TMR_RXT))) {
		/*
		 * Either a Rack, TLP or RXT is fine if  we
		 * have outstanding data.
		 */
		return;
	} else if (tmr_up == PACE_TMR_DELACK) {
		/*
		 * If the delayed ack was going to go off
		 * before the rtx/tlp/rack timer were going to
		 * expire, then that would be the timer in control.
		 * Note we don't check the time here trusting the
		 * code is correct.
		 */
		return;
	}
	/*
	 * Ok the timer originally started is not what we want now.
	 * We will force the hpts to be stopped if any, and restart
	 * with the slot set to what was in the saved slot.
	 */
	if (rack->rc_inp->inp_in_hpts) {
		if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) {
			uint32_t us_cts;

			us_cts = tcp_get_usecs(NULL);
			if (TSTMP_GT(rack->r_ctl.rc_last_output_to, us_cts)) {
				rack->r_early = 1;
				rack->r_ctl.rc_agg_early += (rack->r_ctl.rc_last_output_to - us_cts);
			}
			rack->r_ctl.rc_hpts_flags &= ~PACE_PKT_OUTPUT;
		}
		tcp_hpts_remove(tp->t_inpcb, HPTS_REMOVE_OUTPUT);
	}
	rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
	rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), 0, 0, 0);
}

static int
rack_do_segment_nounlock(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos,
    int32_t nxt_pkt, struct timeval *tv)
{
	int32_t thflags, retval, did_out = 0;
	int32_t way_out = 0;
	uint32_t cts;
	uint32_t tiwin;
	struct timespec ts;
	struct tcpopt to;
	struct tcp_rack *rack;
	struct rack_sendmap *rsm;
	int32_t prev_state = 0;
	uint32_t us_cts;
	/*
	 * tv passed from common code is from either M_TSTMP_LRO or
	 * tcp_get_usecs() if no LRO m_pkthdr timestamp is present. The
	 * rack_pacing stack assumes tv always refers to 'now', so we overwrite
	 * tv here to guarantee that.
	 */
	if (m->m_flags & M_TSTMP_LRO)
		tcp_get_usecs(tv);

	cts = tcp_tv_to_mssectick(tv);
	rack = (struct tcp_rack *)tp->t_fb_ptr;

	if ((m->m_flags & M_TSTMP) ||
	    (m->m_flags & M_TSTMP_LRO)) {
		mbuf_tstmp2timespec(m, &ts);
		rack->r_ctl.act_rcv_time.tv_sec = ts.tv_sec;
		rack->r_ctl.act_rcv_time.tv_usec = ts.tv_nsec/1000;
	} else
		rack->r_ctl.act_rcv_time = *tv;
	kern_prefetch(rack, &prev_state);
	prev_state = 0;
	thflags = th->th_flags;

	NET_EPOCH_ASSERT();
	INP_WLOCK_ASSERT(tp->t_inpcb);
	KASSERT(tp->t_state > TCPS_LISTEN, ("%s: TCPS_LISTEN",
	    __func__));
	KASSERT(tp->t_state != TCPS_TIME_WAIT, ("%s: TCPS_TIME_WAIT",
	    __func__));
	if (tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval ltv;
#ifdef NETFLIX_HTTP_LOGGING
		struct http_sendfile_track *http_req;

		if (SEQ_GT(th->th_ack, tp->snd_una)) {
			http_req = tcp_http_find_req_for_seq(tp, (th->th_ack-1));
		} else {
			http_req = tcp_http_find_req_for_seq(tp, th->th_ack);
		}
#endif
		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		if (rack->rack_no_prr == 0)
			log.u_bbr.flex1 = rack->r_ctl.rc_prr_sndcnt;
		else
			log.u_bbr.flex1 = 0;
		log.u_bbr.flex2 = rack->r_ctl.rc_num_maps_alloced;
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		log.u_bbr.pkts_out = rack->rc_tp->t_maxseg;
		log.u_bbr.flex3 = m->m_flags;
		log.u_bbr.flex4 = rack->r_ctl.rc_hpts_flags;
		if (m->m_flags & M_TSTMP) {
			/* Record the hardware timestamp if present */
			mbuf_tstmp2timespec(m, &ts);
			ltv.tv_sec = ts.tv_sec;
			ltv.tv_usec = ts.tv_nsec / 1000;
			log.u_bbr.lt_epoch = tcp_tv_to_usectick(&ltv);
		} else if (m->m_flags & M_TSTMP_LRO) {
			/* Record the LRO the arrival timestamp */
			mbuf_tstmp2timespec(m, &ts);
			ltv.tv_sec = ts.tv_sec;
			ltv.tv_usec = ts.tv_nsec / 1000;
			log.u_bbr.flex5 = tcp_tv_to_usectick(&ltv);
		}
		log.u_bbr.timeStamp = tcp_get_usecs(&ltv);
		/* Log the rcv time */
		log.u_bbr.delRate = m->m_pkthdr.rcv_tstmp;
#ifdef NETFLIX_HTTP_LOGGING
		log.u_bbr.applimited = tp->t_http_closed;
		log.u_bbr.applimited <<= 8;
		log.u_bbr.applimited |= tp->t_http_open;
		log.u_bbr.applimited <<= 8;
		log.u_bbr.applimited |= tp->t_http_req;
		if (http_req) {
			/* Copy out any client req info */
			/* seconds */
			log.u_bbr.pkt_epoch = (http_req->localtime / HPTS_USEC_IN_SEC);
			/* useconds */
			log.u_bbr.delivered = (http_req->localtime % HPTS_USEC_IN_SEC);
			log.u_bbr.rttProp = http_req->timestamp;
			log.u_bbr.cur_del_rate = http_req->start;
			if (http_req->flags & TCP_HTTP_TRACK_FLG_OPEN) {
				log.u_bbr.flex8 |= 1;
			} else {
				log.u_bbr.flex8 |= 2;
				log.u_bbr.bw_inuse = http_req->end;
			}
			log.u_bbr.flex6 = http_req->start_seq;
			if (http_req->flags & TCP_HTTP_TRACK_FLG_COMP) {
				log.u_bbr.flex8 |= 4;
				log.u_bbr.epoch = http_req->end_seq;
			}
		}
#endif
		TCP_LOG_EVENTP(tp, th, &so->so_rcv, &so->so_snd, TCP_LOG_IN, 0,
		    tlen, &log, true, &ltv);
	}
	if ((thflags & TH_SYN) && (thflags & TH_FIN) && V_drop_synfin) {
		way_out = 4;
		retval = 0;
		goto done_with_input;
	}
	/*
	 * If a segment with the ACK-bit set arrives in the SYN-SENT state
	 * check SEQ.ACK first as described on page 66 of RFC 793, section 3.9.
	 */
	if ((tp->t_state == TCPS_SYN_SENT) && (thflags & TH_ACK) &&
	    (SEQ_LEQ(th->th_ack, tp->iss) || SEQ_GT(th->th_ack, tp->snd_max))) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return(1);
	}
	/*
	 * Segment received on connection. Reset idle time and keep-alive
	 * timer. XXX: This should be done after segment validation to
	 * ignore broken/spoofed segs.
	 */
	if  (tp->t_idle_reduce &&
	     (tp->snd_max == tp->snd_una) &&
	     ((ticks - tp->t_rcvtime) >= tp->t_rxtcur)) {
		counter_u64_add(rack_input_idle_reduces, 1);
		rack_cc_after_idle(rack, tp);
	}
	tp->t_rcvtime = ticks;
	/*
	 * Unscale the window into a 32-bit value. For the SYN_SENT state
	 * the scale is zero.
	 */
	tiwin = th->th_win << tp->snd_scale;
#ifdef STATS
	stats_voi_update_abs_ulong(tp->t_stats, VOI_TCP_FRWIN, tiwin);
#endif
	if (tiwin > rack->r_ctl.rc_high_rwnd)
		rack->r_ctl.rc_high_rwnd = tiwin;
	/*
	 * TCP ECN processing. XXXJTL: If we ever use ECN, we need to move
	 * this to occur after we've validated the segment.
	 */
	if (tp->t_flags2 & TF2_ECN_PERMIT) {
		if (thflags & TH_CWR) {
			tp->t_flags2 &= ~TF2_ECN_SND_ECE;
			tp->t_flags |= TF_ACKNOW;
		}
		switch (iptos & IPTOS_ECN_MASK) {
		case IPTOS_ECN_CE:
			tp->t_flags2 |= TF2_ECN_SND_ECE;
			KMOD_TCPSTAT_INC(tcps_ecn_ce);
			break;
		case IPTOS_ECN_ECT0:
			KMOD_TCPSTAT_INC(tcps_ecn_ect0);
			break;
		case IPTOS_ECN_ECT1:
			KMOD_TCPSTAT_INC(tcps_ecn_ect1);
			break;
		}

		/* Process a packet differently from RFC3168. */
		cc_ecnpkt_handler(tp, th, iptos);

		/* Congestion experienced. */
		if (thflags & TH_ECE) {
			rack_cong_signal(tp, th, CC_ECN);
		}
	}
	/*
	 * Parse options on any incoming segment.
	 */
	tcp_dooptions(&to, (u_char *)(th + 1),
	    (th->th_off << 2) - sizeof(struct tcphdr),
	    (thflags & TH_SYN) ? TO_SYN : 0);

	/*
	 * If echoed timestamp is later than the current time, fall back to
	 * non RFC1323 RTT calculation.  Normalize timestamp if syncookies
	 * were used when this connection was established.
	 */
	if ((to.to_flags & TOF_TS) && (to.to_tsecr != 0)) {
		to.to_tsecr -= tp->ts_offset;
		if (TSTMP_GT(to.to_tsecr, cts))
			to.to_tsecr = 0;
	}

	/*
	 * If its the first time in we need to take care of options and
	 * verify we can do SACK for rack!
	 */
	if (rack->r_state == 0) {
		/* Should be init'd by rack_init() */
		KASSERT(rack->rc_inp != NULL,
		    ("%s: rack->rc_inp unexpectedly NULL", __func__));
		if (rack->rc_inp == NULL) {
			rack->rc_inp = tp->t_inpcb;
		}

		/*
		 * Process options only when we get SYN/ACK back. The SYN
		 * case for incoming connections is handled in tcp_syncache.
		 * According to RFC1323 the window field in a SYN (i.e., a
		 * <SYN> or <SYN,ACK>) segment itself is never scaled. XXX
		 * this is traditional behavior, may need to be cleaned up.
		 */
		if (tp->t_state == TCPS_SYN_SENT && (thflags & TH_SYN)) {
			/* Handle parallel SYN for ECN */
			if (!(thflags & TH_ACK) &&
			    ((thflags & (TH_CWR | TH_ECE)) == (TH_CWR | TH_ECE)) &&
			    ((V_tcp_do_ecn == 1) || (V_tcp_do_ecn == 2))) {
				tp->t_flags2 |= TF2_ECN_PERMIT;
				tp->t_flags2 |= TF2_ECN_SND_ECE;
				TCPSTAT_INC(tcps_ecn_shs);
			}
			if ((to.to_flags & TOF_SCALE) &&
			    (tp->t_flags & TF_REQ_SCALE)) {
				tp->t_flags |= TF_RCVD_SCALE;
				tp->snd_scale = to.to_wscale;
			} else
				tp->t_flags &= ~TF_REQ_SCALE;
			/*
			 * Initial send window.  It will be updated with the
			 * next incoming segment to the scaled value.
			 */
			tp->snd_wnd = th->th_win;
			if ((to.to_flags & TOF_TS) &&
			    (tp->t_flags & TF_REQ_TSTMP)) {
				tp->t_flags |= TF_RCVD_TSTMP;
				tp->ts_recent = to.to_tsval;
				tp->ts_recent_age = cts;
			} else
				tp->t_flags &= ~TF_REQ_TSTMP;
			if (to.to_flags & TOF_MSS)
				tcp_mss(tp, to.to_mss);
			if ((tp->t_flags & TF_SACK_PERMIT) &&
			    (to.to_flags & TOF_SACKPERM) == 0)
				tp->t_flags &= ~TF_SACK_PERMIT;
			if (IS_FASTOPEN(tp->t_flags)) {
				if (to.to_flags & TOF_FASTOPEN) {
					uint16_t mss;

					if (to.to_flags & TOF_MSS)
						mss = to.to_mss;
					else
						if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0)
							mss = TCP6_MSS;
						else
							mss = TCP_MSS;
					tcp_fastopen_update_cache(tp, mss,
					    to.to_tfo_len, to.to_tfo_cookie);
				} else
					tcp_fastopen_disable_path(tp);
			}
		}
		/*
		 * At this point we are at the initial call. Here we decide
		 * if we are doing RACK or not. We do this by seeing if
		 * TF_SACK_PERMIT is set and the sack-not-required is clear.
		 * The code now does do dup-ack counting so if you don't
		 * switch back you won't get rack & TLP, but you will still
		 * get this stack.
		 */

		if ((rack_sack_not_required == 0) &&
		    ((tp->t_flags & TF_SACK_PERMIT) == 0)) {
			tcp_switch_back_to_default(tp);
			(*tp->t_fb->tfb_tcp_do_segment) (m, th, so, tp, drop_hdrlen,
			    tlen, iptos);
			return (1);
		}
		/* Set the flag */
		rack->r_is_v6 = (tp->t_inpcb->inp_vflag & INP_IPV6) != 0;
		tcp_set_hpts(tp->t_inpcb);
		sack_filter_clear(&rack->r_ctl.rack_sf, th->th_ack);
	}
	if (thflags & TH_FIN)
		tcp_log_end_status(tp, TCP_EI_STATUS_CLIENT_FIN);
	us_cts = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
	if ((rack->rc_gp_dyn_mul) &&
	    (rack->use_fixed_rate == 0) &&
	    (rack->rc_always_pace)) {
		/* Check in on probertt */
		rack_check_probe_rtt(rack, us_cts);
	}
	if (rack->forced_ack) {
		uint32_t us_rtt;

		/*
		 * A persist or keep-alive was forced out, update our
		 * min rtt time. Note we do not worry about lost
		 * retransmissions since KEEP-ALIVES and persists
		 * are usually way long on times of sending (though
		 * if we were really paranoid or worried we could
		 * at least use timestamps if available to validate).
		 */
		rack->forced_ack = 0;
		us_rtt = us_cts - rack->r_ctl.forced_ack_ts;
		if (us_rtt == 0)
			us_rtt = 1;
		rack_log_rtt_upd(tp, rack, us_rtt, 0, NULL, 3);
		rack_apply_updated_usrtt(rack, us_rtt, us_cts);
	}
	/*
	 * This is the one exception case where we set the rack state
	 * always. All other times (timers etc) we must have a rack-state
	 * set (so we assure we have done the checks above for SACK).
	 */
	rack->r_ctl.rc_rcvtime = cts;
	if (rack->r_state != tp->t_state)
		rack_set_state(tp, rack);
	if (SEQ_GT(th->th_ack, tp->snd_una) &&
	    (rsm = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree)) != NULL)
		kern_prefetch(rsm, &prev_state);
	prev_state = rack->r_state;
	rack_clear_rate_sample(rack);
	retval = (*rack->r_substate) (m, th, so,
	    tp, &to, drop_hdrlen,
	    tlen, tiwin, thflags, nxt_pkt, iptos);
#ifdef INVARIANTS
	if ((retval == 0) &&
	    (tp->t_inpcb == NULL)) {
		panic("retval:%d tp:%p t_inpcb:NULL state:%d",
		    retval, tp, prev_state);
	}
#endif
	if (retval == 0) {
		/*
		 * If retval is 1 the tcb is unlocked and most likely the tp
		 * is gone.
		 */
		INP_WLOCK_ASSERT(tp->t_inpcb);
		if ((rack->rc_gp_dyn_mul) &&
		    (rack->rc_always_pace) &&
		    (rack->use_fixed_rate == 0) &&
		    rack->in_probe_rtt &&
		    (rack->r_ctl.rc_time_probertt_starts == 0)) {
			/*
			 * If we are going for target, lets recheck before
			 * we output.
			 */
			rack_check_probe_rtt(rack, us_cts);
		}
		if (rack->set_pacing_done_a_iw == 0) {
			/* How much has been acked? */
			if ((tp->snd_una - tp->iss) > (ctf_fixed_maxseg(tp) * 10)) {
				/* We have enough to set in the pacing segment size */
				rack->set_pacing_done_a_iw = 1;
				rack_set_pace_segments(tp, rack, __LINE__);
			}
		}
		tcp_rack_xmit_timer_commit(rack, tp);
		if (nxt_pkt == 0) {
			if (rack->r_wanted_output != 0) {
do_output_now:
				did_out = 1;
				(void)tp->t_fb->tfb_tcp_output(tp);
			}
			rack_start_hpts_timer(rack, tp, cts, 0, 0, 0);
		}
		if ((nxt_pkt == 0) &&
		    ((rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK) == 0) &&
		    (SEQ_GT(tp->snd_max, tp->snd_una) ||
		     (tp->t_flags & TF_DELACK) ||
		     ((V_tcp_always_keepalive || rack->rc_inp->inp_socket->so_options & SO_KEEPALIVE) &&
		      (tp->t_state <= TCPS_CLOSING)))) {
			/* We could not send (probably in the hpts but stopped the timer earlier)? */
			if ((tp->snd_max == tp->snd_una) &&
			    ((tp->t_flags & TF_DELACK) == 0) &&
			    (rack->rc_inp->inp_in_hpts) &&
			    (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {
				/* keep alive not needed if we are hptsi output yet */
				;
			} else {
				int late = 0;
				if (rack->rc_inp->inp_in_hpts) {
					if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) {
						us_cts = tcp_get_usecs(NULL);
						if (TSTMP_GT(rack->r_ctl.rc_last_output_to, us_cts)) {
							rack->r_early = 1;
							rack->r_ctl.rc_agg_early += (rack->r_ctl.rc_last_output_to - us_cts);
						} else
							late = 1;
						rack->r_ctl.rc_hpts_flags &= ~PACE_PKT_OUTPUT;
					}
					tcp_hpts_remove(tp->t_inpcb, HPTS_REMOVE_OUTPUT);
				}
				if (late && (did_out == 0)) {
					/*
					 * We are late in the sending
					 * and we did not call the output
					 * (this probably should not happen).
					 */
					goto do_output_now;
				}
				rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), 0, 0, 0);
			}
			way_out = 1;
		} else if (nxt_pkt == 0) {
			/* Do we have the correct timer running? */
			rack_timer_audit(tp, rack, &so->so_snd);
			way_out = 2;
		}
	done_with_input:
		rack_log_doseg_done(rack, cts, nxt_pkt, did_out, way_out);
		if (did_out)
			rack->r_wanted_output = 0;
#ifdef INVARIANTS
		if (tp->t_inpcb == NULL) {
			panic("OP:%d retval:%d tp:%p t_inpcb:NULL state:%d",
			      did_out,
			      retval, tp, prev_state);
		}
#endif
	}
	return (retval);
}

void
rack_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos)
{
	struct timeval tv;

	/* First lets see if we have old packets */
	if (tp->t_in_pkt) {
		if (ctf_do_queued_segments(so, tp, 1)) {
			m_freem(m);
			return;
		}
	}
	if (m->m_flags & M_TSTMP_LRO) {
		tv.tv_sec = m->m_pkthdr.rcv_tstmp /1000000000;
		tv.tv_usec = (m->m_pkthdr.rcv_tstmp % 1000000000)/1000;
	} else {
		/* Should not be should we kassert instead? */
		tcp_get_usecs(&tv);
	}
	if(rack_do_segment_nounlock(m, th, so, tp,
				    drop_hdrlen, tlen, iptos, 0, &tv) == 0)
		INP_WUNLOCK(tp->t_inpcb);
}

struct rack_sendmap *
tcp_rack_output(struct tcpcb *tp, struct tcp_rack *rack, uint32_t tsused)
{
	struct rack_sendmap *rsm = NULL;
	int32_t idx;
	uint32_t srtt = 0, thresh = 0, ts_low = 0;

	/* Return the next guy to be re-transmitted */
	if (RB_EMPTY(&rack->r_ctl.rc_mtree)) {
		return (NULL);
	}
	if (tp->t_flags & TF_SENTFIN) {
		/* retran the end FIN? */
		return (NULL);
	}
	/* ok lets look at this one */
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm && ((rsm->r_flags & RACK_ACKED) == 0)) {
		goto check_it;
	}
	rsm = rack_find_lowest_rsm(rack);
	if (rsm == NULL) {
		return (NULL);
	}
check_it:
	if (rsm->r_flags & RACK_ACKED) {
		return (NULL);
	}
	if ((rsm->r_flags & RACK_SACK_PASSED) == 0) {
		/* Its not yet ready */
		return (NULL);
	}
	srtt = rack_grab_rtt(tp, rack);
	idx = rsm->r_rtr_cnt - 1;
	ts_low = rsm->r_tim_lastsent[idx];
	thresh = rack_calc_thresh_rack(rack, srtt, tsused);
	if ((tsused == ts_low) ||
	    (TSTMP_LT(tsused, ts_low))) {
		/* No time since sending */
		return (NULL);
	}
	if ((tsused - ts_low) < thresh) {
		/* It has not been long enough yet */
		return (NULL);
	}
	if ((rsm->r_dupack >= DUP_ACK_THRESHOLD) ||
	    ((rsm->r_flags & RACK_SACK_PASSED) &&
	     (rack->sack_attack_disable == 0))) {
		/*
		 * We have passed the dup-ack threshold <or>
		 * a SACK has indicated this is missing.
		 * Note that if you are a declared attacker
		 * it is only the dup-ack threshold that
		 * will cause retransmits.
		 */
		/* log retransmit reason */
		rack_log_retran_reason(rack, rsm, (tsused - ts_low), thresh, 1);
		return (rsm);
	}
	return (NULL);
}

static void
rack_log_pacing_delay_calc(struct tcp_rack *rack, uint32_t len, uint32_t slot,
			   uint64_t bw_est, uint64_t bw, uint64_t len_time, int method,
			   int line, struct rack_sendmap *rsm)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = slot;
		log.u_bbr.flex2 = len;
		log.u_bbr.flex3 = rack->r_ctl.rc_pace_min_segs;
		log.u_bbr.flex4 = rack->r_ctl.rc_pace_max_segs;
		log.u_bbr.flex5 = rack->r_ctl.rack_per_of_gp_ss;
		log.u_bbr.flex6 = rack->r_ctl.rack_per_of_gp_ca;
		log.u_bbr.use_lt_bw = rack->app_limited_needs_set;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw = rack->rc_gp_filled;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->measure_saw_probe_rtt;
		log.u_bbr.use_lt_bw <<= 1;
		log.u_bbr.use_lt_bw |= rack->in_probe_rtt;
		log.u_bbr.pkt_epoch = line;
		log.u_bbr.applimited = rack->r_ctl.rack_per_of_gp_rec;
		log.u_bbr.bw_inuse = bw_est;
		log.u_bbr.delRate = bw;
		if (rack->r_ctl.gp_bw == 0)
			log.u_bbr.cur_del_rate = 0;
		else
			log.u_bbr.cur_del_rate = rack_get_bw(rack);
		log.u_bbr.rttProp = len_time;
		log.u_bbr.pkts_out = rack->r_ctl.rc_rack_min_rtt;
		log.u_bbr.lost = rack->r_ctl.rc_probertt_sndmax_atexit;
		log.u_bbr.pacing_gain = rack_get_output_gain(rack, rsm);
		if (rack->r_ctl.cwnd_to_use < rack->rc_tp->snd_ssthresh) {
			/* We are in slow start */
			log.u_bbr.flex7 = 1;
		} else {
			/* we are on congestion avoidance */
			log.u_bbr.flex7 = 0;
		}
		log.u_bbr.flex8 = method;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		log.u_bbr.cwnd_gain = rack->rc_gp_saw_rec;
		log.u_bbr.cwnd_gain <<= 1;
		log.u_bbr.cwnd_gain |= rack->rc_gp_saw_ss;
		log.u_bbr.cwnd_gain <<= 1;
		log.u_bbr.cwnd_gain |= rack->rc_gp_saw_ca;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_HPTSI_CALC, 0,
		    0, &log, false, &tv);
	}
}

static uint32_t
rack_get_pacing_len(struct tcp_rack *rack, uint64_t bw, uint32_t mss)
{
	uint32_t new_tso, user_max;

	user_max = rack->rc_user_set_max_segs * mss;
	if (rack->rc_force_max_seg) {
		return (user_max);
	}
	if (rack->use_fixed_rate &&
	    ((rack->r_ctl.crte == NULL) ||
	     (bw != rack->r_ctl.crte->rate))) {
		/* Use the user mss since we are not exactly matched */
		return (user_max);
	}
	new_tso = tcp_get_pacing_burst_size(bw, mss, rack_pace_one_seg, rack->r_ctl.crte, NULL);
	if (new_tso > user_max)
		new_tso = user_max;
	return(new_tso);
}

static void
rack_log_hdwr_pacing(struct tcp_rack *rack, const struct ifnet *ifp,
		     uint64_t rate, uint64_t hw_rate, int line,
		     int error)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = ((hw_rate >> 32) & 0x00000000ffffffff);
		log.u_bbr.flex2 = (hw_rate & 0x00000000ffffffff);
		log.u_bbr.flex3 = (((uint64_t)ifp  >> 32) & 0x00000000ffffffff);
		log.u_bbr.flex4 = ((uint64_t)ifp & 0x00000000ffffffff);
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.bw_inuse = rate;
		log.u_bbr.flex5 = line;
		log.u_bbr.flex6 = error;
		log.u_bbr.applimited = rack->r_ctl.rc_pace_max_segs;
		log.u_bbr.flex8 = rack->use_fixed_rate;
		log.u_bbr.flex8 <<= 1;
		log.u_bbr.flex8 |= rack->rack_hdrw_pacing;
		log.u_bbr.pkts_out = rack->rc_tp->t_maxseg;
		TCP_LOG_EVENTP(rack->rc_tp, NULL,
		    &rack->rc_inp->inp_socket->so_rcv,
		    &rack->rc_inp->inp_socket->so_snd,
		    BBR_LOG_HDWR_PACE, 0,
		    0, &log, false, &tv);
	}
}

static int32_t
pace_to_fill_cwnd(struct tcp_rack *rack, int32_t slot, uint32_t len, uint32_t segsiz)
{
	uint64_t lentim, fill_bw;

	/* Lets first see if we are full, if so continue with normal rate */
	if (ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked) > rack->r_ctl.cwnd_to_use)
		return (slot);
	if ((ctf_outstanding(rack->rc_tp) + (segsiz-1)) > rack->rc_tp->snd_wnd)
		return (slot);
	if (rack->r_ctl.rc_last_us_rtt == 0)
		return (slot);
	if (rack->rc_pace_fill_if_rttin_range &&
	    (rack->r_ctl.rc_last_us_rtt >=
	     (get_filter_value_small(&rack->r_ctl.rc_gp_min_rtt) * rack->rtt_limit_mul))) {
		/* The rtt is huge, N * smallest, lets not fill */
		return (slot);
	}
	/*
	 * first lets calculate the b/w based on the last us-rtt
	 * and the sndwnd.
	 */
	fill_bw = rack->r_ctl.cwnd_to_use;
	/* Take the rwnd if its smaller */
	if (fill_bw > rack->rc_tp->snd_wnd)
		fill_bw = rack->rc_tp->snd_wnd;
	fill_bw *= (uint64_t)HPTS_USEC_IN_SEC;
	fill_bw /= (uint64_t)rack->r_ctl.rc_last_us_rtt;
	/* We are below the min b/w */
	if (fill_bw < RACK_MIN_BW)
		return (slot);
	/*
	 * Ok fill_bw holds our mythical b/w to fill the cwnd
	 * in a rtt, what does that time wise equate too?
	 */
	lentim = (uint64_t)(len) * (uint64_t)HPTS_USEC_IN_SEC;
	lentim /= fill_bw;
	if (lentim < slot) {
		rack_log_pacing_delay_calc(rack, len, slot, fill_bw,
					   0, lentim, 12, __LINE__, NULL);
		return ((int32_t)lentim);
	} else
		return (slot);
}

static int32_t
rack_get_pacing_delay(struct tcp_rack *rack, struct tcpcb *tp, uint32_t len, struct rack_sendmap *rsm, uint32_t segsiz)
{
	struct rack_sendmap *lrsm;
	int32_t slot = 0;
	int err;

	if (rack->rc_always_pace == 0) {
		/*
		 * We use the most optimistic possible cwnd/srtt for
		 * sending calculations. This will make our
		 * calculation anticipate getting more through
		 * quicker then possible. But thats ok we don't want
		 * the peer to have a gap in data sending.
		 */
		uint32_t srtt, cwnd, tr_perms = 0;
		int32_t reduce = 0;

	old_method:
		/*
		 * We keep no precise pacing with the old method
		 * instead we use the pacer to mitigate bursts.
		 */
		rack->r_ctl.rc_agg_delayed = 0;
		rack->r_early = 0;
		rack->r_late = 0;
		rack->r_ctl.rc_agg_early = 0;
		if (rack->r_ctl.rc_rack_min_rtt)
			srtt = rack->r_ctl.rc_rack_min_rtt;
		else
			srtt = TICKS_2_MSEC((tp->t_srtt >> TCP_RTT_SHIFT));
		if (rack->r_ctl.rc_rack_largest_cwnd)
			cwnd = rack->r_ctl.rc_rack_largest_cwnd;
		else
			cwnd = rack->r_ctl.cwnd_to_use;
		tr_perms = cwnd / srtt;
		if (tr_perms == 0) {
			tr_perms = ctf_fixed_maxseg(tp);
		}
		/*
		 * Calculate how long this will take to drain, if
		 * the calculation comes out to zero, thats ok we
		 * will use send_a_lot to possibly spin around for
		 * more increasing tot_len_this_send to the point
		 * that its going to require a pace, or we hit the
		 * cwnd. Which in that case we are just waiting for
		 * a ACK.
		 */
		slot = len / tr_perms;
		/* Now do we reduce the time so we don't run dry? */
		if (slot && rack_slot_reduction) {
			reduce = (slot / rack_slot_reduction);
			if (reduce < slot) {
				slot -= reduce;
			} else
				slot = 0;
		}
		slot *=  HPTS_USEC_IN_MSEC;
		if (rsm == NULL) {
			/*
			 * We always consider ourselves app limited with old style
			 * that are not retransmits. This could be the initial
			 * measurement, but thats ok its all setup and specially
			 * handled. If another send leaks out, then that too will
			 * be mark app-limited.
			 */
			lrsm = RB_MAX(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
			if (lrsm && ((lrsm->r_flags & RACK_APP_LIMITED) == 0)) {
				rack->r_ctl.rc_first_appl = lrsm;
				lrsm->r_flags |= RACK_APP_LIMITED;
				rack->r_ctl.rc_app_limited_cnt++;
			}
		}
		rack_log_pacing_delay_calc(rack, len, slot, tr_perms, reduce, 0, 7, __LINE__, NULL);
	} else {
		uint64_t bw_est, res, lentim, rate_wanted;
		uint32_t orig_val, srtt, segs, oh;

		if ((rack->r_rr_config == 1) && rsm) {
			return (rack->r_ctl.rc_min_to * HPTS_USEC_IN_MSEC);
		}
		if (rack->use_fixed_rate) {
			rate_wanted = bw_est = rack_get_fixed_pacing_bw(rack);
		} else if ((rack->r_ctl.init_rate == 0) &&
#ifdef NETFLIX_PEAKRATE
			   (rack->rc_tp->t_maxpeakrate == 0) &&
#endif
			   (rack->r_ctl.gp_bw == 0)) {
			/* no way to yet do an estimate */
			bw_est = rate_wanted = 0;
		} else {
			bw_est = rack_get_bw(rack);
			rate_wanted = rack_get_output_bw(rack, bw_est, rsm);
		}
		if ((bw_est == 0) || (rate_wanted == 0)) {
			/*
			 * No way yet to make a b/w estimate or
			 * our raise is set incorrectly.
			 */
			goto old_method;
		}
		/* We need to account for all the overheads */
		segs = (len + segsiz - 1) / segsiz;
		/*
		 * We need the diff between 1514 bytes (e-mtu with e-hdr)
		 * and how much data we put in each packet. Yes this
		 * means we may be off if we are larger than 1500 bytes
		 * or smaller. But this just makes us more conservative.
		 */
		if (ETHERNET_SEGMENT_SIZE > segsiz)
			oh = ETHERNET_SEGMENT_SIZE - segsiz;
		else
			oh = 0;
		segs *= oh;
		lentim = (uint64_t)(len + segs)  * (uint64_t)HPTS_USEC_IN_SEC;
		res = lentim / rate_wanted;
		slot = (uint32_t)res;
		orig_val = rack->r_ctl.rc_pace_max_segs;
		rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
#ifdef KERN_TLS
		/* For TLS we need to override this, possibly  */
		if (rack->rc_inp->inp_socket->so_snd.sb_flags & SB_TLS_IFNET) {
			rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
		}
#endif
		/* Did we change the TSO size, if so log it */
		if (rack->r_ctl.rc_pace_max_segs != orig_val)
			rack_log_pacing_delay_calc(rack, len, slot, orig_val, 0, 0, 15, __LINE__, NULL);
		if ((rack->rc_pace_to_cwnd) &&
		    (rack->in_probe_rtt == 0) &&
		    (IN_RECOVERY(rack->rc_tp->t_flags) == 0)) {
			/*
			 * We want to pace at our rate *or* faster to
			 * fill the cwnd to the max if its not full.
			 */
			slot = pace_to_fill_cwnd(rack, slot, (len+segs), segsiz);
		}
		if ((rack->rc_inp->inp_route.ro_nh != NULL) &&
		    (rack->rc_inp->inp_route.ro_nh->nh_ifp != NULL)) {
			if ((rack->rack_hdw_pace_ena) &&
			    (rack->rack_hdrw_pacing == 0) &&
			    (rack->rack_attempt_hdwr_pace == 0)) {
				/*
				 * Lets attempt to turn on hardware pacing
				 * if we can.
				 */
				rack->rack_attempt_hdwr_pace = 1;
				rack->r_ctl.crte = tcp_set_pacing_rate(rack->rc_tp,
								       rack->rc_inp->inp_route.ro_nh->nh_ifp,
								       rate_wanted,
								       RS_PACING_GEQ,
								       &err);
				if (rack->r_ctl.crte) {
					rack->rack_hdrw_pacing = 1;
					rack->r_ctl.rc_pace_max_segs = tcp_get_pacing_burst_size(rate_wanted, segsiz,
												 0, rack->r_ctl.crte,
												 NULL);
					rack_log_hdwr_pacing(rack, rack->rc_inp->inp_route.ro_nh->nh_ifp,
							     rate_wanted, rack->r_ctl.crte->rate, __LINE__,
							     err);
				}
			} else if (rack->rack_hdrw_pacing &&
				   (rack->r_ctl.crte->rate != rate_wanted)) {
				/* Do we need to adjust our rate? */
				const struct tcp_hwrate_limit_table *nrte;

				nrte = tcp_chg_pacing_rate(rack->r_ctl.crte,
							   rack->rc_tp,
							   rack->rc_inp->inp_route.ro_nh->nh_ifp,
							   rate_wanted,
							   RS_PACING_GEQ,
							   &err);
				if (nrte == NULL) {
					/* Lost the rate */
					rack->rack_hdrw_pacing = 0;
					rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
				} else if (nrte != rack->r_ctl.crte) {
					rack->r_ctl.crte = nrte;
					rack->r_ctl.rc_pace_max_segs = tcp_get_pacing_burst_size(rate_wanted,
												 segsiz, 0,
												 rack->r_ctl.crte,
												 NULL);
					rack_log_hdwr_pacing(rack, rack->rc_inp->inp_route.ro_nh->nh_ifp,
							     rate_wanted, rack->r_ctl.crte->rate, __LINE__,
							     err);
				}

			}
		}
		if (rack_limit_time_with_srtt &&
		    (rack->use_fixed_rate == 0) &&
#ifdef NETFLIX_PEAKRATE
		    (rack->rc_tp->t_maxpeakrate == 0) &&
#endif
		    (rack->rack_hdrw_pacing == 0)) {
			/*
			 * Sanity check, we do not allow the pacing delay
			 * to be longer than the SRTT of the path. If it is
			 * a slow path, then adding a packet should increase
			 * the RTT and compensate for this i.e. the srtt will
			 * be greater so the allowed pacing time will be greater.
			 *
			 * Note this restriction is not for where a peak rate
			 * is set, we are doing fixed pacing or hardware pacing.
			 */
			if (rack->rc_tp->t_srtt)
				srtt = (TICKS_2_USEC(rack->rc_tp->t_srtt) >> TCP_RTT_SHIFT);
			else
				srtt = RACK_INITIAL_RTO * HPTS_USEC_IN_MSEC;	/* its in ms convert */
			if (srtt < slot) {
				rack_log_pacing_delay_calc(rack, srtt, slot, rate_wanted, bw_est, lentim, 99, __LINE__, NULL);
				slot = srtt;
			}
		}
		rack_log_pacing_delay_calc(rack, len, slot, rate_wanted, bw_est, lentim, 2, __LINE__, rsm);
	}
	if (slot)
		counter_u64_add(rack_calc_nonzero, 1);
	else
		counter_u64_add(rack_calc_zero, 1);
	return (slot);
}

static void
rack_start_gp_measurement(struct tcpcb *tp, struct tcp_rack *rack,
    tcp_seq startseq, uint32_t sb_offset)
{
	struct rack_sendmap *my_rsm = NULL;
	struct rack_sendmap fe;

	if (tp->t_state < TCPS_ESTABLISHED) {
		/*
		 * We don't start any measurements if we are
		 * not at least established.
		 */
		return;
	}
	tp->t_flags |= TF_GPUTINPROG;
	rack->r_ctl.rc_gp_lowrtt = 0xffffffff;
	rack->r_ctl.rc_gp_high_rwnd = rack->rc_tp->snd_wnd;
	tp->gput_seq = startseq;
	rack->app_limited_needs_set = 0;
	if (rack->in_probe_rtt)
		rack->measure_saw_probe_rtt = 1;
	else if ((rack->measure_saw_probe_rtt) &&
		 (SEQ_GEQ(tp->gput_seq, rack->r_ctl.rc_probertt_sndmax_atexit)))
		rack->measure_saw_probe_rtt = 0;
	if (rack->rc_gp_filled)
		tp->gput_ts = tcp_tv_to_usectick(&rack->r_ctl.act_rcv_time);
	else {
		/* Special case initial measurement */
		rack->r_ctl.rc_gp_output_ts = tp->gput_ts = tcp_get_usecs(NULL);
	}
	/*
	 * We take a guess out into the future,
	 * if we have no measurement and no
	 * initial rate, we measure the first
	 * initial-windows worth of data to
	 * speed up getting some GP measurement and
	 * thus start pacing.
	 */
	if ((rack->rc_gp_filled == 0) && (rack->r_ctl.init_rate == 0)) {
		rack->app_limited_needs_set = 1;
		tp->gput_ack = startseq + max(rc_init_window(rack),
					      (MIN_GP_WIN * ctf_fixed_maxseg(tp)));
		rack_log_pacing_delay_calc(rack,
					   tp->gput_seq,
					   tp->gput_ack,
					   0,
					   tp->gput_ts,
					   rack->r_ctl.rc_app_limited_cnt,
					   9,
					   __LINE__, NULL);
		return;
	}
	if (sb_offset) {
		/*
		 * We are out somewhere in the sb
		 * can we use the already outstanding data?
		 */

		if (rack->r_ctl.rc_app_limited_cnt == 0) {
			/*
			 * Yes first one is good and in this case
			 * the tp->gput_ts is correctly set based on
			 * the last ack that arrived (no need to
			 * set things up when an ack comes in).
			 */
			my_rsm = RB_MIN(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
			if ((my_rsm == NULL) ||
			    (my_rsm->r_rtr_cnt != 1)) {
				/* retransmission? */
				goto use_latest;
			}
		} else {
			if (rack->r_ctl.rc_first_appl == NULL) {
				/*
				 * If rc_first_appl is NULL
				 * then the cnt should be 0.
				 * This is probably an error, maybe
				 * a KASSERT would be approprate.
				 */
				goto use_latest;
			}
			/*
			 * If we have a marker pointer to the last one that is
			 * app limited we can use that, but we need to set
			 * things up so that when it gets ack'ed we record
			 * the ack time (if its not already acked).
			 */
			rack->app_limited_needs_set = 1;
			/*
			 * We want to get to the rsm that is either
			 * next with space i.e. over 1 MSS or the one
			 * after that (after the app-limited).
			 */
			my_rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree,
					 rack->r_ctl.rc_first_appl);
			if (my_rsm) {
				if ((my_rsm->r_end - my_rsm->r_start) <= ctf_fixed_maxseg(tp))
					/* Have to use the next one */
					my_rsm = RB_NEXT(rack_rb_tree_head, &rack->r_ctl.rc_mtree,
							 my_rsm);
				else {
					/* Use after the first MSS of it is acked */
					tp->gput_seq = my_rsm->r_start + ctf_fixed_maxseg(tp);
					goto start_set;
				}
			}
			if ((my_rsm == NULL) ||
			    (my_rsm->r_rtr_cnt != 1)) {
				/*
				 * Either its a retransmit or
				 * the last is the app-limited one.
				 */
				goto use_latest;
			}
		}
		tp->gput_seq = my_rsm->r_start;
start_set:
		if (my_rsm->r_flags & RACK_ACKED) {
			/*
			 * This one has been acked use the arrival ack time
			 */
			tp->gput_ts = my_rsm->r_ack_arrival;
			rack->app_limited_needs_set = 0;
		}
		rack->r_ctl.rc_gp_output_ts = my_rsm->usec_orig_send;
		tp->gput_ack = tp->gput_seq + rack_get_measure_window(tp, rack);
		rack_log_pacing_delay_calc(rack,
					   tp->gput_seq,
					   tp->gput_ack,
					   (uint64_t)my_rsm,
					   tp->gput_ts,
					   rack->r_ctl.rc_app_limited_cnt,
					   9,
					   __LINE__, NULL);
		return;
	}

use_latest:
	/*
	 * We don't know how long we may have been
	 * idle or if this is the first-send. Lets
	 * setup the flag so we will trim off
	 * the first ack'd data so we get a true
	 * measurement.
	 */
	rack->app_limited_needs_set = 1;
	tp->gput_ack = startseq + rack_get_measure_window(tp, rack);
	/* Find this guy so we can pull the send time */
	fe.r_start = startseq;
	my_rsm = RB_FIND(rack_rb_tree_head, &rack->r_ctl.rc_mtree, &fe);
	if (my_rsm) {
		rack->r_ctl.rc_gp_output_ts = my_rsm->usec_orig_send;
		if (my_rsm->r_flags & RACK_ACKED) {
			/*
			 * Unlikely since its probably what was
			 * just transmitted (but I am paranoid).
			 */
			tp->gput_ts = my_rsm->r_ack_arrival;
			rack->app_limited_needs_set = 0;
		}
		if (SEQ_LT(my_rsm->r_start, tp->gput_seq)) {
			/* This also is unlikely */
			tp->gput_seq = my_rsm->r_start;
		}
	} else {
		/*
		 * TSNH unless we have some send-map limit,
		 * and even at that it should not be hitting
		 * that limit (we should have stopped sending).
		 */
		rack->r_ctl.rc_gp_output_ts = tcp_get_usecs(NULL);
	}
	rack_log_pacing_delay_calc(rack,
				   tp->gput_seq,
				   tp->gput_ack,
				   (uint64_t)my_rsm,
				   tp->gput_ts,
				   rack->r_ctl.rc_app_limited_cnt,
				   9, __LINE__, NULL);
}

static inline uint32_t
rack_what_can_we_send(struct tcpcb *tp, struct tcp_rack *rack,  uint32_t cwnd_to_use,
    uint32_t avail, int32_t sb_offset)
{
	uint32_t len;
	uint32_t sendwin;

	if (tp->snd_wnd > cwnd_to_use)
		sendwin = cwnd_to_use;
	else
		sendwin = tp->snd_wnd;
	if (ctf_outstanding(tp) >= tp->snd_wnd) {
		/* We never want to go over our peers rcv-window */
		len = 0;
	} else {
		uint32_t flight;

		flight = ctf_flight_size(tp, rack->r_ctl.rc_sacked);
		if (flight >= sendwin) {
			/*
			 * We have in flight what we are allowed by cwnd (if
			 * it was rwnd blocking it would have hit above out
			 * >= tp->snd_wnd).
			 */
			return (0);
		}
		len = sendwin - flight;
		if ((len + ctf_outstanding(tp)) > tp->snd_wnd) {
			/* We would send too much (beyond the rwnd) */
			len = tp->snd_wnd - ctf_outstanding(tp);
		}
		if ((len + sb_offset) > avail) {
			/*
			 * We don't have that much in the SB, how much is
			 * there?
			 */
			len = avail - sb_offset;
		}
	}
	return (len);
}

static int
rack_output(struct tcpcb *tp)
{
	struct socket *so;
	uint32_t recwin;
	uint32_t sb_offset;
	int32_t len, flags, error = 0;
	struct mbuf *m;
	struct mbuf *mb;
	uint32_t if_hw_tsomaxsegcount = 0;
	uint32_t if_hw_tsomaxsegsize;
	int32_t segsiz, minseg;
	long tot_len_this_send = 0;
	struct ip *ip = NULL;
#ifdef TCPDEBUG
	struct ipovly *ipov = NULL;
#endif
	struct udphdr *udp = NULL;
	struct tcp_rack *rack;
	struct tcphdr *th;
	uint8_t pass = 0;
	uint8_t mark = 0;
	uint8_t wanted_cookie = 0;
	u_char opt[TCP_MAXOLEN];
	unsigned ipoptlen, optlen, hdrlen, ulen=0;
	uint32_t rack_seq;

#if defined(IPSEC) || defined(IPSEC_SUPPORT)
	unsigned ipsec_optlen = 0;

#endif
	int32_t idle, sendalot;
	int32_t sub_from_prr = 0;
	volatile int32_t sack_rxmit;
	struct rack_sendmap *rsm = NULL;
	int32_t tso, mtu;
	struct tcpopt to;
	int32_t slot = 0;
	int32_t sup_rack = 0;
	uint32_t cts, us_cts, delayed, early;
	uint8_t hpts_calling, new_data_tlp = 0, doing_tlp = 0;
	uint32_t cwnd_to_use;
	int32_t do_a_prefetch;
	int32_t prefetch_rsm = 0;
	int force_tso = 0;
	int32_t orig_len;
	struct timeval tv;
	int32_t prefetch_so_done = 0;
	struct tcp_log_buffer *lgb = NULL;
	struct inpcb *inp;
	struct sockbuf *sb;
#ifdef INET6
	struct ip6_hdr *ip6 = NULL;
	int32_t isipv6;
#endif
	uint8_t filled_all = 0;
	bool hw_tls = false;

	/* setup and take the cache hits here */
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	inp = rack->rc_inp;
	so = inp->inp_socket;
	sb = &so->so_snd;
	kern_prefetch(sb, &do_a_prefetch);
	do_a_prefetch = 1;
	hpts_calling = inp->inp_hpts_calls;
#ifdef KERN_TLS
	hw_tls = (so->so_snd.sb_flags & SB_TLS_IFNET) != 0;
#endif

	NET_EPOCH_ASSERT();
	INP_WLOCK_ASSERT(inp);
#ifdef TCP_OFFLOAD
	if (tp->t_flags & TF_TOE)
		return (tcp_offload_output(tp));
#endif
	/*
	 * For TFO connections in SYN_RECEIVED, only allow the initial
	 * SYN|ACK and those sent by the retransmit timer.
	 */
	if (IS_FASTOPEN(tp->t_flags) &&
	    (tp->t_state == TCPS_SYN_RECEIVED) &&
	    SEQ_GT(tp->snd_max, tp->snd_una) &&    /* initial SYN|ACK sent */
	    (rack->r_ctl.rc_resend == NULL))         /* not a retransmit */
		return (0);
#ifdef INET6
	if (rack->r_state) {
		/* Use the cache line loaded if possible */
		isipv6 = rack->r_is_v6;
	} else {
		isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
	}
#endif
	early = 0;
	us_cts = tcp_get_usecs(&tv);
	cts = tcp_tv_to_mssectick(&tv);
	if (((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0) &&
	    inp->inp_in_hpts) {
		/*
		 * We are on the hpts for some timer but not hptsi output.
		 * Remove from the hpts unconditionally.
		 */
		rack_timer_cancel(tp, rack, cts, __LINE__);
	}
	/* Are we pacing and late? */
	if ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) &&
	    TSTMP_GEQ(us_cts, rack->r_ctl.rc_last_output_to)) {
		/* We are delayed */
		delayed = us_cts - rack->r_ctl.rc_last_output_to;
	} else {
		delayed = 0;
	}
	/* Do the timers, which may override the pacer  */
	if (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK) {
		if (rack_process_timers(tp, rack, cts, hpts_calling)) {
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_ATIMER], 1);
			return (0);
		}
	}
	if ((rack->r_timer_override) ||
	    (delayed) ||
	    (tp->t_state < TCPS_ESTABLISHED)) {
		if (tp->t_inpcb->inp_in_hpts)
			tcp_hpts_remove(tp->t_inpcb, HPTS_REMOVE_OUTPUT);
	} else if (tp->t_inpcb->inp_in_hpts) {
		/*
		 * On the hpts you can't pass even if ACKNOW is on, we will
		 * when the hpts fires.
		 */
		counter_u64_add(rack_out_size[TCP_MSS_ACCT_INPACE], 1);
		return (0);
	}
	inp->inp_hpts_calls = 0;
	/* Finish out both pacing early and late accounting */
	if ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) &&
	    TSTMP_GT(rack->r_ctl.rc_last_output_to, us_cts)) {
		early = rack->r_ctl.rc_last_output_to - us_cts;
	} else
		early = 0;
	if (delayed) {
		rack->r_ctl.rc_agg_delayed += delayed;
		rack->r_late = 1;
	} else if (early) {
		rack->r_ctl.rc_agg_early += early;
		rack->r_early = 1;
	}
	/* Now that early/late accounting is done turn off the flag */
	rack->r_ctl.rc_hpts_flags &= ~PACE_PKT_OUTPUT;
	rack->r_wanted_output = 0;
	rack->r_timer_override = 0;
	/*
	 * For TFO connections in SYN_SENT or SYN_RECEIVED,
	 * only allow the initial SYN or SYN|ACK and those sent
	 * by the retransmit timer.
	 */
	if (IS_FASTOPEN(tp->t_flags) &&
	    ((tp->t_state == TCPS_SYN_RECEIVED) ||
	     (tp->t_state == TCPS_SYN_SENT)) &&
	    SEQ_GT(tp->snd_max, tp->snd_una) && /* initial SYN or SYN|ACK sent */
	    (tp->t_rxtshift == 0)) {              /* not a retransmit */
		cwnd_to_use = rack->r_ctl.cwnd_to_use = tp->snd_cwnd;
		goto just_return_nolock;
	}
	/*
	 * Determine length of data that should be transmitted, and flags
	 * that will be used. If there is some data or critical controls
	 * (SYN, RST) to send, then transmit; otherwise, investigate
	 * further.
	 */
	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);
	if (tp->t_idle_reduce) {
		if (idle && ((ticks - tp->t_rcvtime) >= tp->t_rxtcur))
			rack_cc_after_idle(rack, tp);
	}
	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}
	if ((tp->snd_una == tp->snd_max) &&
	    rack->r_ctl.rc_went_idle_time &&
	    TSTMP_GT(us_cts, rack->r_ctl.rc_went_idle_time)) {
		idle = us_cts - rack->r_ctl.rc_went_idle_time;
		if (idle > rack_min_probertt_hold) {
			/* Count as a probe rtt */
			if (rack->in_probe_rtt == 0) {
				rack->r_ctl.rc_lower_rtt_us_cts = us_cts;
				rack->r_ctl.rc_time_probertt_entered = rack->r_ctl.rc_lower_rtt_us_cts;
				rack->r_ctl.rc_time_probertt_starts = rack->r_ctl.rc_lower_rtt_us_cts;
				rack->r_ctl.rc_time_of_last_probertt = rack->r_ctl.rc_lower_rtt_us_cts;
			} else {
				rack_exit_probertt(rack, us_cts);
			}
		}
		idle = 0;
	}
again:
	/*
	 * If we've recently taken a timeout, snd_max will be greater than
	 * snd_nxt.  There may be SACK information that allows us to avoid
	 * resending already delivered data.  Adjust snd_nxt accordingly.
	 */
	sendalot = 0;
	us_cts = tcp_get_usecs(&tv);
	cts = tcp_tv_to_mssectick(&tv);
	tso = 0;
	mtu = 0;
	segsiz = min(ctf_fixed_maxseg(tp), rack->r_ctl.rc_pace_min_segs);
	if (so->so_snd.sb_flags & SB_TLS_IFNET) {
		minseg = rack->r_ctl.rc_pace_min_segs;
	} else {
		minseg = segsiz;
	}
	sb_offset = tp->snd_max - tp->snd_una;
	cwnd_to_use = rack->r_ctl.cwnd_to_use = tp->snd_cwnd;
#ifdef NETFLIX_SHARED_CWND
	if ((tp->t_flags2 & TF2_TCP_SCWND_ALLOWED) &&
	    rack->rack_enable_scwnd) {
		/* We are doing cwnd sharing */
		if (rack->rc_gp_filled &&
		    (rack->rack_attempted_scwnd == 0) &&
		    (rack->r_ctl.rc_scw == NULL) &&
		    tp->t_lib) {
			/* The pcbid is in, lets make an attempt */
			counter_u64_add(rack_try_scwnd, 1);
			rack->rack_attempted_scwnd = 1;
			rack->r_ctl.rc_scw = tcp_shared_cwnd_alloc(tp,
								   &rack->r_ctl.rc_scw_index,
								   segsiz);
		}
		if (rack->r_ctl.rc_scw &&
		    (rack->rack_scwnd_is_idle == 1) &&
		    (rack->rc_in_persist == 0) &&
		    sbavail(sb)) {
			/* we are no longer out of data */
			tcp_shared_cwnd_active(rack->r_ctl.rc_scw, rack->r_ctl.rc_scw_index);
			rack->rack_scwnd_is_idle = 0;
		}
		if (rack->r_ctl.rc_scw) {
			/* First lets update and get the cwnd */
			rack->r_ctl.cwnd_to_use = cwnd_to_use = tcp_shared_cwnd_update(rack->r_ctl.rc_scw,
								    rack->r_ctl.rc_scw_index,
								    tp->snd_cwnd, tp->snd_wnd, segsiz);
		}
	}
#endif
	flags = tcp_outflags[tp->t_state];
	while (rack->rc_free_cnt < rack_free_cache) {
		rsm = rack_alloc(rack);
		if (rsm == NULL) {
			if (inp->inp_hpts_calls)
				/* Retry in a ms */
				slot = (1 * HPTS_USEC_IN_MSEC);
			goto just_return_nolock;
		}
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_free, rsm, r_tnext);
		rack->rc_free_cnt++;
		rsm = NULL;
	}
	if (inp->inp_hpts_calls)
		inp->inp_hpts_calls = 0;
	sack_rxmit = 0;
	len = 0;
	rsm = NULL;
	if (flags & TH_RST) {
		SOCKBUF_LOCK(sb);
		goto send;
	}
	if (rack->r_ctl.rc_resend) {
		/* Retransmit timer */
		rsm = rack->r_ctl.rc_resend;
		rack->r_ctl.rc_resend = NULL;
		rsm->r_flags &= ~RACK_TLP;
		len = rsm->r_end - rsm->r_start;
		sack_rxmit = 1;
		sendalot = 0;
		KASSERT(SEQ_LEQ(tp->snd_una, rsm->r_start),
			("%s:%d: r.start:%u < SND.UNA:%u; tp:%p, rack:%p, rsm:%p",
			 __func__, __LINE__,
			 rsm->r_start, tp->snd_una, tp, rack, rsm));
		sb_offset = rsm->r_start - tp->snd_una;
		if (len >= segsiz)
			len = segsiz;
	} else if ((rack->rc_in_persist == 0) &&
		   ((rsm = tcp_rack_output(tp, rack, cts)) != NULL)) {
		/* We have a retransmit that takes precedence */
		rsm->r_flags &= ~RACK_TLP;
		if ((!IN_RECOVERY(tp->t_flags)) &&
		    ((tp->t_flags & (TF_WASFRECOVERY | TF_WASCRECOVERY)) == 0)) {
			/* Enter recovery if not induced by a time-out */
			rack->r_ctl.rc_rsm_start = rsm->r_start;
			rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
			rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
			rack_cong_signal(tp, NULL, CC_NDUPACK);
			/*
			 * When we enter recovery we need to assure we send
			 * one packet.
			 */
			if (rack->rack_no_prr == 0) {
				rack->r_ctl.rc_prr_sndcnt = segsiz;
				rack_log_to_prr(rack, 13, 0);
			}
		}
#ifdef INVARIANTS
		if (SEQ_LT(rsm->r_start, tp->snd_una)) {
			panic("Huh, tp:%p rack:%p rsm:%p start:%u < snd_una:%u\n",
			      tp, rack, rsm, rsm->r_start, tp->snd_una);
		}
#endif
		len = rsm->r_end - rsm->r_start;
		KASSERT(SEQ_LEQ(tp->snd_una, rsm->r_start),
			("%s:%d: r.start:%u < SND.UNA:%u; tp:%p, rack:%p, rsm:%p",
			 __func__, __LINE__,
			 rsm->r_start, tp->snd_una, tp, rack, rsm));
		sb_offset = rsm->r_start - tp->snd_una;
		/* Can we send it within the PRR boundary? */
		if (rack->rack_no_prr == 0) {
			if ((rack->use_rack_rr == 0) && (len > rack->r_ctl.rc_prr_sndcnt)) {
				/* It does not fit */
				if ((ctf_flight_size(tp, rack->r_ctl.rc_sacked) > len) &&
				    (rack->r_ctl.rc_prr_sndcnt < segsiz)) {
					/*
					 * prr is less than a segment, we
					 * have more acks due in besides
					 * what we need to resend. Lets not send
					 * to avoid sending small pieces of
					 * what we need to retransmit.
					 */
					len = 0;
					goto just_return_nolock;
				}
				len = rack->r_ctl.rc_prr_sndcnt;
			}
		}
		sendalot = 0;
		if (len >= segsiz)
			len = segsiz;
		if (len > 0) {
			sub_from_prr = 1;
			sack_rxmit = 1;
			KMOD_TCPSTAT_INC(tcps_sack_rexmits);
			KMOD_TCPSTAT_ADD(tcps_sack_rexmit_bytes,
			    min(len, segsiz));
			counter_u64_add(rack_rtm_prr_retran, 1);
		}
	} else 	if (rack->r_ctl.rc_tlpsend) {
		/* Tail loss probe */
		long cwin;
		long tlen;

		doing_tlp = 1;
		/*
		 * Check if we can do a TLP with a RACK'd packet
		 * this can happen if we are not doing the rack
		 * cheat and we skipped to a TLP and it
		 * went off.
		 */
		rsm = rack->r_ctl.rc_tlpsend;
		rsm->r_flags |= RACK_TLP;
		rack->r_ctl.rc_tlpsend = NULL;
		sack_rxmit = 1;
		tlen = rsm->r_end - rsm->r_start;
		if (tlen > segsiz)
			tlen = segsiz;
		KASSERT(SEQ_LEQ(tp->snd_una, rsm->r_start),
			("%s:%d: r.start:%u < SND.UNA:%u; tp:%p, rack:%p, rsm:%p",
			 __func__, __LINE__,
			 rsm->r_start, tp->snd_una, tp, rack, rsm));
		sb_offset = rsm->r_start - tp->snd_una;
		cwin = min(tp->snd_wnd, tlen);
		len = cwin;
	}
	/*
	 * Enforce a connection sendmap count limit if set
	 * as long as we are not retransmiting.
	 */
	if ((rsm == NULL) &&
	    (rack->do_detection == 0) &&
	    (V_tcp_map_entries_limit > 0) &&
	    (rack->r_ctl.rc_num_maps_alloced >= V_tcp_map_entries_limit)) {
		counter_u64_add(rack_to_alloc_limited, 1);
		if (!rack->alloc_limit_reported) {
			rack->alloc_limit_reported = 1;
			counter_u64_add(rack_alloc_limited_conns, 1);
		}
		goto just_return_nolock;
	}
	if (rsm && (rsm->r_flags & RACK_HAS_FIN)) {
		/* we are retransmitting the fin */
		len--;
		if (len) {
			/*
			 * When retransmitting data do *not* include the
			 * FIN. This could happen from a TLP probe.
			 */
			flags &= ~TH_FIN;
		}
	}
#ifdef INVARIANTS
	/* For debugging */
	rack->r_ctl.rc_rsm_at_retran = rsm;
#endif
	/*
	 * Get standard flags, and add SYN or FIN if requested by 'hidden'
	 * state flags.
	 */
	if (tp->t_flags & TF_NEEDFIN)
		flags |= TH_FIN;
	if (tp->t_flags & TF_NEEDSYN)
		flags |= TH_SYN;
	if ((sack_rxmit == 0) && (prefetch_rsm == 0)) {
		void *end_rsm;
		end_rsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_tmap, rack_sendmap, r_tnext);
		if (end_rsm)
			kern_prefetch(end_rsm, &prefetch_rsm);
		prefetch_rsm = 1;
	}
	SOCKBUF_LOCK(sb);
	/*
	 * If snd_nxt == snd_max and we have transmitted a FIN, the
	 * sb_offset will be > 0 even if so_snd.sb_cc is 0, resulting in a
	 * negative length.  This can also occur when TCP opens up its
	 * congestion window while receiving additional duplicate acks after
	 * fast-retransmit because TCP will reset snd_nxt to snd_max after
	 * the fast-retransmit.
	 *
	 * In the normal retransmit-FIN-only case, however, snd_nxt will be
	 * set to snd_una, the sb_offset will be 0, and the length may wind
	 * up 0.
	 *
	 * If sack_rxmit is true we are retransmitting from the scoreboard
	 * in which case len is already set.
	 */
	if ((sack_rxmit == 0) && TCPS_HAVEESTABLISHED(tp->t_state)) {
		uint32_t avail;

		avail = sbavail(sb);
		if (SEQ_GT(tp->snd_nxt, tp->snd_una) && avail)
			sb_offset = tp->snd_nxt - tp->snd_una;
		else
			sb_offset = 0;
		if ((IN_RECOVERY(tp->t_flags) == 0) || rack->rack_no_prr) {
			if (rack->r_ctl.rc_tlp_new_data) {
				/* TLP is forcing out new data */
				if (rack->r_ctl.rc_tlp_new_data > (uint32_t) (avail - sb_offset)) {
					rack->r_ctl.rc_tlp_new_data = (uint32_t) (avail - sb_offset);
				}
				if (rack->r_ctl.rc_tlp_new_data > tp->snd_wnd)
					len = tp->snd_wnd;
				else
					len = rack->r_ctl.rc_tlp_new_data;
				rack->r_ctl.rc_tlp_new_data = 0;
				new_data_tlp = doing_tlp = 1;
			}  else
				len = rack_what_can_we_send(tp, rack, cwnd_to_use, avail, sb_offset);
			if (IN_RECOVERY(tp->t_flags) && (len > segsiz)) {
				/*
				 * For prr=off, we need to send only 1 MSS
				 * at a time. We do this because another sack could
				 * be arriving that causes us to send retransmits and
				 * we don't want to be on a long pace due to a larger send
				 * that keeps us from sending out the retransmit.
				 */
				len = segsiz;
			}
		} else {
			uint32_t outstanding;

			/*
			 * We are inside of a SACK recovery episode and are
			 * sending new data, having retransmitted all the
			 * data possible so far in the scoreboard.
			 */
			outstanding = tp->snd_max - tp->snd_una;
			if ((rack->r_ctl.rc_prr_sndcnt + outstanding) > tp->snd_wnd) {
				if (tp->snd_wnd > outstanding) {
					len = tp->snd_wnd - outstanding;
					/* Check to see if we have the data */
					if ((sb_offset + len) > avail) {
						/* It does not all fit */
						if (avail > sb_offset)
							len = avail - sb_offset;
						else
							len = 0;
					}
				} else
					len = 0;
			} else if (avail > sb_offset)
				len = avail - sb_offset;
			else
				len = 0;
			if (len > 0) {
				if (len > rack->r_ctl.rc_prr_sndcnt)
					len = rack->r_ctl.rc_prr_sndcnt;
				if (len > 0) {
					sub_from_prr = 1;
					counter_u64_add(rack_rtm_prr_newdata, 1);
				}
			}
			if (len > segsiz) {
				/*
				 * We should never send more than a MSS when
				 * retransmitting or sending new data in prr
				 * mode unless the override flag is on. Most
				 * likely the PRR algorithm is not going to
				 * let us send a lot as well :-)
				 */
				if (rack->r_ctl.rc_prr_sendalot == 0)
					len = segsiz;
			} else if (len < segsiz) {
				/*
				 * Do we send any? The idea here is if the
				 * send empty's the socket buffer we want to
				 * do it. However if not then lets just wait
				 * for our prr_sndcnt to get bigger.
				 */
				long leftinsb;

				leftinsb = sbavail(sb) - sb_offset;
				if (leftinsb > len) {
					/* This send does not empty the sb */
					len = 0;
				}
			}
		}
	} else if (!TCPS_HAVEESTABLISHED(tp->t_state)) {
		/*
		 * If you have not established
		 * and are not doing FAST OPEN
		 * no data please.
		 */
		if ((sack_rxmit == 0) &&
		    (!IS_FASTOPEN(tp->t_flags))){
			len = 0;
			sb_offset = 0;
		}
	}
	if (prefetch_so_done == 0) {
		kern_prefetch(so, &prefetch_so_done);
		prefetch_so_done = 1;
	}
	/*
	 * Lop off SYN bit if it has already been sent.  However, if this is
	 * SYN-SENT state and if segment contains data and if we don't know
	 * that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una) &&
	    ((sack_rxmit == 0) && (tp->t_rxtshift == 0))) {
		/*
		 * When sending additional segments following a TFO SYN|ACK,
		 * do not include the SYN bit.
		 */
		if (IS_FASTOPEN(tp->t_flags) &&
		    (tp->t_state == TCPS_SYN_RECEIVED))
			flags &= ~TH_SYN;
	}
	/*
	 * Be careful not to send data and/or FIN on SYN segments. This
	 * measure is needed to prevent interoperability problems with not
	 * fully conformant TCP implementations.
	 */
	if ((flags & TH_SYN) && (tp->t_flags & TF_NOOPT)) {
		len = 0;
		flags &= ~TH_FIN;
	}
	/*
	 * On TFO sockets, ensure no data is sent in the following cases:
	 *
	 *  - When retransmitting SYN|ACK on a passively-created socket
	 *
	 *  - When retransmitting SYN on an actively created socket
	 *
	 *  - When sending a zero-length cookie (cookie request) on an
	 *    actively created socket
	 *
	 *  - When the socket is in the CLOSED state (RST is being sent)
	 */
	if (IS_FASTOPEN(tp->t_flags) &&
	    (((flags & TH_SYN) && (tp->t_rxtshift > 0)) ||
	     ((tp->t_state == TCPS_SYN_SENT) &&
	      (tp->t_tfo_client_cookie_len == 0)) ||
	     (flags & TH_RST))) {
		sack_rxmit = 0;
		len = 0;
	}
	/* Without fast-open there should never be data sent on a SYN */
	if ((flags & TH_SYN) && (!IS_FASTOPEN(tp->t_flags)))
		len = 0;
	orig_len = len;
	if (len <= 0) {
		/*
		 * If FIN has been sent but not acked, but we haven't been
		 * called to retransmit, len will be < 0.  Otherwise, window
		 * shrank after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back to (closed)
		 * window, and set the persist timer if it isn't already
		 * going.  If the window didn't close completely, just wait
		 * for an ACK.
		 *
		 * We also do a general check here to ensure that we will
		 * set the persist timer when we have data to send, but a
		 * 0-byte window. This makes sure the persist timer is set
		 * even if the packet hits one of the "goto send" lines
		 * below.
		 */
		len = 0;
		if ((tp->snd_wnd == 0) &&
		    (TCPS_HAVEESTABLISHED(tp->t_state)) &&
		    (tp->snd_una == tp->snd_max) &&
		    (sb_offset < (int)sbavail(sb))) {
			tp->snd_nxt = tp->snd_una;
			rack_enter_persist(tp, rack, cts);
		}
	} else if ((rsm == NULL) &&
		   ((doing_tlp == 0) || (new_data_tlp == 1)) &&
		   (len < rack->r_ctl.rc_pace_max_segs)) {
		/*
		 * We are not sending a maximum sized segment for
		 * some reason. Should we not send anything (think
		 * sws or persists)?
		 */
		if ((tp->snd_wnd < min(max(segsiz, (rack->r_ctl.rc_high_rwnd/2)), minseg)) &&
		    (TCPS_HAVEESTABLISHED(tp->t_state)) &&
		    (len < minseg) &&
		    (len < (int)(sbavail(sb) - sb_offset))) {
			/*
			 * Here the rwnd is less than
			 * the minimum pacing size, this is not a retransmit,
			 * we are established and
			 * the send is not the last in the socket buffer
			 * we send nothing, and we may enter persists
			 * if nothing is outstanding.
			 */
			len = 0;
			if (tp->snd_max == tp->snd_una) {
				/*
				 * Nothing out we can
				 * go into persists.
				 */
				rack_enter_persist(tp, rack, cts);
				tp->snd_nxt = tp->snd_una;
			}
		} else if ((cwnd_to_use >= max(minseg, (segsiz * 4))) &&
			   (ctf_flight_size(tp, rack->r_ctl.rc_sacked) > (2 * segsiz)) &&
			   (len < (int)(sbavail(sb) - sb_offset)) &&
			   (len < minseg)) {
			/*
			 * Here we are not retransmitting, and
			 * the cwnd is not so small that we could
			 * not send at least a min size (rxt timer
			 * not having gone off), We have 2 segments or
			 * more already in flight, its not the tail end
			 * of the socket buffer  and the cwnd is blocking
			 * us from sending out a minimum pacing segment size.
			 * Lets not send anything.
			 */
			len = 0;
		} else if (((tp->snd_wnd - ctf_outstanding(tp)) <
			    min((rack->r_ctl.rc_high_rwnd/2), minseg)) &&
			   (ctf_flight_size(tp, rack->r_ctl.rc_sacked) > (2 * segsiz)) &&
			   (len < (int)(sbavail(sb) - sb_offset)) &&
			   (TCPS_HAVEESTABLISHED(tp->t_state))) {
			/*
			 * Here we have a send window but we have
			 * filled it up and we can't send another pacing segment.
			 * We also have in flight more than 2 segments
			 * and we are not completing the sb i.e. we allow
			 * the last bytes of the sb to go out even if
			 * its not a full pacing segment.
			 */
			len = 0;
		}
	}
	/* len will be >= 0 after this point. */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));
	tcp_sndbuf_autoscale(tp, so, min(tp->snd_wnd, cwnd_to_use));
	/*
	 * Decide if we can use TCP Segmentation Offloading (if supported by
	 * hardware).
	 *
	 * TSO may only be used if we are in a pure bulk sending state.  The
	 * presence of TCP-MD5, SACK retransmits, SACK advertizements and IP
	 * options prevent using TSO.  With TSO the TCP header is the same
	 * (except for the sequence number) for all generated packets.  This
	 * makes it impossible to transmit any options which vary per
	 * generated segment or packet.
	 *
	 * IPv4 handling has a clear separation of ip options and ip header
	 * flags while IPv6 combines both in in6p_outputopts. ip6_optlen() does
	 * the right thing below to provide length of just ip options and thus
	 * checking for ipoptlen is enough to decide if ip options are present.
	 */

#ifdef INET6
	if (isipv6)
		ipoptlen = ip6_optlen(tp->t_inpcb);
	else
#endif
		if (tp->t_inpcb->inp_options)
			ipoptlen = tp->t_inpcb->inp_options->m_len -
				offsetof(struct ipoption, ipopt_list);
		else
			ipoptlen = 0;
#if defined(IPSEC) || defined(IPSEC_SUPPORT)
	/*
	 * Pre-calculate here as we save another lookup into the darknesses
	 * of IPsec that way and can actually decide if TSO is ok.
	 */
#ifdef INET6
	if (isipv6 && IPSEC_ENABLED(ipv6))
		ipsec_optlen = IPSEC_HDRSIZE(ipv6, tp->t_inpcb);
#ifdef INET
	else
#endif
#endif				/* INET6 */
#ifdef INET
		if (IPSEC_ENABLED(ipv4))
			ipsec_optlen = IPSEC_HDRSIZE(ipv4, tp->t_inpcb);
#endif				/* INET */
#endif

#if defined(IPSEC) || defined(IPSEC_SUPPORT)
	ipoptlen += ipsec_optlen;
#endif
	if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > segsiz &&
	    (tp->t_port == 0) &&
	    ((tp->t_flags & TF_SIGNATURE) == 0) &&
	    tp->rcv_numsacks == 0 && sack_rxmit == 0 &&
	    ipoptlen == 0)
		tso = 1;
	{
		uint32_t outstanding;

		outstanding = tp->snd_max - tp->snd_una;
		if (tp->t_flags & TF_SENTFIN) {
			/*
			 * If we sent a fin, snd_max is 1 higher than
			 * snd_una
			 */
			outstanding--;
		}
		if (sack_rxmit) {
			if ((rsm->r_flags & RACK_HAS_FIN) == 0)
				flags &= ~TH_FIN;
		} else {
			if (SEQ_LT(tp->snd_nxt + len, tp->snd_una +
				   sbused(sb)))
				flags &= ~TH_FIN;
		}
	}
	recwin = sbspace(&so->so_rcv);

	/*
	 * Sender silly window avoidance.   We transmit under the following
	 * conditions when len is non-zero:
	 *
	 * - We have a full segment (or more with TSO) - This is the last
	 * buffer in a write()/send() and we are either idle or running
	 * NODELAY - we've timed out (e.g. persist timer) - we have more
	 * then 1/2 the maximum send window's worth of data (receiver may be
	 * limited the window size) - we need to retransmit
	 */
	if (len) {
		if (len >= segsiz) {
			goto send;
		}
		/*
		 * NOTE! on localhost connections an 'ack' from the remote
		 * end may occur synchronously with the output and cause us
		 * to flush a buffer queued with moretocome.  XXX
		 *
		 */
		if (!(tp->t_flags & TF_MORETOCOME) &&	/* normal case */
		    (idle || (tp->t_flags & TF_NODELAY)) &&
		    ((uint32_t)len + (uint32_t)sb_offset >= sbavail(sb)) &&
		    (tp->t_flags & TF_NOPUSH) == 0) {
			pass = 2;
			goto send;
		}
		if ((tp->snd_una == tp->snd_max) && len) {	/* Nothing outstanding */
			pass = 22;
			goto send;
		}
		if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0) {
			pass = 4;
			goto send;
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {	/* retransmit case */
			pass = 5;
			goto send;
		}
		if (sack_rxmit) {
			pass = 6;
			goto send;
		}
		if (((tp->snd_wnd - ctf_outstanding(tp)) < segsiz) &&
		    (ctf_outstanding(tp) < (segsiz * 2))) {
			/*
			 * We have less than two MSS outstanding (delayed ack)
			 * and our rwnd will not let us send a full sized
			 * MSS. Lets go ahead and let this small segment
			 * out because we want to try to have at least two
			 * packets inflight to not be caught by delayed ack.
			 */
			pass = 12;
			goto send;
		}
	}
	/*
	 * Sending of standalone window updates.
	 *
	 * Window updates are important when we close our window due to a
	 * full socket buffer and are opening it again after the application
	 * reads data from it.  Once the window has opened again and the
	 * remote end starts to send again the ACK clock takes over and
	 * provides the most current window information.
	 *
	 * We must avoid the silly window syndrome whereas every read from
	 * the receive buffer, no matter how small, causes a window update
	 * to be sent.  We also should avoid sending a flurry of window
	 * updates when the socket buffer had queued a lot of data and the
	 * application is doing small reads.
	 *
	 * Prevent a flurry of pointless window updates by only sending an
	 * update when we can increase the advertized window by more than
	 * 1/4th of the socket buffer capacity.  When the buffer is getting
	 * full or is very small be more aggressive and send an update
	 * whenever we can increase by two mss sized segments. In all other
	 * situations the ACK's to new incoming data will carry further
	 * window increases.
	 *
	 * Don't send an independent window update if a delayed ACK is
	 * pending (it will get piggy-backed on it) or the remote side
	 * already has done a half-close and won't send more data.  Skip
	 * this if the connection is in T/TCP half-open state.
	 */
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) &&
	    !(tp->t_flags & TF_DELACK) &&
	    !TCPS_HAVERCVDFIN(tp->t_state)) {
		/*
		 * "adv" is the amount we could increase the window, taking
		 * into account that we are limited by TCP_MAXWIN <<
		 * tp->rcv_scale.
		 */
		int32_t adv;
		int oldwin;

		adv = min(recwin, (long)TCP_MAXWIN << tp->rcv_scale);
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
			oldwin = (tp->rcv_adv - tp->rcv_nxt);
			adv -= oldwin;
		} else
			oldwin = 0;

		/*
		 * If the new window size ends up being the same as the old
		 * size when it is scaled, then don't force a window update.
		 */
		if (oldwin >> tp->rcv_scale == (adv + oldwin) >> tp->rcv_scale)
			goto dontupdate;

		if (adv >= (int32_t)(2 * segsiz) &&
		    (adv >= (int32_t)(so->so_rcv.sb_hiwat / 4) ||
		     recwin <= (int32_t)(so->so_rcv.sb_hiwat / 8) ||
		     so->so_rcv.sb_hiwat <= 8 * segsiz)) {
			pass = 7;
			goto send;
		}
		if (2 * adv >= (int32_t) so->so_rcv.sb_hiwat) {
			pass = 23;
			goto send;
		}
	}
dontupdate:

	/*
	 * Send if we owe the peer an ACK, RST, SYN, or urgent data.  ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW) {
		pass = 8;
		goto send;
	}
	if (((flags & TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0)) {
		pass = 9;
		goto send;
	}
	/*
	 * If our state indicates that FIN should be sent and we have not
	 * yet done so, then we need to send.
	 */
	if ((flags & TH_FIN) &&
	    (tp->snd_nxt == tp->snd_una)) {
		pass = 11;
		goto send;
	}
	/*
	 * No reason to send a segment, just return.
	 */
just_return:
	SOCKBUF_UNLOCK(sb);
just_return_nolock:
	{
		int app_limited = CTF_JR_SENT_DATA;

		if (tot_len_this_send > 0) {
			/* Make sure snd_nxt is up to max */
			if (SEQ_GT(tp->snd_max, tp->snd_nxt))
				tp->snd_nxt = tp->snd_max;
			slot = rack_get_pacing_delay(rack, tp, tot_len_this_send, NULL, segsiz);
		} else {
			int end_window = 0;
			uint32_t seq = tp->gput_ack;

			rsm = RB_MAX(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
			if (rsm) {
				/*
				 * Mark the last sent that we just-returned (hinting
				 * that delayed ack may play a role in any rtt measurement).
				 */
				rsm->r_just_ret = 1;
			}
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_JUSTRET], 1);
			rack->r_ctl.rc_agg_delayed = 0;
			rack->r_early = 0;
			rack->r_late = 0;
			rack->r_ctl.rc_agg_early = 0;
			if ((ctf_outstanding(tp) +
			     min(max(segsiz, (rack->r_ctl.rc_high_rwnd/2)),
				 minseg)) >= tp->snd_wnd) {
				/* We are limited by the rwnd */
				app_limited = CTF_JR_RWND_LIMITED;
			} else if (ctf_outstanding(tp) >= sbavail(sb)) {
				/* We are limited by whats available -- app limited */
				app_limited = CTF_JR_APP_LIMITED;
			} else if ((idle == 0) &&
				   ((tp->t_flags & TF_NODELAY) == 0) &&
				   ((uint32_t)len + (uint32_t)sb_offset >= sbavail(sb)) &&
				   (len < segsiz)) {
				/*
				 * No delay is not on and the
				 * user is sending less than 1MSS. This
				 * brings out SWS avoidance so we
				 * don't send. Another app-limited case.
				 */
				app_limited = CTF_JR_APP_LIMITED;
			} else if (tp->t_flags & TF_NOPUSH) {
				/*
				 * The user has requested no push of
				 * the last segment and we are
				 * at the last segment. Another app
				 * limited case.
				 */
				app_limited = CTF_JR_APP_LIMITED;
			} else if ((ctf_outstanding(tp) + minseg) > cwnd_to_use) {
				/* Its the cwnd */
				app_limited = CTF_JR_CWND_LIMITED;
			} else if (rack->rc_in_persist == 1) {
				/* We are in persists */
				app_limited = CTF_JR_PERSISTS;
			} else if (IN_RECOVERY(tp->t_flags) &&
				   (rack->rack_no_prr == 0) &&
				   (rack->r_ctl.rc_prr_sndcnt < segsiz)) {
				app_limited = CTF_JR_PRR;
			} else {
				/* Now why here are we not sending? */
#ifdef NOW
#ifdef INVARIANTS
				panic("rack:%p hit JR_ASSESSING case cwnd_to_use:%u?", rack, cwnd_to_use);
#endif
#endif
				app_limited = CTF_JR_ASSESSING;
			}
			/*
			 * App limited in some fashion, for our pacing GP
			 * measurements we don't want any gap (even cwnd).
			 * Close  down the measurement window.
			 */
			if (rack_cwnd_block_ends_measure &&
			    ((app_limited == CTF_JR_CWND_LIMITED) ||
			     (app_limited == CTF_JR_PRR))) {
				/*
				 * The reason we are not sending is
				 * the cwnd (or prr). We have been configured
				 * to end the measurement window in
				 * this case.
				 */
				end_window = 1;
			} else if (app_limited == CTF_JR_PERSISTS) {
				/*
				 * We never end the measurement window
				 * in persists, though in theory we
				 * should be only entering after everything
				 * is acknowledged (so we will probably
				 * never come here).
				 */
				end_window = 0;
			} else if (rack_rwnd_block_ends_measure &&
				   (app_limited == CTF_JR_RWND_LIMITED)) {
				/*
				 * We are rwnd limited and have been
				 * configured to end the measurement
				 * window in this case.
				 */
				end_window = 1;
			} else if (app_limited == CTF_JR_APP_LIMITED) {
				/*
				 * A true application limited period, we have
				 * ran out of data.
				 */
				end_window = 1;
			} else if (app_limited == CTF_JR_ASSESSING) {
				/*
				 * In the assessing case we hit the end of
				 * the if/else and had no known reason
				 * This will panic us under invariants..
				 *
				 * If we get this out in logs we need to
				 * investagate which reason we missed.
				 */
				end_window = 1;
			}
			if (end_window) {
				uint8_t log = 0;

				if ((tp->t_flags & TF_GPUTINPROG) &&
				    SEQ_GT(tp->gput_ack, tp->snd_max)) {
					/* Mark the last packet has app limited */
					tp->gput_ack = tp->snd_max;
					log = 1;
				}
				rsm = RB_MAX(rack_rb_tree_head, &rack->r_ctl.rc_mtree);
				if (rsm && ((rsm->r_flags & RACK_APP_LIMITED) == 0)) {
					if (rack->r_ctl.rc_app_limited_cnt == 0)
						rack->r_ctl.rc_end_appl = rack->r_ctl.rc_first_appl = rsm;
					else {
						/*
						 * Go out to the end app limited and mark
						 * this new one as next and move the end_appl up
						 * to this guy.
						 */
						if (rack->r_ctl.rc_end_appl)
							rack->r_ctl.rc_end_appl->r_nseq_appl = rsm->r_start;
						rack->r_ctl.rc_end_appl = rsm;
					}
					rsm->r_flags |= RACK_APP_LIMITED;
					rack->r_ctl.rc_app_limited_cnt++;
				}
				if (log)
					rack_log_pacing_delay_calc(rack,
								   rack->r_ctl.rc_app_limited_cnt, seq,
								   tp->gput_ack, 0, 0, 4, __LINE__, NULL);
			}
		}
		if (slot) {
			/* set the rack tcb into the slot N */
			counter_u64_add(rack_paced_segments, 1);
		} else if (tot_len_this_send) {
			counter_u64_add(rack_unpaced_segments, 1);
		}
		/* Check if we need to go into persists or not */
		if ((rack->rc_in_persist == 0) &&
		    (tp->snd_max == tp->snd_una) &&
		    TCPS_HAVEESTABLISHED(tp->t_state) &&
		    sbavail(sb) &&
		    (sbavail(sb) > tp->snd_wnd) &&
		    (tp->snd_wnd < min((rack->r_ctl.rc_high_rwnd/2), minseg))) {
			/* Yes lets make sure to move to persist before timer-start */
			rack_enter_persist(tp, rack, rack->r_ctl.rc_rcvtime);
		}
		rack_start_hpts_timer(rack, tp, cts, slot, tot_len_this_send, sup_rack);
		rack_log_type_just_return(rack, cts, tot_len_this_send, slot, hpts_calling, app_limited, cwnd_to_use);
	}
#ifdef NETFLIX_SHARED_CWND
	if ((sbavail(sb) == 0) &&
	    rack->r_ctl.rc_scw) {
		tcp_shared_cwnd_idle(rack->r_ctl.rc_scw, rack->r_ctl.rc_scw_index);
		rack->rack_scwnd_is_idle = 1;
	}
#endif
	return (0);

send:
	if ((flags & TH_FIN) &&
	    sbavail(sb)) {
		/*
		 * We do not transmit a FIN
		 * with data outstanding. We
		 * need to make it so all data
		 * is acked first.
		 */
		flags &= ~TH_FIN;
	}
	/* Enforce stack imposed max seg size if we have one */
	if (rack->r_ctl.rc_pace_max_segs &&
	    (len > rack->r_ctl.rc_pace_max_segs)) {
		mark = 1;
		len = rack->r_ctl.rc_pace_max_segs;
	}
	SOCKBUF_LOCK_ASSERT(sb);
	if (len > 0) {
		if (len >= segsiz)
			tp->t_flags2 |= TF2_PLPMTU_MAXSEGSNT;
		else
			tp->t_flags2 &= ~TF2_PLPMTU_MAXSEGSNT;
	}
	/*
	 * Before ESTABLISHED, force sending of initial options unless TCP
	 * set not to do any options. NOTE: we assume that the IP/TCP header
	 * plus TCP options always fit in a single mbuf, leaving room for a
	 * maximum link header, i.e. max_linkhdr + sizeof (struct tcpiphdr)
	 * + optlen <= MCLBYTES
	 */
	optlen = 0;
#ifdef INET6
	if (isipv6)
		hdrlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	else
#endif
		hdrlen = sizeof(struct tcpiphdr);

	/*
	 * Compute options for segment. We only have to care about SYN and
	 * established connection segments.  Options for SYN-ACK segments
	 * are handled in TCP syncache.
	 */
	to.to_flags = 0;
	if ((tp->t_flags & TF_NOOPT) == 0) {
		/* Maximum segment size. */
		if (flags & TH_SYN) {
			tp->snd_nxt = tp->iss;
			to.to_mss = tcp_mssopt(&inp->inp_inc);
#ifdef NETFLIX_TCPOUDP
			if (tp->t_port)
				to.to_mss -= V_tcp_udp_tunneling_overhead;
#endif
			to.to_flags |= TOF_MSS;

			/*
			 * On SYN or SYN|ACK transmits on TFO connections,
			 * only include the TFO option if it is not a
			 * retransmit, as the presence of the TFO option may
			 * have caused the original SYN or SYN|ACK to have
			 * been dropped by a middlebox.
			 */
			if (IS_FASTOPEN(tp->t_flags) &&
			    (tp->t_rxtshift == 0)) {
				if (tp->t_state == TCPS_SYN_RECEIVED) {
					to.to_tfo_len = TCP_FASTOPEN_COOKIE_LEN;
					to.to_tfo_cookie =
						(u_int8_t *)&tp->t_tfo_cookie.server;
					to.to_flags |= TOF_FASTOPEN;
					wanted_cookie = 1;
				} else if (tp->t_state == TCPS_SYN_SENT) {
					to.to_tfo_len =
						tp->t_tfo_client_cookie_len;
					to.to_tfo_cookie =
						tp->t_tfo_cookie.client;
					to.to_flags |= TOF_FASTOPEN;
					wanted_cookie = 1;
					/*
					 * If we wind up having more data to
					 * send with the SYN than can fit in
					 * one segment, don't send any more
					 * until the SYN|ACK comes back from
					 * the other end.
					 */
					sendalot = 0;
				}
			}
		}
		/* Window scaling. */
		if ((flags & TH_SYN) && (tp->t_flags & TF_REQ_SCALE)) {
			to.to_wscale = tp->request_r_scale;
			to.to_flags |= TOF_SCALE;
		}
		/* Timestamps. */
		if ((tp->t_flags & TF_RCVD_TSTMP) ||
		    ((flags & TH_SYN) && (tp->t_flags & TF_REQ_TSTMP))) {
			to.to_tsval = cts + tp->ts_offset;
			to.to_tsecr = tp->ts_recent;
			to.to_flags |= TOF_TS;
		}
		/* Set receive buffer autosizing timestamp. */
		if (tp->rfbuf_ts == 0 &&
		    (so->so_rcv.sb_flags & SB_AUTOSIZE))
			tp->rfbuf_ts = tcp_ts_getticks();
		/* Selective ACK's. */
		if (flags & TH_SYN)
			to.to_flags |= TOF_SACKPERM;
		else if (TCPS_HAVEESTABLISHED(tp->t_state) &&
			 tp->rcv_numsacks > 0) {
			to.to_flags |= TOF_SACK;
			to.to_nsacks = tp->rcv_numsacks;
			to.to_sacks = (u_char *)tp->sackblks;
		}
#if defined(IPSEC_SUPPORT) || defined(TCP_SIGNATURE)
		/* TCP-MD5 (RFC2385). */
		if (tp->t_flags & TF_SIGNATURE)
			to.to_flags |= TOF_SIGNATURE;
#endif				/* TCP_SIGNATURE */

		/* Processing the options. */
		hdrlen += optlen = tcp_addoptions(&to, opt);
		/*
		 * If we wanted a TFO option to be added, but it was unable
		 * to fit, ensure no data is sent.
		 */
		if (IS_FASTOPEN(tp->t_flags) && wanted_cookie &&
		    !(to.to_flags & TOF_FASTOPEN))
			len = 0;
	}
#ifdef NETFLIX_TCPOUDP
	if (tp->t_port) {
		if (V_tcp_udp_tunneling_port == 0) {
			/* The port was removed?? */
			SOCKBUF_UNLOCK(&so->so_snd);
			return (EHOSTUNREACH);
		}
		hdrlen += sizeof(struct udphdr);
	}
#endif
#ifdef INET6
	if (isipv6)
		ipoptlen = ip6_optlen(tp->t_inpcb);
	else
#endif
		if (tp->t_inpcb->inp_options)
			ipoptlen = tp->t_inpcb->inp_options->m_len -
				offsetof(struct ipoption, ipopt_list);
		else
			ipoptlen = 0;
#if defined(IPSEC) || defined(IPSEC_SUPPORT)
	ipoptlen += ipsec_optlen;
#endif

#ifdef KERN_TLS
 	/* force TSO for so TLS offload can get mss */
 	if (sb->sb_flags & SB_TLS_IFNET) {
 		force_tso = 1;
 	}
#endif
	/*
	 * Adjust data length if insertion of options will bump the packet
	 * length beyond the t_maxseg length. Clear the FIN bit because we
	 * cut off the tail of the segment.
	 */
	if (len + optlen + ipoptlen > tp->t_maxseg) {
		if (tso) {
			uint32_t if_hw_tsomax;
			uint32_t moff;
			int32_t max_len;

			/* extract TSO information */
			if_hw_tsomax = tp->t_tsomax;
			if_hw_tsomaxsegcount = tp->t_tsomaxsegcount;
			if_hw_tsomaxsegsize = tp->t_tsomaxsegsize;
			KASSERT(ipoptlen == 0,
				("%s: TSO can't do IP options", __func__));

			/*
			 * Check if we should limit by maximum payload
			 * length:
			 */
			if (if_hw_tsomax != 0) {
				/* compute maximum TSO length */
				max_len = (if_hw_tsomax - hdrlen -
					   max_linkhdr);
				if (max_len <= 0) {
					len = 0;
				} else if (len > max_len) {
					sendalot = 1;
					len = max_len;
					mark = 2;
				}
			}
			/*
			 * Prevent the last segment from being fractional
			 * unless the send sockbuf can be emptied:
			 */
			max_len = (tp->t_maxseg - optlen);
			if (((sb_offset + len) < sbavail(sb)) &&
			    (hw_tls == 0)) {
				moff = len % (u_int)max_len;
				if (moff != 0) {
					mark = 3;
					len -= moff;
				}
			}
                        /*
			 * In case there are too many small fragments don't
			 * use TSO:
			 */
			if (len <= segsiz) {
				mark = 4;
				tso = 0;
			}
			/*
			 * Send the FIN in a separate segment after the bulk
			 * sending is done. We don't trust the TSO
			 * implementations to clear the FIN flag on all but
			 * the last segment.
			 */
			if (tp->t_flags & TF_NEEDFIN) {
				sendalot = 4;
			}
		} else {
			mark = 5;
			if (optlen + ipoptlen >= tp->t_maxseg) {
				/*
				 * Since we don't have enough space to put
				 * the IP header chain and the TCP header in
				 * one packet as required by RFC 7112, don't
				 * send it. Also ensure that at least one
				 * byte of the payload can be put into the
				 * TCP segment.
				 */
				SOCKBUF_UNLOCK(&so->so_snd);
				error = EMSGSIZE;
				sack_rxmit = 0;
				goto out;
			}
			len = tp->t_maxseg - optlen - ipoptlen;
			sendalot = 5;
		}
	} else {
		tso = 0;
		mark = 6;
	}
	KASSERT(len + hdrlen + ipoptlen <= IP_MAXPACKET,
		("%s: len > IP_MAXPACKET", __func__));
#ifdef DIAGNOSTIC
#ifdef INET6
	if (max_linkhdr + hdrlen > MCLBYTES)
#else
		if (max_linkhdr + hdrlen > MHLEN)
#endif
			panic("tcphdr too big");
#endif

	/*
	 * This KASSERT is here to catch edge cases at a well defined place.
	 * Before, those had triggered (random) panic conditions further
	 * down.
	 */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));
	if ((len == 0) &&
	    (flags & TH_FIN) &&
	    (sbused(sb))) {
		/*
		 * We have outstanding data, don't send a fin by itself!.
		 */
		goto just_return;
	}
	/*
	 * Grab a header mbuf, attaching a copy of data to be transmitted,
	 * and initialize the header from the template for sends on this
	 * connection.
	 */
	if (len) {
		uint32_t max_val;
		uint32_t moff;

		if (rack->r_ctl.rc_pace_max_segs)
			max_val = rack->r_ctl.rc_pace_max_segs;
		else if (rack->rc_user_set_max_segs)
			max_val = rack->rc_user_set_max_segs * segsiz;
		else
			max_val = len;
		/*
		 * We allow a limit on sending with hptsi.
		 */
		if (len > max_val) {
			mark = 7;
			len = max_val;
		}
#ifdef INET6
		if (MHLEN < hdrlen + max_linkhdr)
			m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		else
#endif
			m = m_gethdr(M_NOWAIT, MT_DATA);

		if (m == NULL) {
			SOCKBUF_UNLOCK(sb);
			error = ENOBUFS;
			sack_rxmit = 0;
			goto out;
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;

		/*
		 * Start the m_copy functions from the closest mbuf to the
		 * sb_offset in the socket buffer chain.
		 */
		mb = sbsndptr_noadv(sb, sb_offset, &moff);
		if (len <= MHLEN - hdrlen - max_linkhdr && !hw_tls) {
			m_copydata(mb, moff, (int)len,
				   mtod(m, caddr_t)+hdrlen);
			if (SEQ_LT(tp->snd_nxt, tp->snd_max))
				sbsndptr_adv(sb, mb, len);
			m->m_len += len;
		} else {
			struct sockbuf *msb;

			if (SEQ_LT(tp->snd_nxt, tp->snd_max))
				msb = NULL;
			else
				msb = sb;
			m->m_next = tcp_m_copym(
				mb, moff, &len,
				if_hw_tsomaxsegcount, if_hw_tsomaxsegsize, msb,
				((rsm == NULL) ? hw_tls : 0)
#ifdef NETFLIX_COPY_ARGS
				, &filled_all
#endif
				);
			if (len <= (tp->t_maxseg - optlen)) {
				/*
				 * Must have ran out of mbufs for the copy
				 * shorten it to no longer need tso. Lets
				 * not put on sendalot since we are low on
				 * mbufs.
				 */
				tso = 0;
			}
			if (m->m_next == NULL) {
				SOCKBUF_UNLOCK(sb);
				(void)m_free(m);
				error = ENOBUFS;
				sack_rxmit = 0;
				goto out;
			}
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
			if (rsm && (rsm->r_flags & RACK_TLP)) {
				/*
				 * TLP should not count in retran count, but
				 * in its own bin
				 */
				counter_u64_add(rack_tlp_retran, 1);
				counter_u64_add(rack_tlp_retran_bytes, len);
			} else {
				tp->t_sndrexmitpack++;
				KMOD_TCPSTAT_INC(tcps_sndrexmitpack);
				KMOD_TCPSTAT_ADD(tcps_sndrexmitbyte, len);
			}
#ifdef STATS
			stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_RETXPB,
						 len);
#endif
		} else {
			KMOD_TCPSTAT_INC(tcps_sndpack);
			KMOD_TCPSTAT_ADD(tcps_sndbyte, len);
#ifdef STATS
			stats_voi_update_abs_u64(tp->t_stats, VOI_TCP_TXPB,
						 len);
#endif
		}
		/*
		 * If we're sending everything we've got, set PUSH. (This
		 * will keep happy those implementations which only give
		 * data to the user when a buffer fills or a PUSH comes in.)
		 */
		if (sb_offset + len == sbused(sb) &&
		    sbused(sb) &&
		    !(flags & TH_SYN))
			flags |= TH_PUSH;

		SOCKBUF_UNLOCK(sb);
	} else {
		SOCKBUF_UNLOCK(sb);
		if (tp->t_flags & TF_ACKNOW)
			KMOD_TCPSTAT_INC(tcps_sndacks);
		else if (flags & (TH_SYN | TH_FIN | TH_RST))
			KMOD_TCPSTAT_INC(tcps_sndctrl);
		else
			KMOD_TCPSTAT_INC(tcps_sndwinup);

		m = m_gethdr(M_NOWAIT, MT_DATA);
		if (m == NULL) {
			error = ENOBUFS;
			sack_rxmit = 0;
			goto out;
		}
#ifdef INET6
		if (isipv6 && (MHLEN < hdrlen + max_linkhdr) &&
		    MHLEN >= hdrlen) {
			M_ALIGN(m, hdrlen);
		} else
#endif
			m->m_data += max_linkhdr;
		m->m_len = hdrlen;
	}
	SOCKBUF_UNLOCK_ASSERT(sb);
	m->m_pkthdr.rcvif = (struct ifnet *)0;
#ifdef MAC
	mac_inpcb_create_mbuf(inp, m);
#endif
#ifdef INET6
	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);
#ifdef NETFLIX_TCPOUDP
		if (tp->t_port) {
			udp = (struct udphdr *)((caddr_t)ip6 + ipoptlen + sizeof(struct ip6_hdr));
			udp->uh_sport = htons(V_tcp_udp_tunneling_port);
			udp->uh_dport = tp->t_port;
			ulen = hdrlen + len - sizeof(struct ip6_hdr);
			udp->uh_ulen = htons(ulen);
			th = (struct tcphdr *)(udp + 1);
		} else
#endif
			th = (struct tcphdr *)(ip6 + 1);
		tcpip_fillheaders(inp,
#ifdef NETFLIX_TCPOUDP
				  tp->t_port,
#endif
				  ip6, th);
	} else
#endif				/* INET6 */
	{
		ip = mtod(m, struct ip *);
#ifdef TCPDEBUG
		ipov = (struct ipovly *)ip;
#endif
#ifdef NETFLIX_TCPOUDP
		if (tp->t_port) {
			udp = (struct udphdr *)((caddr_t)ip + ipoptlen + sizeof(struct ip));
			udp->uh_sport = htons(V_tcp_udp_tunneling_port);
			udp->uh_dport = tp->t_port;
			ulen = hdrlen + len - sizeof(struct ip);
			udp->uh_ulen = htons(ulen);
			th = (struct tcphdr *)(udp + 1);
		} else
#endif
			th = (struct tcphdr *)(ip + 1);
		tcpip_fillheaders(inp,
#ifdef NETFLIX_TCPOUDP
				  tp->t_port,
#endif
				  ip, th);
	}
	/*
	 * Fill in fields, remembering maximum advertised window for use in
	 * delaying messages about window sizes. If resending a FIN, be sure
	 * not to use a new sequence number.
	 */
	if (flags & TH_FIN && tp->t_flags & TF_SENTFIN &&
	    tp->snd_nxt == tp->snd_max)
		tp->snd_nxt--;
	/*
	 * If we are starting a connection, send ECN setup SYN packet. If we
	 * are on a retransmit, we may resend those bits a number of times
	 * as per RFC 3168.
	 */
	if (tp->t_state == TCPS_SYN_SENT && V_tcp_do_ecn == 1) {
		if (tp->t_rxtshift >= 1) {
			if (tp->t_rxtshift <= V_tcp_ecn_maxretries)
				flags |= TH_ECE | TH_CWR;
		} else
			flags |= TH_ECE | TH_CWR;
	}
	/* Handle parallel SYN for ECN */
	if ((tp->t_state == TCPS_SYN_RECEIVED) &&
	    (tp->t_flags2 & TF2_ECN_SND_ECE)) {
		flags |= TH_ECE;
		tp->t_flags2 &= ~TF2_ECN_SND_ECE;
	}
	if (tp->t_state == TCPS_ESTABLISHED &&
	    (tp->t_flags2 & TF2_ECN_PERMIT)) {
		/*
		 * If the peer has ECN, mark data packets with ECN capable
		 * transmission (ECT). Ignore pure ack packets,
		 * retransmissions.
		 */
		if (len > 0 && SEQ_GEQ(tp->snd_nxt, tp->snd_max) &&
		    (sack_rxmit == 0)) {
#ifdef INET6
			if (isipv6)
				ip6->ip6_flow |= htonl(IPTOS_ECN_ECT0 << 20);
			else
#endif
				ip->ip_tos |= IPTOS_ECN_ECT0;
			KMOD_TCPSTAT_INC(tcps_ecn_ect0);
			/*
			 * Reply with proper ECN notifications.
			 * Only set CWR on new data segments.
			 */
			if (tp->t_flags2 & TF2_ECN_SND_CWR) {
				flags |= TH_CWR;
				tp->t_flags2 &= ~TF2_ECN_SND_CWR;
			}
		}
		if (tp->t_flags2 & TF2_ECN_SND_ECE)
			flags |= TH_ECE;
	}
	/*
	 * If we are doing retransmissions, then snd_nxt will not reflect
	 * the first unsent octet.  For ACK only packets, we do not want the
	 * sequence number of the retransmitted packet, we want the sequence
	 * number of the next unsent octet.  So, if there is no data (and no
	 * SYN or FIN), use snd_max instead of snd_nxt when filling in
	 * ti_seq.  But if we are in persist state, snd_max might reflect
	 * one byte beyond the right edge of the window, so use snd_nxt in
	 * that case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */
	if (sack_rxmit == 0) {
		if (len || (flags & (TH_SYN | TH_FIN)) ||
		    rack->rc_in_persist) {
			th->th_seq = htonl(tp->snd_nxt);
			rack_seq = tp->snd_nxt;
		} else if (flags & TH_RST) {
			/*
			 * For a Reset send the last cum ack in sequence
			 * (this like any other choice may still generate a
			 * challenge ack, if a ack-update packet is in
			 * flight).
			 */
			th->th_seq = htonl(tp->snd_una);
			rack_seq = tp->snd_una;
		} else {
			th->th_seq = htonl(tp->snd_max);
			rack_seq = tp->snd_max;
		}
	} else {
		th->th_seq = htonl(rsm->r_start);
		rack_seq = rsm->r_start;
	}
	th->th_ack = htonl(tp->rcv_nxt);
	if (optlen) {
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof(struct tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window, but avoid silly
	 * window syndrome.
	 * If a RST segment is sent, advertise a window of zero.
	 */
	if (flags & TH_RST) {
		recwin = 0;
	} else {
		if (recwin < (long)(so->so_rcv.sb_hiwat / 4) &&
		    recwin < (long)segsiz)
			recwin = 0;
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) &&
		    recwin < (long)(tp->rcv_adv - tp->rcv_nxt))
			recwin = (long)(tp->rcv_adv - tp->rcv_nxt);
		if (recwin > (long)TCP_MAXWIN << tp->rcv_scale)
			recwin = (long)TCP_MAXWIN << tp->rcv_scale;
	}

	/*
	 * According to RFC1323 the window field in a SYN (i.e., a <SYN> or
	 * <SYN,ACK>) segment itself is never scaled.  The <SYN,ACK> case is
	 * handled in syncache.
	 */
	if (flags & TH_SYN)
		th->th_win = htons((u_short)
				   (min(sbspace(&so->so_rcv), TCP_MAXWIN)));
	else {
		/* Avoid shrinking window with window scaling. */
		recwin = roundup2(recwin, 1 << tp->rcv_scale);
		th->th_win = htons((u_short)(recwin >> tp->rcv_scale));
	}
	/*
	 * Adjust the RXWIN0SENT flag - indicate that we have advertised a 0
	 * window.  This may cause the remote transmitter to stall.  This
	 * flag tells soreceive() to disable delayed acknowledgements when
	 * draining the buffer.  This can occur if the receiver is
	 * attempting to read more data than can be buffered prior to
	 * transmitting on the connection.
	 */
	if (th->th_win == 0) {
		tp->t_sndzerowin++;
		tp->t_flags |= TF_RXWIN0SENT;
	} else
		tp->t_flags &= ~TF_RXWIN0SENT;
	tp->snd_up = tp->snd_una;	/* drag it along, its deprecated  */

#if defined(IPSEC_SUPPORT) || defined(TCP_SIGNATURE)
	if (to.to_flags & TOF_SIGNATURE) {
		/*
		 * Calculate MD5 signature and put it into the place
		 * determined before.
		 * NOTE: since TCP options buffer doesn't point into
		 * mbuf's data, calculate offset and use it.
		 */
		if (!TCPMD5_ENABLED() || TCPMD5_OUTPUT(m, th,
						       (u_char *)(th + 1) + (to.to_signature - opt)) != 0) {
			/*
			 * Do not send segment if the calculation of MD5
			 * digest has failed.
			 */
			goto out;
		}
	}
#endif

	/*
	 * Put TCP length in extended header, and then checksum extended
	 * header and data.
	 */
	m->m_pkthdr.len = hdrlen + len;	/* in6_cksum() need this */
#ifdef INET6
	if (isipv6) {
		/*
		 * ip6_plen is not need to be filled now, and will be filled
		 * in ip6_output.
		 */
		if (tp->t_port) {
			m->m_pkthdr.csum_flags = CSUM_UDP_IPV6;
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
			udp->uh_sum = in6_cksum_pseudo(ip6, ulen, IPPROTO_UDP, 0);
			th->th_sum = htons(0);
			UDPSTAT_INC(udps_opackets);
		} else {
			m->m_pkthdr.csum_flags = CSUM_TCP_IPV6;
			m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
			th->th_sum = in6_cksum_pseudo(ip6,
						      sizeof(struct tcphdr) + optlen + len, IPPROTO_TCP,
						      0);
		}
	}
#endif
#if defined(INET6) && defined(INET)
	else
#endif
#ifdef INET
	{
		if (tp->t_port) {
			m->m_pkthdr.csum_flags = CSUM_UDP;
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
			udp->uh_sum = in_pseudo(ip->ip_src.s_addr,
						ip->ip_dst.s_addr, htons(ulen + IPPROTO_UDP));
			th->th_sum = htons(0);
			UDPSTAT_INC(udps_opackets);
		} else {
			m->m_pkthdr.csum_flags = CSUM_TCP;
			m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
			th->th_sum = in_pseudo(ip->ip_src.s_addr,
					       ip->ip_dst.s_addr, htons(sizeof(struct tcphdr) +
									IPPROTO_TCP + len + optlen));
		}
		/* IP version must be set here for ipv4/ipv6 checking later */
		KASSERT(ip->ip_v == IPVERSION,
			("%s: IP version incorrect: %d", __func__, ip->ip_v));
	}
#endif
	/*
	 * Enable TSO and specify the size of the segments. The TCP pseudo
	 * header checksum is always provided. XXX: Fixme: This is currently
	 * not the case for IPv6.
	 */
	if (tso || force_tso) {
		KASSERT(force_tso || len > tp->t_maxseg - optlen,
			("%s: len <= tso_segsz", __func__));
		m->m_pkthdr.csum_flags |= CSUM_TSO;
		m->m_pkthdr.tso_segsz = tp->t_maxseg - optlen;
	}
	KASSERT(len + hdrlen == m_length(m, NULL),
		("%s: mbuf chain different than expected: %d + %u != %u",
		 __func__, len, hdrlen, m_length(m, NULL)));

#ifdef TCP_HHOOK
	/* Run HHOOK_TCP_ESTABLISHED_OUT helper hooks. */
	hhook_run_tcp_est_out(tp, th, &to, len, tso);
#endif
#ifdef TCPDEBUG
	/*
	 * Trace.
	 */
	if (so->so_options & SO_DEBUG) {
		u_short save = 0;

#ifdef INET6
		if (!isipv6)
#endif
		{
			save = ipov->ih_len;
			ipov->ih_len = htons(m->m_pkthdr.len	/* - hdrlen +
								 * (th->th_off << 2) */ );
		}
		tcp_trace(TA_OUTPUT, tp->t_state, tp, mtod(m, void *), th, 0);
#ifdef INET6
		if (!isipv6)
#endif
			ipov->ih_len = save;
	}
#endif				/* TCPDEBUG */

	/* We're getting ready to send; log now. */
	if (tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		if (rack->rack_no_prr)
			log.u_bbr.flex1 = 0;
		else
			log.u_bbr.flex1 = rack->r_ctl.rc_prr_sndcnt;
		log.u_bbr.flex2 = rack->r_ctl.rc_pace_min_segs;
		log.u_bbr.flex3 = rack->r_ctl.rc_pace_max_segs;
		log.u_bbr.flex4 = orig_len;
		if (filled_all)
			log.u_bbr.flex5 = 0x80000000;
		else
			log.u_bbr.flex5 = 0;
		/* Save off the early/late values */
		log.u_bbr.flex6 = rack->r_ctl.rc_agg_early;
		log.u_bbr.applimited = rack->r_ctl.rc_agg_delayed;
		log.u_bbr.bw_inuse = rack_get_bw(rack);
		if (rsm || sack_rxmit) {
			if (doing_tlp)
				log.u_bbr.flex8 = 2;
			else
				log.u_bbr.flex8 = 1;
		} else {
			log.u_bbr.flex8 = 0;
		}
		log.u_bbr.pacing_gain = rack_get_output_gain(rack, rsm);
		log.u_bbr.flex7 = mark;
		log.u_bbr.pkts_out = tp->t_maxseg;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.inflight = ctf_flight_size(rack->rc_tp, rack->r_ctl.rc_sacked);
		log.u_bbr.lt_epoch = cwnd_to_use;
		log.u_bbr.delivered = sendalot;
		lgb = tcp_log_event_(tp, th, &so->so_rcv, &so->so_snd, TCP_LOG_OUT, ERRNO_UNK,
				     len, &log, false, NULL, NULL, 0, &tv);
	} else
		lgb = NULL;

	/*
	 * Fill in IP length and desired time to live and send to IP level.
	 * There should be a better way to handle ttl and tos; we could keep
	 * them in the template, but need a way to checksum without them.
	 */
	/*
	 * m->m_pkthdr.len should have been set before cksum calcuration,
	 * because in6_cksum() need it.
	 */
#ifdef INET6
	if (isipv6) {
		/*
		 * we separately set hoplimit for every segment, since the
		 * user might want to change the value via setsockopt. Also,
		 * desired default hop limit might be changed via Neighbor
		 * Discovery.
		 */
		ip6->ip6_hlim = in6_selecthlim(inp, NULL);

		/*
		 * Set the packet size here for the benefit of DTrace
		 * probes. ip6_output() will set it properly; it's supposed
		 * to include the option header lengths as well.
		 */
		ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(*ip6));

		if (V_path_mtu_discovery && tp->t_maxseg > V_tcp_minmss)
			tp->t_flags2 |= TF2_PLPMTU_PMTUD;
		else
			tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;

		if (tp->t_state == TCPS_SYN_SENT)
			TCP_PROBE5(connect__request, NULL, tp, ip6, tp, th);

		TCP_PROBE5(send, NULL, tp, ip6, tp, th);
		/* TODO: IPv6 IP6TOS_ECT bit on */
		error = ip6_output(m, inp->in6p_outputopts,
				   &inp->inp_route6,
				   ((rsm || sack_rxmit) ? IP_NO_SND_TAG_RL : 0),
				   NULL, NULL, inp);

		if (error == EMSGSIZE && inp->inp_route6.ro_nh != NULL)
			mtu = inp->inp_route6.ro_nh->nh_mtu;
	}
#endif				/* INET6 */
#if defined(INET) && defined(INET6)
	else
#endif
#ifdef INET
	{
		ip->ip_len = htons(m->m_pkthdr.len);
#ifdef INET6
		if (inp->inp_vflag & INP_IPV6PROTO)
			ip->ip_ttl = in6_selecthlim(inp, NULL);
#endif				/* INET6 */
		/*
		 * If we do path MTU discovery, then we set DF on every
		 * packet. This might not be the best thing to do according
		 * to RFC3390 Section 2. However the tcp hostcache migitates
		 * the problem so it affects only the first tcp connection
		 * with a host.
		 *
		 * NB: Don't set DF on small MTU/MSS to have a safe
		 * fallback.
		 */
		if (V_path_mtu_discovery && tp->t_maxseg > V_tcp_minmss) {
			tp->t_flags2 |= TF2_PLPMTU_PMTUD;
			if (tp->t_port == 0 || len < V_tcp_minmss) {
				ip->ip_off |= htons(IP_DF);
			}
		} else {
			tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;
		}

		if (tp->t_state == TCPS_SYN_SENT)
			TCP_PROBE5(connect__request, NULL, tp, ip, tp, th);

		TCP_PROBE5(send, NULL, tp, ip, tp, th);

		error = ip_output(m, inp->inp_options, &inp->inp_route,
				  ((rsm || sack_rxmit) ? IP_NO_SND_TAG_RL : 0), 0,
				  inp);
		if (error == EMSGSIZE && inp->inp_route.ro_nh != NULL)
			mtu = inp->inp_route.ro_nh->nh_mtu;
	}
#endif				/* INET */

out:
	if (lgb) {
		lgb->tlb_errno = error;
		lgb = NULL;
	}
	/*
	 * In transmit state, time the transmission and arrange for the
	 * retransmit.  In persist state, just set snd_max.
	 */
	if (error == 0) {
		rack->forced_ack = 0;	/* If we send something zap the FA flag */
		if (rsm && (doing_tlp == 0)) {
			/* Set we retransmitted */
			rack->rc_gp_saw_rec = 1;
		} else {
			if (cwnd_to_use > tp->snd_ssthresh) {
				/* Set we sent in CA */
				rack->rc_gp_saw_ca = 1;
			} else {
				/* Set we sent in SS */
				rack->rc_gp_saw_ss = 1;
			}
		}
		if (TCPS_HAVEESTABLISHED(tp->t_state) &&
		    (tp->t_flags & TF_SACK_PERMIT) &&
		    tp->rcv_numsacks > 0)
			tcp_clean_dsack_blocks(tp);
		tot_len_this_send += len;
		if (len == 0)
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_SNDACK], 1);
		else if (len == 1) {
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_PERSIST], 1);
		} else if (len > 1) {
			int idx;

			idx = (len / segsiz) + 3;
			if (idx >= TCP_MSS_ACCT_ATIMER)
				counter_u64_add(rack_out_size[(TCP_MSS_ACCT_ATIMER-1)], 1);
			else
				counter_u64_add(rack_out_size[idx], 1);
		}
		if (hw_tls && len > 0) {
			if (filled_all) {
				counter_u64_add(rack_tls_filled, 1);
				rack_log_type_hrdwtso(tp, rack, len, 0, orig_len, 1);
			} else {
				if (rsm) {
					counter_u64_add(rack_tls_rxt, 1);
					rack_log_type_hrdwtso(tp, rack, len, 2, orig_len, 1);
				} else if (doing_tlp) {
					counter_u64_add(rack_tls_tlp, 1);
					rack_log_type_hrdwtso(tp, rack, len, 3, orig_len, 1);
				} else if ( (ctf_outstanding(tp) + minseg) > sbavail(sb)) {
					counter_u64_add(rack_tls_app, 1);
					rack_log_type_hrdwtso(tp, rack, len, 4, orig_len, 1);
				} else if ((ctf_flight_size(tp, rack->r_ctl.rc_sacked) + minseg) > cwnd_to_use) {
					counter_u64_add(rack_tls_cwnd, 1);
					rack_log_type_hrdwtso(tp, rack, len, 5, orig_len, 1);
				} else if ((ctf_outstanding(tp) + minseg) > tp->snd_wnd) {
					counter_u64_add(rack_tls_rwnd, 1);
					rack_log_type_hrdwtso(tp, rack, len, 6, orig_len, 1);
				} else {
					rack_log_type_hrdwtso(tp, rack, len, 7, orig_len, 1);
					counter_u64_add(rack_tls_other, 1);
				}
			}
		}
	}
	if (rack->rack_no_prr == 0) {
		if (sub_from_prr && (error == 0)) {
			if (rack->r_ctl.rc_prr_sndcnt >= len)
				rack->r_ctl.rc_prr_sndcnt -= len;
			else
				rack->r_ctl.rc_prr_sndcnt = 0;
		}
 	}
	sub_from_prr = 0;
	rack_log_output(tp, &to, len, rack_seq, (uint8_t) flags, error, cts,
			pass, rsm, us_cts);
	if ((error == 0) &&
	    (len > 0) &&
	    (tp->snd_una == tp->snd_max))
		rack->r_ctl.rc_tlp_rxt_last_time = cts;
	/* Now are we in persists? */
	if (rack->rc_in_persist == 0) {
		tcp_seq startseq = tp->snd_nxt;

		/* Track our lost count */
		if (rsm && (doing_tlp == 0))
			rack->r_ctl.rc_loss_count += rsm->r_end - rsm->r_start;
		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (error)
			/* We don't log or do anything with errors */
			goto nomore;
		if (doing_tlp == 0) {
			if (rsm == NULL) {
				/*
				 * Not a retransmission of some
				 * sort, new data is going out so
				 * clear our TLP count and flag.
				 */
				rack->rc_tlp_in_progress = 0;
				rack->r_ctl.rc_tlp_cnt_out = 0;
			}
		} else {
			/*
			 * We have just sent a TLP, mark that it is true
			 * and make sure our in progress is set so we
			 * continue to check the count.
			 */
			rack->rc_tlp_in_progress = 1;
			rack->r_ctl.rc_tlp_cnt_out++;
		}
		if (flags & (TH_SYN | TH_FIN)) {
			if (flags & TH_SYN)
				tp->snd_nxt++;
			if (flags & TH_FIN) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		/* In the ENOBUFS case we do *not* update snd_max */
		if (sack_rxmit)
			goto nomore;

		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			if (tp->snd_una == tp->snd_max) {
				/*
				 * Update the time we just added data since
				 * none was outstanding.
				 */
				rack_log_progress_event(rack, tp, ticks, PROGRESS_START, __LINE__);
				tp->t_acktime = ticks;
			}
			tp->snd_max = tp->snd_nxt;
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 * This is only relevant in case of switching back to
			 * the base stack.
			 */
			if (tp->t_rtttime == 0) {
				tp->t_rtttime = ticks;
				tp->t_rtseq = startseq;
				KMOD_TCPSTAT_INC(tcps_segstimed);
			}
			if (len &&
			    ((tp->t_flags & TF_GPUTINPROG) == 0))
				rack_start_gp_measurement(tp, rack, startseq, sb_offset);
		}
	} else {
		/*
		 * Persist case, update snd_max but since we are in persist
		 * mode (no window) we do not update snd_nxt.
		 */
		int32_t xlen = len;

		if (error)
			goto nomore;

		if (flags & TH_SYN)
			++xlen;
		if (flags & TH_FIN) {
			++xlen;
			tp->t_flags |= TF_SENTFIN;
		}
		/* In the ENOBUFS case we do *not* update snd_max */
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max)) {
			if (tp->snd_una == tp->snd_max) {
				/*
				 * Update the time we just added data since
				 * none was outstanding.
				 */
				rack_log_progress_event(rack, tp, ticks, PROGRESS_START, __LINE__);
				tp->t_acktime = ticks;
			}
			tp->snd_max = tp->snd_nxt + len;
		}
	}
nomore:
	if (error) {
		rack->r_ctl.rc_agg_delayed = 0;
		rack->r_early = 0;
		rack->r_late = 0;
		rack->r_ctl.rc_agg_early = 0;
		SOCKBUF_UNLOCK_ASSERT(sb);	/* Check gotos. */
		/*
		 * Failures do not advance the seq counter above. For the
		 * case of ENOBUFS we will fall out and retry in 1ms with
		 * the hpts. Everything else will just have to retransmit
		 * with the timer.
		 *
		 * In any case, we do not want to loop around for another
		 * send without a good reason.
		 */
		sendalot = 0;
		switch (error) {
		case EPERM:
			tp->t_softerror = error;
			return (error);
		case ENOBUFS:
			if (slot == 0) {
				/*
				 * Pace us right away to retry in a some
				 * time
				 */
				slot = ((1 + rack->rc_enobuf) * HPTS_USEC_IN_MSEC);
				if (rack->rc_enobuf < 126)
					rack->rc_enobuf++;
				if (slot > ((rack->rc_rack_rtt / 2) * HPTS_USEC_IN_MSEC)) {
					slot = (rack->rc_rack_rtt / 2) * HPTS_USEC_IN_MSEC;
				}
				if (slot < (10 * HPTS_USEC_IN_MSEC))
					slot = 10 * HPTS_USEC_IN_MSEC;
			}
			counter_u64_add(rack_saw_enobuf, 1);
			error = 0;
			goto enobufs;
		case EMSGSIZE:
			/*
			 * For some reason the interface we used initially
			 * to send segments changed to another or lowered
			 * its MTU. If TSO was active we either got an
			 * interface without TSO capabilits or TSO was
			 * turned off. If we obtained mtu from ip_output()
			 * then update it and try again.
			 */
			if (tso)
				tp->t_flags &= ~TF_TSO;
			if (mtu != 0) {
				tcp_mss_update(tp, -1, mtu, NULL, NULL);
				goto again;
			}
			slot = 10 * HPTS_USEC_IN_MSEC;
			rack_start_hpts_timer(rack, tp, cts, slot, 0, 0);
			return (error);
		case ENETUNREACH:
			counter_u64_add(rack_saw_enetunreach, 1);
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
			if (TCPS_HAVERCVDSYN(tp->t_state)) {
				tp->t_softerror = error;
			}
			/* FALLTHROUGH */
		default:
			slot = 10 * HPTS_USEC_IN_MSEC;
			rack_start_hpts_timer(rack, tp, cts, slot, 0, 0);
			return (error);
		}
	} else {
		rack->rc_enobuf = 0;
	}
	KMOD_TCPSTAT_INC(tcps_sndtotal);

	/*
	 * Data sent (as far as we can tell). If this advertises a larger
	 * window than any other segment, then remember the size of the
	 * advertised window. Any pending ACK has now been sent.
	 */
	if (recwin > 0 && SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
enobufs:
	/* Assure when we leave that snd_nxt will point to top */
	if (SEQ_GT(tp->snd_max, tp->snd_nxt))
		tp->snd_nxt = tp->snd_max;
	if (sendalot) {
		/* Do we need to turn off sendalot? */
		if (rack->r_ctl.rc_pace_max_segs &&
		    (tot_len_this_send >= rack->r_ctl.rc_pace_max_segs)) {
			/* We hit our max. */
			sendalot = 0;
		} else if ((rack->rc_user_set_max_segs) &&
			   (tot_len_this_send >= (rack->rc_user_set_max_segs * segsiz))) {
			/* We hit the user defined max */
			sendalot = 0;
		}
	}
	if ((error == 0) && (flags & TH_FIN))
		tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_FIN);
	if (flags & TH_RST) {
		/*
		 * We don't send again after sending a RST.
		 */
		slot = 0;
		sendalot = 0;
		if (error == 0)
			tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_RST);
	} else if ((slot == 0) && (sendalot == 0) && tot_len_this_send) {
		/*
		 * Get our pacing rate, if an error
		 * occured in sending (ENOBUF) we would
		 * hit the else if with slot preset. Other
		 * errors return.
		 */
		slot = rack_get_pacing_delay(rack, tp, tot_len_this_send, rsm, segsiz);
	}
	if (rsm &&
	    rack->use_rack_rr) {
		/* Its a retransmit and we use the rack cheat? */
		if ((slot == 0) ||
		    (rack->rc_always_pace == 0) ||
		    (rack->r_rr_config == 1)) {
			/*
			 * We have no pacing set or we
			 * are using old-style rack or
			 * we are overriden to use the old 1ms pacing.
			 */
			slot = rack->r_ctl.rc_min_to * HPTS_USEC_IN_MSEC;
		}
	}
	if (slot) {
		/* set the rack tcb into the slot N */
		counter_u64_add(rack_paced_segments, 1);
	} else if (sendalot) {
		if (len)
			counter_u64_add(rack_unpaced_segments, 1);
		sack_rxmit = 0;
		goto again;
	} else if (len) {
		counter_u64_add(rack_unpaced_segments, 1);
	}
	rack_start_hpts_timer(rack, tp, cts, slot, tot_len_this_send, 0);
	return (error);
}

static void
rack_update_seg(struct tcp_rack *rack)
{
	uint32_t orig_val;

	orig_val = rack->r_ctl.rc_pace_max_segs;
	rack_set_pace_segments(rack->rc_tp, rack, __LINE__);
	if (orig_val != rack->r_ctl.rc_pace_max_segs)
		rack_log_pacing_delay_calc(rack, 0, 0, orig_val, 0, 0, 15, __LINE__, NULL);
}

/*
 * rack_ctloutput() must drop the inpcb lock before performing copyin on
 * socket option arguments.  When it re-acquires the lock after the copy, it
 * has to revalidate that the connection is still valid for the socket
 * option.
 */
static int
rack_set_sockopt(struct socket *so, struct sockopt *sopt,
    struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack)
{
	struct epoch_tracker et;
	uint64_t val;
	int32_t error = 0, optval;
	uint16_t ca, ss;


	switch (sopt->sopt_name) {
	case TCP_RACK_PROP_RATE:		/*  URL:prop_rate */
	case TCP_RACK_PROP	:		/*  URL:prop */
	case TCP_RACK_TLP_REDUCE:		/*  URL:tlp_reduce */
	case TCP_RACK_EARLY_RECOV:		/*  URL:early_recov */
	case TCP_RACK_PACE_REDUCE:		/*  Not used */
        /*  Pacing related ones */
	case TCP_RACK_PACE_ALWAYS:		/*  URL:pace_always */
	case TCP_BBR_RACK_INIT_RATE:		/*  URL:irate */
	case TCP_BBR_IWINTSO:			/*  URL:tso_iwin */
	case TCP_RACK_PACE_MAX_SEG:		/*  URL:pace_max_seg */
	case TCP_RACK_FORCE_MSEG:		/*  URL:force_max_seg */
	case TCP_RACK_PACE_RATE_CA:		/*  URL:pr_ca */
	case TCP_RACK_PACE_RATE_SS:		/*  URL:pr_ss*/
	case TCP_RACK_PACE_RATE_REC:		/*  URL:pr_rec */
	case TCP_RACK_GP_INCREASE_CA:		/*  URL:gp_inc_ca */
	case TCP_RACK_GP_INCREASE_SS:		/*  URL:gp_inc_ss */
	case TCP_RACK_GP_INCREASE_REC:		/*  URL:gp_inc_rec */
	case TCP_RACK_RR_CONF:			/*  URL:rrr_conf */
	case TCP_BBR_HDWR_PACE:			/*  URL:hdwrpace */
       /* End pacing related */
	case TCP_DELACK:
	case TCP_RACK_PRR_SENDALOT:		/*  URL:prr_sendalot */
	case TCP_RACK_MIN_TO:			/*  URL:min_to */
	case TCP_RACK_EARLY_SEG:		/*  URL:early_seg */
	case TCP_RACK_REORD_THRESH:		/*  URL:reord_thresh */
	case TCP_RACK_REORD_FADE:		/*  URL:reord_fade */
	case TCP_RACK_TLP_THRESH:		/*  URL:tlp_thresh */
	case TCP_RACK_PKT_DELAY:		/*  URL:pkt_delay */
	case TCP_RACK_TLP_USE:			/*  URL:tlp_use */
	case TCP_RACK_TLP_INC_VAR:		/*  URL:tlp_inc_var */
	case TCP_RACK_IDLE_REDUCE_HIGH:		/*  URL:idle_reduce_high */
	case TCP_BBR_RACK_RTT_USE:		/*  URL:rttuse */
	case TCP_BBR_USE_RACK_RR:		/*  URL:rackrr */
	case TCP_RACK_DO_DETECTION:		/*  URL:detect */
	case TCP_NO_PRR:			/*  URL:noprr */
	case TCP_TIMELY_DYN_ADJ:		/*  URL:dynamic */
	case TCP_DATA_AFTER_CLOSE:
	case TCP_RACK_NONRXT_CFG_RATE:		/*  URL:nonrxtcr */
	case TCP_SHARED_CWND_ENABLE:		/*  URL:scwnd */
	case TCP_RACK_MBUF_QUEUE:		/*  URL:mqueue */
	case TCP_RACK_NO_PUSH_AT_MAX:		/*  URL:npush */
	case TCP_RACK_PACE_TO_FILL:		/*  URL:fillcw */
	case TCP_SHARED_CWND_TIME_LIMIT:	/*  URL:lscwnd */
	case TCP_RACK_PROFILE:			/*  URL:profile */
		break;
	default:
		return (tcp_default_ctloutput(so, sopt, inp, tp));
		break;
	}
	INP_WUNLOCK(inp);
	error = sooptcopyin(sopt, &optval, sizeof(optval), sizeof(optval));
	if (error)
		return (error);
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	switch (sopt->sopt_name) {
	case TCP_RACK_PROFILE:
		RACK_OPTS_INC(tcp_profile);
		if (optval == 1) {
			/* pace_always=1 */
			rack->rc_always_pace = 1;
			tp->t_inpcb->inp_flags2 |= INP_SUPPORTS_MBUFQ;
			/* scwnd=1 */
			rack->rack_enable_scwnd = 1;
			/* dynamic=100 */
			rack->rc_gp_dyn_mul = 1;
			rack->r_ctl.rack_per_of_gp_ca = 100;
			/* rrr_conf=3 */
			rack->r_rr_config = 3;
			/* npush=2 */
			rack->r_ctl.rc_no_push_at_mrtt = 2;
			/* fillcw=1 */
			rack->rc_pace_to_cwnd = 1;
			rack->rc_pace_fill_if_rttin_range = 0;
			rack->rtt_limit_mul = 0;
			/* noprr=1 */
			rack->rack_no_prr = 1;
			/* lscwnd=1 */
			rack->r_limit_scw = 1;
		} else if (optval == 2) {
			/* pace_always=1 */
			rack->rc_always_pace = 1;
			tp->t_inpcb->inp_flags2 |= INP_SUPPORTS_MBUFQ;
			/* scwnd=1 */
			rack->rack_enable_scwnd = 1;
			/* dynamic=100 */
			rack->rc_gp_dyn_mul = 1;
			rack->r_ctl.rack_per_of_gp_ca = 100;
			/* rrr_conf=3 */
			rack->r_rr_config = 3;
			/* npush=2 */
			rack->r_ctl.rc_no_push_at_mrtt = 2;
			/* fillcw=1 */
			rack->rc_pace_to_cwnd = 1;
			rack->rc_pace_fill_if_rttin_range = 0;
			rack->rtt_limit_mul = 0;
			/* noprr=1 */
			rack->rack_no_prr = 1;
			/* lscwnd=0 */
			rack->r_limit_scw = 0;
		}
		break;
	case TCP_SHARED_CWND_TIME_LIMIT:
		RACK_OPTS_INC(tcp_lscwnd);
		if (optval)
			rack->r_limit_scw = 1;
		else
			rack->r_limit_scw = 0;
		break;
 	case TCP_RACK_PACE_TO_FILL:
		RACK_OPTS_INC(tcp_fillcw);
		if (optval == 0)
			rack->rc_pace_to_cwnd = 0;
		else
			rack->rc_pace_to_cwnd = 1;
		if ((optval >= rack_gp_rtt_maxmul) &&
		    rack_gp_rtt_maxmul &&
		    (optval < 0xf)) {
			rack->rc_pace_fill_if_rttin_range = 1;
			rack->rtt_limit_mul = optval;
		} else {
			rack->rc_pace_fill_if_rttin_range = 0;
			rack->rtt_limit_mul = 0;
		}
		break;
	case TCP_RACK_NO_PUSH_AT_MAX:
		RACK_OPTS_INC(tcp_npush);
		if (optval == 0)
			rack->r_ctl.rc_no_push_at_mrtt = 0;
		else if (optval < 0xff)
			rack->r_ctl.rc_no_push_at_mrtt = optval;
		else
			error = EINVAL;
		break;
	case TCP_SHARED_CWND_ENABLE:
		RACK_OPTS_INC(tcp_rack_scwnd);
		if (optval == 0)
			rack->rack_enable_scwnd = 0;
		else
			rack->rack_enable_scwnd = 1;
		break;
	case TCP_RACK_MBUF_QUEUE:
		/* Now do we use the LRO mbuf-queue feature */
		RACK_OPTS_INC(tcp_rack_mbufq);
		if (optval)
			rack->r_mbuf_queue = 1;
		else
			rack->r_mbuf_queue = 0;
		if  (rack->r_mbuf_queue || rack->rc_always_pace)
			tp->t_inpcb->inp_flags2 |= INP_SUPPORTS_MBUFQ;
		else
			tp->t_inpcb->inp_flags2 &= ~INP_SUPPORTS_MBUFQ;
		break;
	case TCP_RACK_NONRXT_CFG_RATE:
		RACK_OPTS_INC(tcp_rack_cfg_rate);
		if (optval == 0)
			rack->rack_rec_nonrxt_use_cr = 0;
		else
			rack->rack_rec_nonrxt_use_cr = 1;
		break;
	case TCP_NO_PRR:
		RACK_OPTS_INC(tcp_rack_noprr);
		if (optval == 0)
			rack->rack_no_prr = 0;
		else
			rack->rack_no_prr = 1;
		break;
	case TCP_TIMELY_DYN_ADJ:
		RACK_OPTS_INC(tcp_timely_dyn);
		if (optval == 0)
			rack->rc_gp_dyn_mul = 0;
		else {
			rack->rc_gp_dyn_mul = 1;
			if (optval >= 100) {
				/*
				 * If the user sets something 100 or more
				 * its the gp_ca value.
				 */
				rack->r_ctl.rack_per_of_gp_ca  = optval;
			}
		}
		break;
	case TCP_RACK_DO_DETECTION:
		RACK_OPTS_INC(tcp_rack_do_detection);
		if (optval == 0)
			rack->do_detection = 0;
		else
			rack->do_detection = 1;
		break;
	case TCP_RACK_PROP_RATE:
		if ((optval <= 0) || (optval >= 100)) {
			error = EINVAL;
			break;
		}
		RACK_OPTS_INC(tcp_rack_prop_rate);
		rack->r_ctl.rc_prop_rate = optval;
		break;
	case TCP_RACK_TLP_USE:
		if ((optval < TLP_USE_ID) || (optval > TLP_USE_TWO_TWO)) {
			error = EINVAL;
			break;
		}
		RACK_OPTS_INC(tcp_tlp_use);
		rack->rack_tlp_threshold_use = optval;
		break;
	case TCP_RACK_PROP:
		/* RACK proportional rate reduction (bool) */
		RACK_OPTS_INC(tcp_rack_prop);
		rack->r_ctl.rc_prop_reduce = optval;
		break;
	case TCP_RACK_TLP_REDUCE:
		/* RACK TLP cwnd reduction (bool) */
		RACK_OPTS_INC(tcp_rack_tlp_reduce);
		rack->r_ctl.rc_tlp_cwnd_reduce = optval;
		break;
	case TCP_RACK_EARLY_RECOV:
		/* Should recovery happen early (bool) */
		RACK_OPTS_INC(tcp_rack_early_recov);
		rack->r_ctl.rc_early_recovery = optval;
		break;

        /*  Pacing related ones */
	case TCP_RACK_PACE_ALWAYS:
		/*
		 * zero is old rack method, 1 is new
		 * method using a pacing rate.
		 */
		RACK_OPTS_INC(tcp_rack_pace_always);
		if (optval > 0)
			rack->rc_always_pace = 1;
		else
			rack->rc_always_pace = 0;
		if  (rack->r_mbuf_queue || rack->rc_always_pace)
			tp->t_inpcb->inp_flags2 |= INP_SUPPORTS_MBUFQ;
		else
			tp->t_inpcb->inp_flags2 &= ~INP_SUPPORTS_MBUFQ;
		/* A rate may be set irate or other, if so set seg size */
		rack_update_seg(rack);
		break;
	case TCP_BBR_RACK_INIT_RATE:
		RACK_OPTS_INC(tcp_initial_rate);
		val = optval;
		/* Change from kbits per second to bytes per second */
		val *= 1000;
		val /= 8;
		rack->r_ctl.init_rate = val;
		if (rack->rc_init_win != rack_default_init_window) {
			uint32_t win, snt;

			/*
			 * Options don't always get applied
			 * in the order you think. So in order
			 * to assure we update a cwnd we need
			 * to check and see if we are still
			 * where we should raise the cwnd.
			 */
			win = rc_init_window(rack);
			if (SEQ_GT(tp->snd_max, tp->iss))
				snt = tp->snd_max - tp->iss;
			else
				snt = 0;
			if ((snt < win) &&
			    (tp->snd_cwnd < win))
				tp->snd_cwnd = win;
		}
		if (rack->rc_always_pace)
			rack_update_seg(rack);
		break;
	case TCP_BBR_IWINTSO:
		RACK_OPTS_INC(tcp_initial_win);
		if (optval && (optval <= 0xff)) {
			uint32_t win, snt;

			rack->rc_init_win = optval;
			win = rc_init_window(rack);
			if (SEQ_GT(tp->snd_max, tp->iss))
				snt = tp->snd_max - tp->iss;
			else
				snt = 0;
			if ((snt < win) &&
			    (tp->t_srtt |
#ifdef NETFLIX_PEAKRATE
			     tp->t_maxpeakrate |
#endif
			     rack->r_ctl.init_rate)) {
				/*
				 * We are not past the initial window
				 * and we have some bases for pacing,
				 * so we need to possibly adjust up
				 * the cwnd. Note even if we don't set
				 * the cwnd, its still ok to raise the rc_init_win
				 * which can be used coming out of idle when we
				 * would have a rate.
				 */
				if (tp->snd_cwnd < win)
					tp->snd_cwnd = win;
			}
			if (rack->rc_always_pace)
				rack_update_seg(rack);
		} else
			error = EINVAL;
		break;
	case TCP_RACK_FORCE_MSEG:
		RACK_OPTS_INC(tcp_rack_force_max_seg);
		if (optval)
			rack->rc_force_max_seg = 1;
		else
			rack->rc_force_max_seg = 0;
		break;
	case TCP_RACK_PACE_MAX_SEG:
		/* Max segments size in a pace in bytes */
		RACK_OPTS_INC(tcp_rack_max_seg);
		rack->rc_user_set_max_segs = optval;
		rack_set_pace_segments(tp, rack, __LINE__);
		break;
	case TCP_RACK_PACE_RATE_REC:
		/* Set the fixed pacing rate in Bytes per second ca */
		RACK_OPTS_INC(tcp_rack_pace_rate_rec);
		rack->r_ctl.rc_fixed_pacing_rate_rec = optval;
		if (rack->r_ctl.rc_fixed_pacing_rate_ca == 0)
			rack->r_ctl.rc_fixed_pacing_rate_ca = optval;
		if (rack->r_ctl.rc_fixed_pacing_rate_ss == 0)
			rack->r_ctl.rc_fixed_pacing_rate_ss = optval;
		rack->use_fixed_rate = 1;
		rack_log_pacing_delay_calc(rack,
					   rack->r_ctl.rc_fixed_pacing_rate_ss,
					   rack->r_ctl.rc_fixed_pacing_rate_ca,
					   rack->r_ctl.rc_fixed_pacing_rate_rec, 0, 0, 8,
					   __LINE__, NULL);
		break;

	case TCP_RACK_PACE_RATE_SS:
		/* Set the fixed pacing rate in Bytes per second ca */
		RACK_OPTS_INC(tcp_rack_pace_rate_ss);
		rack->r_ctl.rc_fixed_pacing_rate_ss = optval;
		if (rack->r_ctl.rc_fixed_pacing_rate_ca == 0)
			rack->r_ctl.rc_fixed_pacing_rate_ca = optval;
		if (rack->r_ctl.rc_fixed_pacing_rate_rec == 0)
			rack->r_ctl.rc_fixed_pacing_rate_rec = optval;
		rack->use_fixed_rate = 1;
		rack_log_pacing_delay_calc(rack,
					   rack->r_ctl.rc_fixed_pacing_rate_ss,
					   rack->r_ctl.rc_fixed_pacing_rate_ca,
					   rack->r_ctl.rc_fixed_pacing_rate_rec, 0, 0, 8,
					   __LINE__, NULL);
		break;

	case TCP_RACK_PACE_RATE_CA:
		/* Set the fixed pacing rate in Bytes per second ca */
		RACK_OPTS_INC(tcp_rack_pace_rate_ca);
		rack->r_ctl.rc_fixed_pacing_rate_ca = optval;
		if (rack->r_ctl.rc_fixed_pacing_rate_ss == 0)
			rack->r_ctl.rc_fixed_pacing_rate_ss = optval;
		if (rack->r_ctl.rc_fixed_pacing_rate_rec == 0)
			rack->r_ctl.rc_fixed_pacing_rate_rec = optval;
		rack->use_fixed_rate = 1;
		rack_log_pacing_delay_calc(rack,
					   rack->r_ctl.rc_fixed_pacing_rate_ss,
					   rack->r_ctl.rc_fixed_pacing_rate_ca,
					   rack->r_ctl.rc_fixed_pacing_rate_rec, 0, 0, 8,
					   __LINE__, NULL);
		break;
	case TCP_RACK_GP_INCREASE_REC:
		RACK_OPTS_INC(tcp_gp_inc_rec);
		rack->r_ctl.rack_per_of_gp_rec = optval;
		rack_log_pacing_delay_calc(rack,
					   rack->r_ctl.rack_per_of_gp_ss,
					   rack->r_ctl.rack_per_of_gp_ca,
					   rack->r_ctl.rack_per_of_gp_rec, 0, 0, 1,
					   __LINE__, NULL);
		break;
	case TCP_RACK_GP_INCREASE_CA:
		RACK_OPTS_INC(tcp_gp_inc_ca);
		ca = optval;
		if (ca < 100) {
			/*
			 * We don't allow any reduction
			 * over the GP b/w.
			 */
			error = EINVAL;
			break;
		}
		rack->r_ctl.rack_per_of_gp_ca = ca;
		rack_log_pacing_delay_calc(rack,
					   rack->r_ctl.rack_per_of_gp_ss,
					   rack->r_ctl.rack_per_of_gp_ca,
					   rack->r_ctl.rack_per_of_gp_rec, 0, 0, 1,
					   __LINE__, NULL);
		break;
	case TCP_RACK_GP_INCREASE_SS:
		RACK_OPTS_INC(tcp_gp_inc_ss);
		ss = optval;
		if (ss < 100) {
			/*
			 * We don't allow any reduction
			 * over the GP b/w.
			 */
			error = EINVAL;
			break;
		}
		rack->r_ctl.rack_per_of_gp_ss = ss;
		rack_log_pacing_delay_calc(rack,
					   rack->r_ctl.rack_per_of_gp_ss,
					   rack->r_ctl.rack_per_of_gp_ca,
					   rack->r_ctl.rack_per_of_gp_rec, 0, 0, 1,
					   __LINE__, NULL);
		break;
	case TCP_RACK_RR_CONF:
		RACK_OPTS_INC(tcp_rack_rrr_no_conf_rate);
		if (optval && optval <= 3)
			rack->r_rr_config = optval;
		else
			rack->r_rr_config = 0;
		break;
	case TCP_BBR_HDWR_PACE:
		RACK_OPTS_INC(tcp_hdwr_pacing);
		if (optval){
			if (rack->rack_hdrw_pacing == 0) {
				rack->rack_hdw_pace_ena = 1;
				rack->rack_attempt_hdwr_pace = 0;
			} else
				error = EALREADY;
		} else {
			rack->rack_hdw_pace_ena = 0;
#ifdef RATELIMIT
			if (rack->rack_hdrw_pacing) {
				rack->rack_hdrw_pacing = 0;
				in_pcbdetach_txrtlmt(rack->rc_inp);
			}
#endif
		}
		break;
        /*  End Pacing related ones */
	case TCP_RACK_PRR_SENDALOT:
		/* Allow PRR to send more than one seg */
		RACK_OPTS_INC(tcp_rack_prr_sendalot);
		rack->r_ctl.rc_prr_sendalot = optval;
		break;
	case TCP_RACK_MIN_TO:
		/* Minimum time between rack t-o's in ms */
		RACK_OPTS_INC(tcp_rack_min_to);
		rack->r_ctl.rc_min_to = optval;
		break;
	case TCP_RACK_EARLY_SEG:
		/* If early recovery max segments */
		RACK_OPTS_INC(tcp_rack_early_seg);
		rack->r_ctl.rc_early_recovery_segs = optval;
		break;
	case TCP_RACK_REORD_THRESH:
		/* RACK reorder threshold (shift amount) */
		RACK_OPTS_INC(tcp_rack_reord_thresh);
		if ((optval > 0) && (optval < 31))
			rack->r_ctl.rc_reorder_shift = optval;
		else
			error = EINVAL;
		break;
	case TCP_RACK_REORD_FADE:
		/* Does reordering fade after ms time */
		RACK_OPTS_INC(tcp_rack_reord_fade);
		rack->r_ctl.rc_reorder_fade = optval;
		break;
	case TCP_RACK_TLP_THRESH:
		/* RACK TLP theshold i.e. srtt+(srtt/N) */
		RACK_OPTS_INC(tcp_rack_tlp_thresh);
		if (optval)
			rack->r_ctl.rc_tlp_threshold = optval;
		else
			error = EINVAL;
		break;
	case TCP_BBR_USE_RACK_RR:
		RACK_OPTS_INC(tcp_rack_rr);
		if (optval)
			rack->use_rack_rr = 1;
		else
			rack->use_rack_rr = 0;
		break;
	case TCP_RACK_PKT_DELAY:
		/* RACK added ms i.e. rack-rtt + reord + N */
		RACK_OPTS_INC(tcp_rack_pkt_delay);
		rack->r_ctl.rc_pkt_delay = optval;
		break;
	case TCP_RACK_TLP_INC_VAR:
		/* Does TLP include rtt variance in t-o */
		error = EINVAL;
		break;
	case TCP_RACK_IDLE_REDUCE_HIGH:
		error = EINVAL;
		break;
	case TCP_DELACK:
		if (optval == 0)
			tp->t_delayed_ack = 0;
		else
			tp->t_delayed_ack = 1;
		if (tp->t_flags & TF_DELACK) {
			tp->t_flags &= ~TF_DELACK;
			tp->t_flags |= TF_ACKNOW;
			NET_EPOCH_ENTER(et);
			rack_output(tp);
			NET_EPOCH_EXIT(et);
		}
		break;

	case TCP_BBR_RACK_RTT_USE:
		if ((optval != USE_RTT_HIGH) &&
		    (optval != USE_RTT_LOW) &&
		    (optval != USE_RTT_AVG))
			error = EINVAL;
		else
			rack->r_ctl.rc_rate_sample_method = optval;
		break;
	case TCP_DATA_AFTER_CLOSE:
		if (optval)
			rack->rc_allow_data_af_clo = 1;
		else
			rack->rc_allow_data_af_clo = 0;
		break;
	case TCP_RACK_PACE_REDUCE:
		/* sysctl only now */
		error = EINVAL;
		break;
	default:
		return (tcp_default_ctloutput(so, sopt, inp, tp));
		break;
	}
#ifdef NETFLIX_STATS
	tcp_log_socket_option(tp, sopt->sopt_name, optval, error);
#endif
	INP_WUNLOCK(inp);
	return (error);
}

static int
rack_get_sockopt(struct socket *so, struct sockopt *sopt,
    struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack)
{
	int32_t error, optval;
	uint64_t val;
	/*
	 * Because all our options are either boolean or an int, we can just
	 * pull everything into optval and then unlock and copy. If we ever
	 * add a option that is not a int, then this will have quite an
	 * impact to this routine.
	 */
	error = 0;
	switch (sopt->sopt_name) {
	case TCP_RACK_PROFILE:
		/* You cannot retrieve a profile, its write only */
		error = EINVAL;
		break;
	case TCP_RACK_PACE_TO_FILL:
		optval = rack->rc_pace_to_cwnd;
		break;
	case TCP_RACK_NO_PUSH_AT_MAX:
		optval = rack->r_ctl.rc_no_push_at_mrtt;
		break;
	case TCP_SHARED_CWND_ENABLE:
		optval = rack->rack_enable_scwnd;
		break;
	case TCP_RACK_NONRXT_CFG_RATE:
		optval = rack->rack_rec_nonrxt_use_cr;
		break;
	case TCP_NO_PRR:
		optval = rack->rack_no_prr;
		break;
	case TCP_RACK_DO_DETECTION:
		optval = rack->do_detection;
		break;
	case TCP_RACK_MBUF_QUEUE:
		/* Now do we use the LRO mbuf-queue feature */
		optval = rack->r_mbuf_queue;
		break;
	case TCP_TIMELY_DYN_ADJ:
		optval = rack->rc_gp_dyn_mul;
		break;
	case TCP_BBR_IWINTSO:
		optval = rack->rc_init_win;
		break;
	case TCP_RACK_PROP_RATE:
		optval = rack->r_ctl.rc_prop_rate;
		break;
	case TCP_RACK_PROP:
		/* RACK proportional rate reduction (bool) */
		optval = rack->r_ctl.rc_prop_reduce;
		break;
	case TCP_RACK_TLP_REDUCE:
		/* RACK TLP cwnd reduction (bool) */
		optval = rack->r_ctl.rc_tlp_cwnd_reduce;
		break;
	case TCP_RACK_EARLY_RECOV:
		/* Should recovery happen early (bool) */
		optval = rack->r_ctl.rc_early_recovery;
		break;
	case TCP_RACK_PACE_REDUCE:
		/* RACK Hptsi reduction factor (divisor) */
		error = EINVAL;
		break;
	case TCP_BBR_RACK_INIT_RATE:
		val = rack->r_ctl.init_rate;
		/* convert to kbits per sec */
		val *= 8;
		val /= 1000;
		optval = (uint32_t)val;
		break;
	case TCP_RACK_FORCE_MSEG:
		optval = rack->rc_force_max_seg;
		break;
	case TCP_RACK_PACE_MAX_SEG:
		/* Max segments in a pace */
		optval = rack->rc_user_set_max_segs;
		break;
	case TCP_RACK_PACE_ALWAYS:
		/* Use the always pace method */
		optval = rack->rc_always_pace;
		break;
	case TCP_RACK_PRR_SENDALOT:
		/* Allow PRR to send more than one seg */
		optval = rack->r_ctl.rc_prr_sendalot;
		break;
	case TCP_RACK_MIN_TO:
		/* Minimum time between rack t-o's in ms */
		optval = rack->r_ctl.rc_min_to;
		break;
	case TCP_RACK_EARLY_SEG:
		/* If early recovery max segments */
		optval = rack->r_ctl.rc_early_recovery_segs;
		break;
	case TCP_RACK_REORD_THRESH:
		/* RACK reorder threshold (shift amount) */
		optval = rack->r_ctl.rc_reorder_shift;
		break;
	case TCP_RACK_REORD_FADE:
		/* Does reordering fade after ms time */
		optval = rack->r_ctl.rc_reorder_fade;
		break;
	case TCP_BBR_USE_RACK_RR:
		/* Do we use the rack cheat for rxt */
		optval = rack->use_rack_rr;
		break;
	case TCP_RACK_RR_CONF:
		optval = rack->r_rr_config;
		break;
	case TCP_BBR_HDWR_PACE:
		optval = rack->rack_hdw_pace_ena;
		break;
	case TCP_RACK_TLP_THRESH:
		/* RACK TLP theshold i.e. srtt+(srtt/N) */
		optval = rack->r_ctl.rc_tlp_threshold;
		break;
	case TCP_RACK_PKT_DELAY:
		/* RACK added ms i.e. rack-rtt + reord + N */
		optval = rack->r_ctl.rc_pkt_delay;
		break;
	case TCP_RACK_TLP_USE:
		optval = rack->rack_tlp_threshold_use;
		break;
	case TCP_RACK_TLP_INC_VAR:
		/* Does TLP include rtt variance in t-o */
		error = EINVAL;
		break;
	case TCP_RACK_IDLE_REDUCE_HIGH:
		error = EINVAL;
		break;
	case TCP_RACK_PACE_RATE_CA:
		optval = rack->r_ctl.rc_fixed_pacing_rate_ca;
		break;
	case TCP_RACK_PACE_RATE_SS:
		optval = rack->r_ctl.rc_fixed_pacing_rate_ss;
		break;
	case TCP_RACK_PACE_RATE_REC:
		optval = rack->r_ctl.rc_fixed_pacing_rate_rec;
		break;
	case TCP_RACK_GP_INCREASE_SS:
		optval = rack->r_ctl.rack_per_of_gp_ca;
		break;
	case TCP_RACK_GP_INCREASE_CA:
		optval = rack->r_ctl.rack_per_of_gp_ss;
		break;
	case TCP_BBR_RACK_RTT_USE:
		optval = rack->r_ctl.rc_rate_sample_method;
		break;
	case TCP_DELACK:
		optval = tp->t_delayed_ack;
		break;
	case TCP_DATA_AFTER_CLOSE:
		optval = rack->rc_allow_data_af_clo;
		break;
	case TCP_SHARED_CWND_TIME_LIMIT:
		optval = rack->r_limit_scw;
		break;
	default:
		return (tcp_default_ctloutput(so, sopt, inp, tp));
		break;
	}
	INP_WUNLOCK(inp);
	if (error == 0) {
		error = sooptcopyout(sopt, &optval, sizeof optval);
	}
	return (error);
}

static int
rack_ctloutput(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp)
{
	int32_t error = EINVAL;
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack == NULL) {
		/* Huh? */
		goto out;
	}
	if (sopt->sopt_dir == SOPT_SET) {
		return (rack_set_sockopt(so, sopt, inp, tp, rack));
	} else if (sopt->sopt_dir == SOPT_GET) {
		return (rack_get_sockopt(so, sopt, inp, tp, rack));
	}
out:
	INP_WUNLOCK(inp);
	return (error);
}

static int
rack_pru_options(struct tcpcb *tp, int flags)
{
	if (flags & PRUS_OOB)
		return (EOPNOTSUPP);
	return (0);
}

static struct tcp_function_block __tcp_rack = {
	.tfb_tcp_block_name = __XSTRING(STACKNAME),
	.tfb_tcp_output = rack_output,
	.tfb_do_queued_segments = ctf_do_queued_segments,
	.tfb_do_segment_nounlock = rack_do_segment_nounlock,
	.tfb_tcp_do_segment = rack_do_segment,
	.tfb_tcp_ctloutput = rack_ctloutput,
	.tfb_tcp_fb_init = rack_init,
	.tfb_tcp_fb_fini = rack_fini,
	.tfb_tcp_timer_stop_all = rack_stopall,
	.tfb_tcp_timer_activate = rack_timer_activate,
	.tfb_tcp_timer_active = rack_timer_active,
	.tfb_tcp_timer_stop = rack_timer_stop,
	.tfb_tcp_rexmit_tmr = rack_remxt_tmr,
	.tfb_tcp_handoff_ok = rack_handoff_ok,
	.tfb_pru_options = rack_pru_options,
};

static const char *rack_stack_names[] = {
	__XSTRING(STACKNAME),
#ifdef STACKALIAS
	__XSTRING(STACKALIAS),
#endif
};

static int
rack_ctor(void *mem, int32_t size, void *arg, int32_t how)
{
	memset(mem, 0, size);
	return (0);
}

static void
rack_dtor(void *mem, int32_t size, void *arg)
{

}

static bool rack_mod_inited = false;

static int
tcp_addrack(module_t mod, int32_t type, void *data)
{
	int32_t err = 0;
	int num_stacks;

	switch (type) {
	case MOD_LOAD:
		rack_zone = uma_zcreate(__XSTRING(MODNAME) "_map",
		    sizeof(struct rack_sendmap),
		    rack_ctor, rack_dtor, NULL, NULL, UMA_ALIGN_PTR, 0);

		rack_pcb_zone = uma_zcreate(__XSTRING(MODNAME) "_pcb",
		    sizeof(struct tcp_rack),
		    rack_ctor, NULL, NULL, NULL, UMA_ALIGN_CACHE, 0);

		sysctl_ctx_init(&rack_sysctl_ctx);
		rack_sysctl_root = SYSCTL_ADD_NODE(&rack_sysctl_ctx,
		    SYSCTL_STATIC_CHILDREN(_net_inet_tcp),
		    OID_AUTO,
#ifdef STACKALIAS
		    __XSTRING(STACKALIAS),
#else
		    __XSTRING(STACKNAME),
#endif
		    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
		    "");
		if (rack_sysctl_root == NULL) {
			printf("Failed to add sysctl node\n");
			err = EFAULT;
			goto free_uma;
		}
		rack_init_sysctls();
		num_stacks = nitems(rack_stack_names);
		err = register_tcp_functions_as_names(&__tcp_rack, M_WAITOK,
		    rack_stack_names, &num_stacks);
		if (err) {
			printf("Failed to register %s stack name for "
			    "%s module\n", rack_stack_names[num_stacks],
			    __XSTRING(MODNAME));
			sysctl_ctx_free(&rack_sysctl_ctx);
free_uma:
			uma_zdestroy(rack_zone);
			uma_zdestroy(rack_pcb_zone);
			rack_counter_destroy();
			printf("Failed to register rack module -- err:%d\n", err);
			return (err);
		}
		tcp_lro_reg_mbufq();
		rack_mod_inited = true;
		break;
	case MOD_QUIESCE:
		err = deregister_tcp_functions(&__tcp_rack, true, false);
		break;
	case MOD_UNLOAD:
		err = deregister_tcp_functions(&__tcp_rack, false, true);
		if (err == EBUSY)
			break;
		if (rack_mod_inited) {
			uma_zdestroy(rack_zone);
			uma_zdestroy(rack_pcb_zone);
			sysctl_ctx_free(&rack_sysctl_ctx);
			rack_counter_destroy();
			rack_mod_inited = false;
		}
		tcp_lro_dereg_mbufq();
		err = 0;
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (err);
}

static moduledata_t tcp_rack = {
	.name = __XSTRING(MODNAME),
	.evhand = tcp_addrack,
	.priv = 0
};

MODULE_VERSION(MODNAME, 1);
DECLARE_MODULE(MODNAME, tcp_rack, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_DEPEND(MODNAME, tcphpts, 1, 1, 1);
