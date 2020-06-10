/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Alexander V. Chernikov
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * This header file contains private definitions for nexthop routing.
 *
 * Header is not intended to be included by the code external to the
 * routing subsystem.
 */

#ifndef	_NET_ROUTE_NHOP_VAR_H_
#define	_NET_ROUTE_NHOP_VAR_H_

/* define nhop hash table */
struct nhop_priv;
CHT_SLIST_DEFINE(nhops, struct nhop_priv);
/* produce hash value for an object */
#define	nhops_hash_obj(_obj)	hash_priv(_obj)
/* compare two objects */
#define	nhops_cmp(_one, _two)	cmp_priv(_one, _two)
/* next object accessor */
#define	nhops_next(_obj)	(_obj)->nh_next


struct nh_control {
	struct nhops_head	nh_head;	/* hash table head */
	struct bitmask_head	nh_idx_head;	/* nhop index head */
	struct rwlock		ctl_lock;	/* overall ctl lock */
	struct rib_head		*ctl_rh;	/* pointer back to rnh */
	struct epoch_context	ctl_epoch_ctx;	/* epoch ctl helper */
};

#define	NHOPS_WLOCK(ctl)	rw_wlock(&(ctl)->ctl_lock)
#define	NHOPS_RLOCK(ctl)	rw_rlock(&(ctl)->ctl_lock)
#define	NHOPS_WUNLOCK(ctl)	rw_wunlock(&(ctl)->ctl_lock)
#define	NHOPS_RUNLOCK(ctl)	rw_runlock(&(ctl)->ctl_lock)
#define	NHOPS_LOCK_INIT(ctl)	rw_init(&(ctl)->ctl_lock, "nhop_ctl")
#define	NHOPS_LOCK_DESTROY(ctl)	rw_destroy(&(ctl)->ctl_lock)
#define	NHOPS_WLOCK_ASSERT(ctl)	rw_assert(&(ctl)->ctl_lock, RA_WLOCKED)


/* Control plane-only nhop data */
struct nhop_object;
struct nhop_priv {
	uint32_t		nh_idx;		/* nexthop index */
	uint8_t			nh_family;	/* address family of the lookup */
	uint16_t		nh_type;	/* nexthop type */
	void			*cb_func;	/* function handling additional rewrite caps */
	u_int			nh_refcnt;	/* number of references, refcount(9)  */
	u_int			nh_linked;	/* refcount(9), == 2 if linked to the list */
	int			rt_flags;	/* routing flags for the control plane */
	struct nhop_object	*nh;		/* backreference to the dataplane nhop */
	struct nh_control	*nh_control;	/* backreference to the rnh */
	struct nhop_priv	*nh_next;	/* hash table membership */
	struct vnet		*nh_vnet;	/* vnet nhop belongs to */
	struct epoch_context	nh_epoch_ctx;	/* epoch data for nhop */
};

#define	NH_IS_PINNED(_nh)	((_nh)->nh_priv->rt_flags & RTF_PINNED)

/* nhop.c */
struct nhop_priv *find_nhop(struct nh_control *ctl,
    const struct nhop_priv *nh_priv);
int link_nhop(struct nh_control *ctl, struct nhop_priv *nh_priv);
struct nhop_priv *unlink_nhop(struct nh_control *ctl, struct nhop_priv *nh_priv);

/* nhop_ctl.c */
int cmp_priv(const struct nhop_priv *_one, const struct nhop_priv *_two);

#endif

