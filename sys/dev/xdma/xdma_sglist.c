/*-
 * Copyright (c) 2017-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <machine/bus.h>

#include <dev/xdma/xdma.h>

int
xchan_sglist_alloc(xdma_channel_t *xchan)
{
	uint32_t sz;

	if (xchan->flags & XCHAN_SGLIST_ALLOCATED)
		return (-1);

	sz = (sizeof(struct xdma_sglist) * XDMA_SGLIST_MAXLEN);
	xchan->sg = malloc(sz, M_XDMA, M_WAITOK | M_ZERO);
	xchan->flags |= XCHAN_SGLIST_ALLOCATED;

	return (0);
}

void
xchan_sglist_free(xdma_channel_t *xchan)
{

	if (xchan->flags & XCHAN_SGLIST_ALLOCATED)
		free(xchan->sg, M_XDMA);

	xchan->flags &= ~XCHAN_SGLIST_ALLOCATED;
}

int
xdma_sglist_add_busdma(struct xdma_sglist *sg, struct bus_dma_segment *seg,
    uint32_t nsegs, struct xdma_request *xr)
{
	int i;
	xdma_request_addr_t seg_addr;

	if (nsegs == 0)
		return (-1);

	for (i = 0; i < nsegs; i++) {
		seg_addr.bus_addr = seg[i].ds_addr;
		xdma_sglist_add(&sg[i], seg_addr, seg[i].ds_len, xr);
	}

	sg[0].first = 1;
	sg[nsegs - 1].last = 1;

	return (0);
}

int
xdma_sglist_add(struct xdma_sglist *sg, xdma_request_addr_t seg_addr,
    size_t len, struct xdma_request *xr)
{

	sg->src_width = xr->src_width;
	sg->dst_width = xr->dst_width;

	if (xr->direction == XDMA_MEM_TO_DEV) {
		sg->src = seg_addr;
		sg->dst = xr->dst;
	} else {
		sg->src = xr->src;
		sg->dst = seg_addr;
	}

	sg->len = len;
	sg->direction = xr->direction;
	sg->first = 0;
	sg->last = 0;

	return (0);
}
// CHERI CHANGES START
// {
//   "updated": 20221205,
//   "target_type": "header",
//   "changes_purecap": [
//     "pointer_as_integer",
//     "support"
//   ],
//   "change_comment": "bus_addr_t"
// }
// CHERI CHANGES END
