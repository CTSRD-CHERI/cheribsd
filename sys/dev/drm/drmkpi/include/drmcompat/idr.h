/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2016 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __DRMCOMPAT_IDR_H__
#define	__DRMCOMPAT_IDR_H__

/* IDR Implementation */
#define	IDR_BITS	5
#define	IDR_SIZE	(1 << IDR_BITS)
#define	IDR_MASK	(IDR_SIZE - 1)

struct idr_layer {
	unsigned long		bitmap;
	struct idr_layer	*ary[IDR_SIZE];
};

struct idr {
	struct mtx		lock;
	struct idr_layer	*top;
	struct idr_layer	*free;
	int			layers;
	int			next_cyclic_id;
};

/* IDA Implementation */
#define	IDA_CHUNK_SIZE		128	/* 128 bytes per chunk */
#define	IDA_BITMAP_LONGS	(IDA_CHUNK_SIZE / sizeof(long) - 1)
#define	IDA_BITMAP_BITS		(IDA_BITMAP_LONGS * sizeof(long) * 8)

struct ida_bitmap {
	long			nr_busy;
	unsigned long		bitmap[IDA_BITMAP_LONGS];
};

struct ida {
	struct idr		idr;
	struct ida_bitmap	*free_bitmap;
};

void	drmcompat_idr_preload(gfp_t gfp_mask);
void	drmcompat_idr_preload_end(void);
void	*drmcompat_idr_find(struct idr *idp, int id);
void	*drmcompat_idr_get_next(struct idr *idp, int *nextid);
bool	drmcompat_idr_is_empty(struct idr *idp);
int	drmcompat_idr_pre_get(struct idr *idp, gfp_t gfp_mask);
int	drmcompat_idr_get_new(struct idr *idp, void *ptr, int *id);
int	drmcompat_idr_get_new_above(struct idr *idp, void *ptr, int starting_id, int *id);
void	*drmcompat_idr_replace(struct idr *idp, void *ptr, int id);
void	*drmcompat_idr_remove(struct idr *idp, int id);
void	drmcompat_idr_remove_all(struct idr *idp);
void	drmcompat_idr_destroy(struct idr *idp);
void	drmcompat_idr_init(struct idr *idp);
int	drmcompat_idr_alloc(struct idr *idp, void *ptr, int start, int end, gfp_t);
int	drmcompat_idr_alloc_cyclic(struct idr *idp, void *ptr, int start, int end, gfp_t);
int	drmcompat_idr_for_each(struct idr *idp, int (*fn)(int id, void *p, void *data), void *data);

int	drmcompat_ida_pre_get(struct ida *ida, gfp_t gfp_mask);
int	drmcompat_ida_get_new_above(struct ida *ida, int starting_id, int *p_id);
void	drmcompat_ida_remove(struct ida *ida, int id);
void	drmcompat_ida_destroy(struct ida *ida);
void	drmcompat_ida_init(struct ida *ida);
int	drmcompat_ida_simple_get(struct ida *ida, unsigned int start, unsigned int end, gfp_t gfp_mask);
void	drmcompat_ida_simple_remove(struct ida *ida, unsigned int id);

#endif /* __DRMCOMPAT_IDR_H__ */
