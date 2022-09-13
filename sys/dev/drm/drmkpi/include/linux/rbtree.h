/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
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

#ifndef __DRMCOMPAT_LINUX_RBTREE_H__
#define	__DRMCOMPAT_LINUX_RBTREE_H__

#include <sys/stddef.h>
#include <sys/tree.h>

struct rb_node {
	RB_ENTRY(rb_node)	__entry;
};
#define	rb_left		__entry.rbe_link[_RB_L]
#define	rb_right	__entry.rbe_link[_RB_R]

/*
 * We provide a false structure that has the same bit pattern as tree.h
 * presents so it matches the member names expected by linux.
 */
struct rb_root {
	struct	rb_node	*rb_node;
};

struct rb_root_cached {
	struct  rb_root rb_root;
	struct  rb_node *rb_node;
};

/*
 * In linux all of the comparisons are done by the caller.
 */
int panic_cmp(struct rb_node *one, struct rb_node *two);

RB_HEAD(drmcompat_root, rb_node);
RB_PROTOTYPE(drmcompat_root, rb_node, __entry, panic_cmp);

#define	rb_parent(r)	RB_PARENT(r, __entry)
#define	rb_entry(ptr, type, member)	container_of(ptr, type, member)
#define	rb_entry_safe(ptr, type, member) \
	(ptr ? rb_entry(ptr, type, member) : NULL)

#define RB_EMPTY_ROOT(root)     RB_EMPTY((struct drmcompat_root *)root)
#define RB_EMPTY_NODE(node)     (RB_PARENT(node, __entry) == node)
#define RB_CLEAR_NODE(node)     RB_SET_PARENT(node, node, __entry)

#define rb_insert_color(node, root) do {				\
	if (rb_parent(node))						\
		drmcompat_root_RB_INSERT_COLOR(				\
		    (struct drmcompat_root *)(root), rb_parent(node),	\
		    (node));						\
} while (0)
#define	rb_erase(node, root)						\
	drmcompat_root_RB_REMOVE((struct drmcompat_root *)(root), (node))
#define	rb_erase_cached(node, root)					\
	drmcompat_root_RB_REMOVE((struct drmcompat_root *)(root), (node))
#define	rb_next(node)	RB_NEXT(drmcompat_root, NULL, (node))
#define	rb_prev(node)	RB_PREV(drmcompat_root, NULL, (node))
#define	rb_first(root)	RB_MIN(drmcompat_root, (struct drmcompat_root *)(root))
#define	rb_first_cached(root)	RB_MIN(drmcompat_root, (struct drmcompat_root *)(root))
#define	rb_last(root)	RB_MAX(drmcompat_root, (struct drmcompat_root *)(root))

static inline void
rb_link_node(struct rb_node *node, struct rb_node *parent,
    struct rb_node **rb_link)
{
	RB_SET(node, parent, __entry);
	*rb_link = node;
}

static inline void
rb_replace_node(struct rb_node *victim, struct rb_node *new,
    struct rb_root *root)
{

	RB_SWAP_CHILD((struct drmcompat_root *)root, rb_parent(victim),
	    victim, new, __entry);
	if (RB_LEFT(victim, __entry))
		RB_SET_PARENT(RB_LEFT(victim, __entry), new, __entry);
	if (RB_RIGHT(victim, __entry))
		RB_SET_PARENT(RB_RIGHT(victim, __entry), new, __entry);
	*new = *victim;
}

static inline void
rb_insert_color_cached(struct rb_node *node, struct rb_root_cached *root,
    bool leftmost)
{
	if (rb_parent(node))
		drmcompat_root_RB_INSERT_COLOR(
		    (struct drmcompat_root *)&root->rb_root,
		    rb_parent(node), node);
	if (leftmost)
		root->rb_node = node;
}

static inline void
rb_replace_node_cached(struct rb_node *victim, struct rb_node *new,
  struct rb_root_cached *root)
{

	if (root->rb_node == victim)
		root->rb_node = victim;
	rb_replace_node(victim, new, &root->rb_root);
}

#undef RB_ROOT
#define RB_ROOT		(struct rb_root) { NULL }
#define RB_ROOT_CACHED	(struct rb_root_cached) { {NULL, }, NULL }

#endif	/* __DRMCOMPAT_LINUX_RBTREE_H__ */
