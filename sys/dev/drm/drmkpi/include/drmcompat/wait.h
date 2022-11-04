/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
 * Copyright (c) 2017 Mark Johnston <markj@FreeBSD.org>
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

#ifndef __DRMCOMPAT_WAIT_H__
#define	__DRMCOMPAT_WAIT_H__

struct wait_queue_entry;
struct wait_queue_head;

typedef struct wait_queue_entry wait_queue_entry_t;
typedef struct wait_queue_head wait_queue_head_t;

typedef int wait_queue_func_t(wait_queue_entry_t *, unsigned int, int, void *);

/*
 * Many API consumers directly reference these fields and those of
 * wait_queue_head.
 */
struct wait_queue_entry {
	unsigned int flags;	/* always 0 */
	void *private;
	u_int state;
	wait_queue_func_t *func;
	struct list_head entry;
};

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

/*
 * This function is referenced by at least one DRM driver, so it may not be
 * renamed and furthermore must be the default wait queue callback.
 */
extern wait_queue_func_t drmcompat_autoremove_wake_function;

void drmcompat_wake_up(wait_queue_head_t *, unsigned int, int, bool);

int drmcompat_wait_event_common(wait_queue_head_t *, wait_queue_entry_t *, int,
    unsigned int, spinlock_t *);

void drmcompat_prepare_to_wait(wait_queue_head_t *, wait_queue_entry_t *, int);
void drmcompat_finish_wait(wait_queue_head_t *, wait_queue_entry_t *);

void drmcompat_wake_up_task_locked(struct thread *task);

#endif	/* __DRMCOMPAT_WAIT_H__ */
