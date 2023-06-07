/*	$NetBSD$	*/

/*-
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __DRMCOMPAT_LINUX_SEQLOCK_H__
#define	__DRMCOMPAT_LINUX_SEQLOCK_H__

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mutex.h>

#include <machine/atomic.h>

#include <linux/preempt.h>
#include <linux/lockdep.h>

struct seqcount {
	unsigned	sqc_gen;
};

typedef struct seqcount seqcount_t;

static inline void
seqcount_init(struct seqcount *seqcount)
{

	seqcount->sqc_gen = 0;
}

static inline void
seqcount_destroy(struct seqcount *seqcount)
{

	MPASS((seqcount->sqc_gen & 1) == 0);
	seqcount->sqc_gen = -1;
}

static inline void
write_seqcount_begin(struct seqcount *seqcount)
{

	MPASS((seqcount->sqc_gen & 1) == 0);
	seqcount->sqc_gen |= 1;
//	membar_producer();
}

static inline void
write_seqcount_end(struct seqcount *seqcount)
{

	MPASS((seqcount->sqc_gen & 1) == 1);
//	membar_producer();
	seqcount->sqc_gen |= 1;	/* paranoia */
	seqcount->sqc_gen++;
}

static inline unsigned
__read_seqcount_begin(const struct seqcount *seqcount)
{
	unsigned gen;

	while (__predict_false((gen = seqcount->sqc_gen) & 1))
;
//		SPINLOCK_BACKOFF_HOOK;
//	__insn_barrier();

	return gen;
}

static inline bool
__read_seqcount_retry(const struct seqcount *seqcount, unsigned gen)
{

//	__insn_barrier();
	return __predict_false(seqcount->sqc_gen != gen);
}

static inline unsigned
read_seqcount_begin(const struct seqcount *seqcount)
{
	unsigned gen;

	gen = __read_seqcount_begin(seqcount);
//	membar_consumer();

	return gen;
}

static inline bool
read_seqcount_retry(const struct seqcount *seqcount, unsigned gen)
{

//	membar_consumer();
	return __read_seqcount_retry(seqcount, gen);
}

static inline unsigned
raw_read_seqcount(const struct seqcount *seqcount)
{
	unsigned gen;

	gen = seqcount->sqc_gen;
//	membar_consumer();

	return gen;
}

struct seqlock {
	struct mtx		sql_lock;
	struct seqcount		sql_count;
};

typedef struct seqlock seqlock_t;

static inline void
seqlock_init(struct seqlock *seqlock)
{

	mtx_init(&seqlock->sql_lock, "seqlock", NULL, MTX_DEF);
//	seqcount_init(&seqlock->sql_count);
}

static inline void
seqlock_destroy(struct seqlock *seqlock)
{

	seqcount_destroy(&seqlock->sql_count);
	mtx_destroy(&seqlock->sql_lock);
}

static inline void
write_seqlock(struct seqlock *seqlock)
{

	mtx_lock(&seqlock->sql_lock);
	write_seqcount_begin(&seqlock->sql_count);
}

static inline void
write_sequnlock(struct seqlock *seqlock)
{

	write_seqcount_end(&seqlock->sql_count);
	mtx_unlock(&seqlock->sql_lock);
}

#define	write_seqlock_irqsave(SEQLOCK, FLAGS)	do {			      \
	critical_enter();				      \
	write_seqlock(SEQLOCK);						      \
} while (0)

#define	write_sequnlock_irqrestore(SEQLOCK, FLAGS)	do {		      \
	write_sequnlock(SEQLOCK);					      \
	critical_exit());						      \
} while (0)

static inline unsigned
read_seqbegin(const struct seqlock *seqlock)
{

	return read_seqcount_begin(&seqlock->sql_count);
}

static inline bool
read_seqretry(const struct seqlock *seqlock, unsigned gen)
{

	return read_seqcount_retry(&seqlock->sql_count, gen);
}

#endif	/* __DRMCOMPAT_LINUX_SEQLOCK_H__ */
