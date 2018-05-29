/*-
 * Copyright (c) 1998 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from BSDI $Id: mutex_witness.c,v 1.1.2.20 2000/04/27 03:10:27 cp Exp $
 *	and BSDI $Id: synch_machdep.c,v 2.3.2.39 2000/04/27 03:10:25 cp Exp $
 */

/*
 * Machine independent bits of mutex implementation.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_adaptive_mutexes.h"
#include "opt_ddb.h"
#include "opt_hwpmc_hooks.h"
#include "opt_sched.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/turnstile.h>
#include <sys/vmmeter.h>
#include <sys/lock_profile.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/cpu.h>

#include <ddb/ddb.h>

#include <fs/devfs/devfs_int.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>

#if defined(SMP) && !defined(NO_ADAPTIVE_MUTEXES)
#define	ADAPTIVE_MUTEXES
#endif

#ifdef HWPMC_HOOKS
#include <sys/pmckern.h>
PMC_SOFT_DEFINE( , , lock, failed);
#endif

/*
 * Return the mutex address when the lock cookie address is provided.
 * This functionality assumes that struct mtx* have a member named mtx_lock.
 */
#define	mtxlock2mtx(c)	(__containerof(c, struct mtx, mtx_lock))

/*
 * Internal utility macros.
 */
#define mtx_unowned(m)	((m)->mtx_lock == MTX_UNOWNED)

#define	mtx_destroyed(m) ((m)->mtx_lock == MTX_DESTROYED)

static void	assert_mtx(const struct lock_object *lock, int what);
#ifdef DDB
static void	db_show_mtx(const struct lock_object *lock);
#endif
static void	lock_mtx(struct lock_object *lock, uintptr_t how);
static void	lock_spin(struct lock_object *lock, uintptr_t how);
#ifdef KDTRACE_HOOKS
static int	owner_mtx(const struct lock_object *lock,
		    struct thread **owner);
#endif
static uintptr_t unlock_mtx(struct lock_object *lock);
static uintptr_t unlock_spin(struct lock_object *lock);

/*
 * Lock classes for sleep and spin mutexes.
 */
struct lock_class lock_class_mtx_sleep = {
	.lc_name = "sleep mutex",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE,
	.lc_assert = assert_mtx,
#ifdef DDB
	.lc_ddb_show = db_show_mtx,
#endif
	.lc_lock = lock_mtx,
	.lc_unlock = unlock_mtx,
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_mtx,
#endif
};
struct lock_class lock_class_mtx_spin = {
	.lc_name = "spin mutex",
	.lc_flags = LC_SPINLOCK | LC_RECURSABLE,
	.lc_assert = assert_mtx,
#ifdef DDB
	.lc_ddb_show = db_show_mtx,
#endif
	.lc_lock = lock_spin,
	.lc_unlock = unlock_spin,
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_mtx,
#endif
};

#ifdef ADAPTIVE_MUTEXES
static SYSCTL_NODE(_debug, OID_AUTO, mtx, CTLFLAG_RD, NULL, "mtx debugging");

static struct lock_delay_config __read_mostly mtx_delay;

SYSCTL_INT(_debug_mtx, OID_AUTO, delay_base, CTLFLAG_RW, &mtx_delay.base,
    0, "");
SYSCTL_INT(_debug_mtx, OID_AUTO, delay_max, CTLFLAG_RW, &mtx_delay.max,
    0, "");

LOCK_DELAY_SYSINIT_DEFAULT(mtx_delay);
#endif

static SYSCTL_NODE(_debug, OID_AUTO, mtx_spin, CTLFLAG_RD, NULL,
    "mtx spin debugging");

static struct lock_delay_config __read_mostly mtx_spin_delay;

SYSCTL_INT(_debug_mtx_spin, OID_AUTO, delay_base, CTLFLAG_RW,
    &mtx_spin_delay.base, 0, "");
SYSCTL_INT(_debug_mtx_spin, OID_AUTO, delay_max, CTLFLAG_RW,
    &mtx_spin_delay.max, 0, "");

LOCK_DELAY_SYSINIT_DEFAULT(mtx_spin_delay);

/*
 * System-wide mutexes
 */
struct mtx blocked_lock;
struct mtx Giant;

void
assert_mtx(const struct lock_object *lock, int what)
{

	mtx_assert((const struct mtx *)lock, what);
}

void
lock_mtx(struct lock_object *lock, uintptr_t how)
{

	mtx_lock((struct mtx *)lock);
}

void
lock_spin(struct lock_object *lock, uintptr_t how)
{

	panic("spin locks can only use msleep_spin");
}

uintptr_t
unlock_mtx(struct lock_object *lock)
{
	struct mtx *m;

	m = (struct mtx *)lock;
	mtx_assert(m, MA_OWNED | MA_NOTRECURSED);
	mtx_unlock(m);
	return (0);
}

uintptr_t
unlock_spin(struct lock_object *lock)
{

	panic("spin locks can only use msleep_spin");
}

#ifdef KDTRACE_HOOKS
int
owner_mtx(const struct lock_object *lock, struct thread **owner)
{
	const struct mtx *m;
	uintptr_t x;

	m = (const struct mtx *)lock;
	x = m->mtx_lock;
	*owner = (struct thread *)(x & ~MTX_FLAGMASK);
	return (x != MTX_UNOWNED);
}
#endif

/*
 * Function versions of the inlined __mtx_* macros.  These are used by
 * modules and can also be called from assembly language if needed.
 */
void
__mtx_lock_flags(volatile uintptr_t *c, int opts, const char *file, int line)
{
	struct mtx *m;
	uintptr_t tid, v;

	m = mtxlock2mtx(c);

	KASSERT(kdb_active != 0 || SCHEDULER_STOPPED() ||
	    !TD_IS_IDLETHREAD(curthread),
	    ("mtx_lock() by idle thread %p on sleep mutex %s @ %s:%d",
	    curthread, m->lock_object.lo_name, file, line));
	KASSERT(m->mtx_lock != MTX_DESTROYED,
	    ("mtx_lock() of destroyed mutex @ %s:%d", file, line));
	KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_sleep,
	    ("mtx_lock() of spin mutex %s @ %s:%d", m->lock_object.lo_name,
	    file, line));
	WITNESS_CHECKORDER(&m->lock_object, (opts & ~MTX_RECURSE) |
	    LOP_NEWORDER | LOP_EXCLUSIVE, file, line, NULL);

	tid = (uintptr_t)curthread;
	v = MTX_UNOWNED;
	if (!_mtx_obtain_lock_fetch(m, &v, tid))
		_mtx_lock_sleep(m, v, tid, opts, file, line);
	else
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(adaptive__acquire,
		    m, 0, 0, file, line);
	LOCK_LOG_LOCK("LOCK", &m->lock_object, opts, m->mtx_recurse, file,
	    line);
	WITNESS_LOCK(&m->lock_object, (opts & ~MTX_RECURSE) | LOP_EXCLUSIVE,
	    file, line);
	TD_LOCKS_INC(curthread);
}

void
__mtx_unlock_flags(volatile uintptr_t *c, int opts, const char *file, int line)
{
	struct mtx *m;

	m = mtxlock2mtx(c);

	KASSERT(m->mtx_lock != MTX_DESTROYED,
	    ("mtx_unlock() of destroyed mutex @ %s:%d", file, line));
	KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_sleep,
	    ("mtx_unlock() of spin mutex %s @ %s:%d", m->lock_object.lo_name,
	    file, line));
	WITNESS_UNLOCK(&m->lock_object, opts | LOP_EXCLUSIVE, file, line);
	LOCK_LOG_LOCK("UNLOCK", &m->lock_object, opts, m->mtx_recurse, file,
	    line);
	mtx_assert(m, MA_OWNED);

#ifdef LOCK_PROFILING
	__mtx_unlock_sleep(c, opts, file, line);
#else
	__mtx_unlock(m, curthread, opts, file, line);
#endif
	TD_LOCKS_DEC(curthread);
}

void
__mtx_lock_spin_flags(volatile uintptr_t *c, int opts, const char *file,
    int line)
{
	struct mtx *m;

	if (SCHEDULER_STOPPED())
		return;

	m = mtxlock2mtx(c);

	KASSERT(m->mtx_lock != MTX_DESTROYED,
	    ("mtx_lock_spin() of destroyed mutex @ %s:%d", file, line));
	KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_spin,
	    ("mtx_lock_spin() of sleep mutex %s @ %s:%d",
	    m->lock_object.lo_name, file, line));
	if (mtx_owned(m))
		KASSERT((m->lock_object.lo_flags & LO_RECURSABLE) != 0 ||
		    (opts & MTX_RECURSE) != 0,
	    ("mtx_lock_spin: recursed on non-recursive mutex %s @ %s:%d\n",
		    m->lock_object.lo_name, file, line));
	opts &= ~MTX_RECURSE;
	WITNESS_CHECKORDER(&m->lock_object, opts | LOP_NEWORDER | LOP_EXCLUSIVE,
	    file, line, NULL);
	__mtx_lock_spin(m, curthread, opts, file, line);
	LOCK_LOG_LOCK("LOCK", &m->lock_object, opts, m->mtx_recurse, file,
	    line);
	WITNESS_LOCK(&m->lock_object, opts | LOP_EXCLUSIVE, file, line);
}

int
__mtx_trylock_spin_flags(volatile uintptr_t *c, int opts, const char *file,
    int line)
{
	struct mtx *m;

	if (SCHEDULER_STOPPED())
		return (1);

	m = mtxlock2mtx(c);

	KASSERT(m->mtx_lock != MTX_DESTROYED,
	    ("mtx_trylock_spin() of destroyed mutex @ %s:%d", file, line));
	KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_spin,
	    ("mtx_trylock_spin() of sleep mutex %s @ %s:%d",
	    m->lock_object.lo_name, file, line));
	KASSERT((opts & MTX_RECURSE) == 0,
	    ("mtx_trylock_spin: unsupp. opt MTX_RECURSE on mutex %s @ %s:%d\n",
	    m->lock_object.lo_name, file, line));
	if (__mtx_trylock_spin(m, curthread, opts, file, line)) {
		LOCK_LOG_TRY("LOCK", &m->lock_object, opts, 1, file, line);
		WITNESS_LOCK(&m->lock_object, opts | LOP_EXCLUSIVE, file, line);
		return (1);
	}
	LOCK_LOG_TRY("LOCK", &m->lock_object, opts, 0, file, line);
	return (0);
}

void
__mtx_unlock_spin_flags(volatile uintptr_t *c, int opts, const char *file,
    int line)
{
	struct mtx *m;

	if (SCHEDULER_STOPPED())
		return;

	m = mtxlock2mtx(c);

	KASSERT(m->mtx_lock != MTX_DESTROYED,
	    ("mtx_unlock_spin() of destroyed mutex @ %s:%d", file, line));
	KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_spin,
	    ("mtx_unlock_spin() of sleep mutex %s @ %s:%d",
	    m->lock_object.lo_name, file, line));
	WITNESS_UNLOCK(&m->lock_object, opts | LOP_EXCLUSIVE, file, line);
	LOCK_LOG_LOCK("UNLOCK", &m->lock_object, opts, m->mtx_recurse, file,
	    line);
	mtx_assert(m, MA_OWNED);

	__mtx_unlock_spin(m);
}

/*
 * The important part of mtx_trylock{,_flags}()
 * Tries to acquire lock `m.'  If this function is called on a mutex that
 * is already owned, it will recursively acquire the lock.
 */
int
_mtx_trylock_flags_(volatile uintptr_t *c, int opts, const char *file, int line)
{
	struct mtx *m;
	struct thread *td;
	uintptr_t tid, v;
#ifdef LOCK_PROFILING
	uint64_t waittime = 0;
	int contested = 0;
#endif
	int rval;
	bool recursed;

	td = curthread;
	tid = (uintptr_t)td;
	if (SCHEDULER_STOPPED_TD(td))
		return (1);

	m = mtxlock2mtx(c);

	KASSERT(kdb_active != 0 || !TD_IS_IDLETHREAD(td),
	    ("mtx_trylock() by idle thread %p on sleep mutex %s @ %s:%d",
	    curthread, m->lock_object.lo_name, file, line));
	KASSERT(m->mtx_lock != MTX_DESTROYED,
	    ("mtx_trylock() of destroyed mutex @ %s:%d", file, line));
	KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_sleep,
	    ("mtx_trylock() of spin mutex %s @ %s:%d", m->lock_object.lo_name,
	    file, line));

	rval = 1;
	recursed = false;
	v = MTX_UNOWNED;
	for (;;) {
		if (_mtx_obtain_lock_fetch(m, &v, tid))
			break;
		if (v == MTX_UNOWNED)
			continue;
		if (v == tid &&
		    ((m->lock_object.lo_flags & LO_RECURSABLE) != 0 ||
		    (opts & MTX_RECURSE) != 0)) {
			m->mtx_recurse++;
			atomic_set_ptr(&m->mtx_lock, MTX_RECURSED);
			recursed = true;
			break;
		}
		rval = 0;
		break;
	}

	opts &= ~MTX_RECURSE;

	LOCK_LOG_TRY("LOCK", &m->lock_object, opts, rval, file, line);
	if (rval) {
		WITNESS_LOCK(&m->lock_object, opts | LOP_EXCLUSIVE | LOP_TRYLOCK,
		    file, line);
		TD_LOCKS_INC(curthread);
		if (!recursed)
			LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(adaptive__acquire,
			    m, contested, waittime, file, line);
	}

	return (rval);
}

/*
 * __mtx_lock_sleep: the tougher part of acquiring an MTX_DEF lock.
 *
 * We call this if the lock is either contested (i.e. we need to go to
 * sleep waiting for it), or if we need to recurse on it.
 */
#if LOCK_DEBUG > 0
void
__mtx_lock_sleep(volatile uintptr_t *c, uintptr_t v, uintptr_t tid, int opts,
    const char *file, int line)
#else
void
__mtx_lock_sleep(volatile uintptr_t *c, uintptr_t v, uintptr_t tid)
#endif
{
	struct mtx *m;
	struct turnstile *ts;
#ifdef ADAPTIVE_MUTEXES
	volatile struct thread *owner;
#endif
#ifdef KTR
	int cont_logged = 0;
#endif
#ifdef LOCK_PROFILING
	int contested = 0;
	uint64_t waittime = 0;
#endif
#if defined(ADAPTIVE_MUTEXES) || defined(KDTRACE_HOOKS)
	struct lock_delay_arg lda;
#endif
#ifdef KDTRACE_HOOKS
	u_int sleep_cnt = 0;
	int64_t sleep_time = 0;
	int64_t all_time = 0;
#endif
#if defined(KDTRACE_HOOKS) || defined(LOCK_PROFILING)
	int doing_lockprof;
#endif

	if (SCHEDULER_STOPPED())
		return;

#if defined(ADAPTIVE_MUTEXES)
	lock_delay_arg_init(&lda, &mtx_delay);
#elif defined(KDTRACE_HOOKS)
	lock_delay_arg_init(&lda, NULL);
#endif
	m = mtxlock2mtx(c);
	if (__predict_false(v == MTX_UNOWNED))
		v = MTX_READ_VALUE(m);

	if (__predict_false(lv_mtx_owner(v) == (struct thread *)tid)) {
		KASSERT((m->lock_object.lo_flags & LO_RECURSABLE) != 0 ||
		    (opts & MTX_RECURSE) != 0,
	    ("_mtx_lock_sleep: recursed on non-recursive mutex %s @ %s:%d\n",
		    m->lock_object.lo_name, file, line));
#if LOCK_DEBUG > 0
		opts &= ~MTX_RECURSE;
#endif
		m->mtx_recurse++;
		atomic_set_ptr(&m->mtx_lock, MTX_RECURSED);
		if (LOCK_LOG_TEST(&m->lock_object, opts))
			CTR1(KTR_LOCK, "_mtx_lock_sleep: %p recursing", m);
		return;
	}
#if LOCK_DEBUG > 0
	opts &= ~MTX_RECURSE;
#endif

#ifdef HWPMC_HOOKS
	PMC_SOFT_CALL( , , lock, failed);
#endif
	lock_profile_obtain_lock_failed(&m->lock_object,
		    &contested, &waittime);
	if (LOCK_LOG_TEST(&m->lock_object, opts))
		CTR4(KTR_LOCK,
		    "_mtx_lock_sleep: %s contested (lock=%p) at %s:%d",
		    m->lock_object.lo_name, (void *)m->mtx_lock, file, line);
#ifdef LOCK_PROFILING
	doing_lockprof = 1;
#elif defined(KDTRACE_HOOKS)
	doing_lockprof = lockstat_enabled;
	if (__predict_false(doing_lockprof))
		all_time -= lockstat_nsecs(&m->lock_object);
#endif

	for (;;) {
		if (v == MTX_UNOWNED) {
			if (_mtx_obtain_lock_fetch(m, &v, tid))
				break;
			continue;
		}
#ifdef KDTRACE_HOOKS
		lda.spin_cnt++;
#endif
#ifdef ADAPTIVE_MUTEXES
		/*
		 * If the owner is running on another CPU, spin until the
		 * owner stops running or the state of the lock changes.
		 */
		owner = lv_mtx_owner(v);
		if (TD_IS_RUNNING(owner)) {
			if (LOCK_LOG_TEST(&m->lock_object, 0))
				CTR3(KTR_LOCK,
				    "%s: spinning on %p held by %p",
				    __func__, m, owner);
			KTR_STATE1(KTR_SCHED, "thread",
			    sched_tdname((struct thread *)tid),
			    "spinning", "lockname:\"%s\"",
			    m->lock_object.lo_name);
			do {
				lock_delay(&lda);
				v = MTX_READ_VALUE(m);
				owner = lv_mtx_owner(v);
			} while (v != MTX_UNOWNED && TD_IS_RUNNING(owner));
			KTR_STATE0(KTR_SCHED, "thread",
			    sched_tdname((struct thread *)tid),
			    "running");
			continue;
		}
#endif

		ts = turnstile_trywait(&m->lock_object);
		v = MTX_READ_VALUE(m);

		/*
		 * Check if the lock has been released while spinning for
		 * the turnstile chain lock.
		 */
		if (v == MTX_UNOWNED) {
			turnstile_cancel(ts);
			continue;
		}

#ifdef ADAPTIVE_MUTEXES
		/*
		 * The current lock owner might have started executing
		 * on another CPU (or the lock could have changed
		 * owners) while we were waiting on the turnstile
		 * chain lock.  If so, drop the turnstile lock and try
		 * again.
		 */
		owner = lv_mtx_owner(v);
		if (TD_IS_RUNNING(owner)) {
			turnstile_cancel(ts);
			continue;
		}
#endif

		/*
		 * If the mutex isn't already contested and a failure occurs
		 * setting the contested bit, the mutex was either released
		 * or the state of the MTX_RECURSED bit changed.
		 */
		if ((v & MTX_CONTESTED) == 0 &&
		    !atomic_cmpset_ptr(&m->mtx_lock, v, v | MTX_CONTESTED)) {
			turnstile_cancel(ts);
			v = MTX_READ_VALUE(m);
			continue;
		}

		/*
		 * We definitely must sleep for this lock.
		 */
		mtx_assert(m, MA_NOTOWNED);

#ifdef KTR
		if (!cont_logged) {
			CTR6(KTR_CONTENTION,
			    "contention: %p at %s:%d wants %s, taken by %s:%d",
			    (void *)tid, file, line, m->lock_object.lo_name,
			    WITNESS_FILE(&m->lock_object),
			    WITNESS_LINE(&m->lock_object));
			cont_logged = 1;
		}
#endif

		/*
		 * Block on the turnstile.
		 */
#ifdef KDTRACE_HOOKS
		sleep_time -= lockstat_nsecs(&m->lock_object);
#endif
		turnstile_wait(ts, mtx_owner(m), TS_EXCLUSIVE_QUEUE);
#ifdef KDTRACE_HOOKS
		sleep_time += lockstat_nsecs(&m->lock_object);
		sleep_cnt++;
#endif
		v = MTX_READ_VALUE(m);
	}
#ifdef KTR
	if (cont_logged) {
		CTR4(KTR_CONTENTION,
		    "contention end: %s acquired by %p at %s:%d",
		    m->lock_object.lo_name, (void *)tid, file, line);
	}
#endif
#if defined(KDTRACE_HOOKS) || defined(LOCK_PROFILING)
	if (__predict_true(!doing_lockprof))
		return;
#endif
#ifdef KDTRACE_HOOKS
	all_time += lockstat_nsecs(&m->lock_object);
#endif
	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(adaptive__acquire, m, contested,
	    waittime, file, line);
#ifdef KDTRACE_HOOKS
	if (sleep_time)
		LOCKSTAT_RECORD1(adaptive__block, m, sleep_time);

	/*
	 * Only record the loops spinning and not sleeping.
	 */
	if (lda.spin_cnt > sleep_cnt)
		LOCKSTAT_RECORD1(adaptive__spin, m, all_time - sleep_time);
#endif
}

static void
_mtx_lock_spin_failed(struct mtx *m)
{
	struct thread *td;

	td = mtx_owner(m);

	/* If the mutex is unlocked, try again. */
	if (td == NULL)
		return;

	printf( "spin lock %p (%s) held by %p (tid %d) too long\n",
	    m, m->lock_object.lo_name, td, td->td_tid);
#ifdef WITNESS
	witness_display_spinlock(&m->lock_object, td, printf);
#endif
	panic("spin lock held too long");
}

#ifdef SMP
/*
 * _mtx_lock_spin_cookie: the tougher part of acquiring an MTX_SPIN lock.
 *
 * This is only called if we need to actually spin for the lock. Recursion
 * is handled inline.
 */
void
_mtx_lock_spin_cookie(volatile uintptr_t *c, uintptr_t v, uintptr_t tid,
    int opts, const char *file, int line)
{
	struct mtx *m;
	struct lock_delay_arg lda;
#ifdef LOCK_PROFILING
	int contested = 0;
	uint64_t waittime = 0;
#endif
#ifdef KDTRACE_HOOKS
	int64_t spin_time = 0;
#endif
#if defined(KDTRACE_HOOKS) || defined(LOCK_PROFILING)
	int doing_lockprof;
#endif

	if (SCHEDULER_STOPPED())
		return;

	lock_delay_arg_init(&lda, &mtx_spin_delay);
	m = mtxlock2mtx(c);

	if (__predict_false(v == MTX_UNOWNED))
		v = MTX_READ_VALUE(m);

	if (__predict_false(v == tid)) {
		m->mtx_recurse++;
		return;
	}

	if (LOCK_LOG_TEST(&m->lock_object, opts))
		CTR1(KTR_LOCK, "_mtx_lock_spin: %p spinning", m);
	KTR_STATE1(KTR_SCHED, "thread", sched_tdname((struct thread *)tid),
	    "spinning", "lockname:\"%s\"", m->lock_object.lo_name);

#ifdef HWPMC_HOOKS
	PMC_SOFT_CALL( , , lock, failed);
#endif
	lock_profile_obtain_lock_failed(&m->lock_object, &contested, &waittime);
#ifdef LOCK_PROFILING
	doing_lockprof = 1;
#elif defined(KDTRACE_HOOKS)
	doing_lockprof = lockstat_enabled;
	if (__predict_false(doing_lockprof))
		spin_time -= lockstat_nsecs(&m->lock_object);
#endif
	for (;;) {
		if (v == MTX_UNOWNED) {
			if (_mtx_obtain_lock_fetch(m, &v, tid))
				break;
			continue;
		}
		/* Give interrupts a chance while we spin. */
		spinlock_exit();
		do {
			if (lda.spin_cnt < 10000000) {
				lock_delay(&lda);
			} else {
				lda.spin_cnt++;
				if (lda.spin_cnt < 60000000 || kdb_active ||
				    panicstr != NULL)
					DELAY(1);
				else
					_mtx_lock_spin_failed(m);
				cpu_spinwait();
			}
			v = MTX_READ_VALUE(m);
		} while (v != MTX_UNOWNED);
		spinlock_enter();
	}

	if (LOCK_LOG_TEST(&m->lock_object, opts))
		CTR1(KTR_LOCK, "_mtx_lock_spin: %p spin done", m);
	KTR_STATE0(KTR_SCHED, "thread", sched_tdname((struct thread *)tid),
	    "running");

#if defined(KDTRACE_HOOKS) || defined(LOCK_PROFILING)
	if (__predict_true(!doing_lockprof))
		return;
#endif
#ifdef KDTRACE_HOOKS
	spin_time += lockstat_nsecs(&m->lock_object);
#endif
	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(spin__acquire, m,
	    contested, waittime, file, line);
#ifdef KDTRACE_HOOKS
	if (spin_time != 0)
		LOCKSTAT_RECORD1(spin__spin, m, spin_time);
#endif
}
#endif /* SMP */

void
thread_lock_flags_(struct thread *td, int opts, const char *file, int line)
{
	struct mtx *m;
	uintptr_t tid, v;
	struct lock_delay_arg lda;
#ifdef LOCK_PROFILING
	int contested = 0;
	uint64_t waittime = 0;
#endif
#ifdef KDTRACE_HOOKS
	int64_t spin_time = 0;
#endif
#if defined(KDTRACE_HOOKS) || defined(LOCK_PROFILING)
	int doing_lockprof = 1;
#endif

	tid = (uintptr_t)curthread;

	if (SCHEDULER_STOPPED()) {
		/*
		 * Ensure that spinlock sections are balanced even when the
		 * scheduler is stopped, since we may otherwise inadvertently
		 * re-enable interrupts while dumping core.
		 */
		spinlock_enter();
		return;
	}

	lock_delay_arg_init(&lda, &mtx_spin_delay);

#ifdef LOCK_PROFILING
	doing_lockprof = 1;
#elif defined(KDTRACE_HOOKS)
	doing_lockprof = lockstat_enabled;
	if (__predict_false(doing_lockprof))
		spin_time -= lockstat_nsecs(&td->td_lock->lock_object);
#endif
	for (;;) {
retry:
		v = MTX_UNOWNED;
		spinlock_enter();
		m = td->td_lock;
		KASSERT(m->mtx_lock != MTX_DESTROYED,
		    ("thread_lock() of destroyed mutex @ %s:%d", file, line));
		KASSERT(LOCK_CLASS(&m->lock_object) == &lock_class_mtx_spin,
		    ("thread_lock() of sleep mutex %s @ %s:%d",
		    m->lock_object.lo_name, file, line));
		if (mtx_owned(m))
			KASSERT((m->lock_object.lo_flags & LO_RECURSABLE) != 0,
	    ("thread_lock: recursed on non-recursive mutex %s @ %s:%d\n",
			    m->lock_object.lo_name, file, line));
		WITNESS_CHECKORDER(&m->lock_object,
		    opts | LOP_NEWORDER | LOP_EXCLUSIVE, file, line, NULL);
		for (;;) {
			if (_mtx_obtain_lock_fetch(m, &v, tid))
				break;
			if (v == MTX_UNOWNED)
				continue;
			if (v == tid) {
				m->mtx_recurse++;
				break;
			}
#ifdef HWPMC_HOOKS
			PMC_SOFT_CALL( , , lock, failed);
#endif
			lock_profile_obtain_lock_failed(&m->lock_object,
			    &contested, &waittime);
			/* Give interrupts a chance while we spin. */
			spinlock_exit();
			do {
				if (lda.spin_cnt < 10000000) {
					lock_delay(&lda);
				} else {
					lda.spin_cnt++;
					if (lda.spin_cnt < 60000000 ||
					    kdb_active || panicstr != NULL)
						DELAY(1);
					else
						_mtx_lock_spin_failed(m);
					cpu_spinwait();
				}
				if (m != td->td_lock)
					goto retry;
				v = MTX_READ_VALUE(m);
			} while (v != MTX_UNOWNED);
			spinlock_enter();
		}
		if (m == td->td_lock)
			break;
		__mtx_unlock_spin(m);	/* does spinlock_exit() */
	}
	LOCK_LOG_LOCK("LOCK", &m->lock_object, opts, m->mtx_recurse, file,
	    line);
	WITNESS_LOCK(&m->lock_object, opts | LOP_EXCLUSIVE, file, line);

#if defined(KDTRACE_HOOKS) || defined(LOCK_PROFILING)
	if (__predict_true(!doing_lockprof))
		return;
#endif
#ifdef KDTRACE_HOOKS
	spin_time += lockstat_nsecs(&m->lock_object);
#endif
	if (m->mtx_recurse == 0)
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(spin__acquire, m,
		    contested, waittime, file, line);
#ifdef KDTRACE_HOOKS
	if (spin_time != 0)
		LOCKSTAT_RECORD1(thread__spin, m, spin_time);
#endif
}

struct mtx *
thread_lock_block(struct thread *td)
{
	struct mtx *lock;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	lock = td->td_lock;
	td->td_lock = &blocked_lock;
	mtx_unlock_spin(lock);

	return (lock);
}

void
thread_lock_unblock(struct thread *td, struct mtx *new)
{
	mtx_assert(new, MA_OWNED);
	MPASS(td->td_lock == &blocked_lock);
	atomic_store_rel_ptr((volatile void *)&td->td_lock, (uintptr_t)new);
}

void
thread_lock_set(struct thread *td, struct mtx *new)
{
	struct mtx *lock;

	mtx_assert(new, MA_OWNED);
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	lock = td->td_lock;
	td->td_lock = new;
	mtx_unlock_spin(lock);
}

/*
 * __mtx_unlock_sleep: the tougher part of releasing an MTX_DEF lock.
 *
 * We are only called here if the lock is recursed, contested (i.e. we
 * need to wake up a blocked thread) or lockstat probe is active.
 */
#if LOCK_DEBUG > 0
void
__mtx_unlock_sleep(volatile uintptr_t *c, int opts, const char *file, int line)
#else
void
__mtx_unlock_sleep(volatile uintptr_t *c)
#endif
{
	struct mtx *m;
	struct turnstile *ts;
	uintptr_t tid, v;

	if (SCHEDULER_STOPPED())
		return;

	tid = (uintptr_t)curthread;
	m = mtxlock2mtx(c);
	v = MTX_READ_VALUE(m);

	if (v & MTX_RECURSED) {
		if (--(m->mtx_recurse) == 0)
			atomic_clear_ptr(&m->mtx_lock, MTX_RECURSED);
		if (LOCK_LOG_TEST(&m->lock_object, opts))
			CTR1(KTR_LOCK, "_mtx_unlock_sleep: %p unrecurse", m);
		return;
	}

	LOCKSTAT_PROFILE_RELEASE_LOCK(adaptive__release, m);
	if (v == tid && _mtx_release_lock(m, tid))
		return;

	/*
	 * We have to lock the chain before the turnstile so this turnstile
	 * can be removed from the hash list if it is empty.
	 */
	turnstile_chain_lock(&m->lock_object);
	ts = turnstile_lookup(&m->lock_object);
	if (LOCK_LOG_TEST(&m->lock_object, opts))
		CTR1(KTR_LOCK, "_mtx_unlock_sleep: %p contested", m);
	MPASS(ts != NULL);
	turnstile_broadcast(ts, TS_EXCLUSIVE_QUEUE);
	_mtx_release_lock_quick(m);

	/*
	 * This turnstile is now no longer associated with the mutex.  We can
	 * unlock the chain lock so a new turnstile may take it's place.
	 */
	turnstile_unpend(ts, TS_EXCLUSIVE_LOCK);
	turnstile_chain_unlock(&m->lock_object);
}

/*
 * All the unlocking of MTX_SPIN locks is done inline.
 * See the __mtx_unlock_spin() macro for the details.
 */

/*
 * The backing function for the INVARIANTS-enabled mtx_assert()
 */
#ifdef INVARIANT_SUPPORT
void
__mtx_assert(const volatile uintptr_t *c, int what, const char *file, int line)
{
	const struct mtx *m;

	if (panicstr != NULL || dumping || SCHEDULER_STOPPED())
		return;

	m = mtxlock2mtx(c);

	switch (what) {
	case MA_OWNED:
	case MA_OWNED | MA_RECURSED:
	case MA_OWNED | MA_NOTRECURSED:
		if (!mtx_owned(m))
			panic("mutex %s not owned at %s:%d",
			    m->lock_object.lo_name, file, line);
		if (mtx_recursed(m)) {
			if ((what & MA_NOTRECURSED) != 0)
				panic("mutex %s recursed at %s:%d",
				    m->lock_object.lo_name, file, line);
		} else if ((what & MA_RECURSED) != 0) {
			panic("mutex %s unrecursed at %s:%d",
			    m->lock_object.lo_name, file, line);
		}
		break;
	case MA_NOTOWNED:
		if (mtx_owned(m))
			panic("mutex %s owned at %s:%d",
			    m->lock_object.lo_name, file, line);
		break;
	default:
		panic("unknown mtx_assert at %s:%d", file, line);
	}
}
#endif

/*
 * General init routine used by the MTX_SYSINIT() macro.
 */
void
mtx_sysinit(void *arg)
{
	struct mtx_args *margs = arg;

	mtx_init((struct mtx *)margs->ma_mtx, margs->ma_desc, NULL,
	    margs->ma_opts);
}

/*
 * Mutex initialization routine; initialize lock `m' of type contained in
 * `opts' with options contained in `opts' and name `name.'  The optional
 * lock type `type' is used as a general lock category name for use with
 * witness.
 */
void
_mtx_init(volatile uintptr_t *c, const char *name, const char *type, int opts)
{
	struct mtx *m;
	struct lock_class *class;
	int flags;

	m = mtxlock2mtx(c);

	MPASS((opts & ~(MTX_SPIN | MTX_QUIET | MTX_RECURSE |
	    MTX_NOWITNESS | MTX_DUPOK | MTX_NOPROFILE | MTX_NEW)) == 0);
	ASSERT_ATOMIC_LOAD_PTR(m->mtx_lock,
	    ("%s: mtx_lock not aligned for %s: %p", __func__, name,
	    &m->mtx_lock));

	/* Determine lock class and lock flags. */
	if (opts & MTX_SPIN)
		class = &lock_class_mtx_spin;
	else
		class = &lock_class_mtx_sleep;
	flags = 0;
	if (opts & MTX_QUIET)
		flags |= LO_QUIET;
	if (opts & MTX_RECURSE)
		flags |= LO_RECURSABLE;
	if ((opts & MTX_NOWITNESS) == 0)
		flags |= LO_WITNESS;
	if (opts & MTX_DUPOK)
		flags |= LO_DUPOK;
	if (opts & MTX_NOPROFILE)
		flags |= LO_NOPROFILE;
	if (opts & MTX_NEW)
		flags |= LO_NEW;

	/* Initialize mutex. */
	lock_init(&m->lock_object, class, name, type, flags);

	m->mtx_lock = MTX_UNOWNED;
	m->mtx_recurse = 0;
}

/*
 * Remove lock `m' from all_mtx queue.  We don't allow MTX_QUIET to be
 * passed in as a flag here because if the corresponding mtx_init() was
 * called with MTX_QUIET set, then it will already be set in the mutex's
 * flags.
 */
void
_mtx_destroy(volatile uintptr_t *c)
{
	struct mtx *m;

	m = mtxlock2mtx(c);

	if (!mtx_owned(m))
		MPASS(mtx_unowned(m));
	else {
		MPASS((m->mtx_lock & (MTX_RECURSED|MTX_CONTESTED)) == 0);

		/* Perform the non-mtx related part of mtx_unlock_spin(). */
		if (LOCK_CLASS(&m->lock_object) == &lock_class_mtx_spin)
			spinlock_exit();
		else
			TD_LOCKS_DEC(curthread);

		lock_profile_release_lock(&m->lock_object);
		/* Tell witness this isn't locked to make it happy. */
		WITNESS_UNLOCK(&m->lock_object, LOP_EXCLUSIVE, __FILE__,
		    __LINE__);
	}

	m->mtx_lock = MTX_DESTROYED;
	lock_destroy(&m->lock_object);
}

/*
 * Intialize the mutex code and system mutexes.  This is called from the MD
 * startup code prior to mi_startup().  The per-CPU data space needs to be
 * setup before this is called.
 */
void
mutex_init(void)
{

	/* Setup turnstiles so that sleep mutexes work. */
	init_turnstiles();

	/*
	 * Initialize mutexes.
	 */
	mtx_init(&Giant, "Giant", NULL, MTX_DEF | MTX_RECURSE);
	mtx_init(&blocked_lock, "blocked lock", NULL, MTX_SPIN);
	blocked_lock.mtx_lock = 0xdeadc0de;	/* Always blocked. */
	mtx_init(&proc0.p_mtx, "process lock", NULL, MTX_DEF | MTX_DUPOK);
	mtx_init(&proc0.p_slock, "process slock", NULL, MTX_SPIN);
	mtx_init(&proc0.p_statmtx, "pstatl", NULL, MTX_SPIN);
	mtx_init(&proc0.p_itimmtx, "pitiml", NULL, MTX_SPIN);
	mtx_init(&proc0.p_profmtx, "pprofl", NULL, MTX_SPIN);
	mtx_init(&devmtx, "cdev", NULL, MTX_DEF);
	mtx_lock(&Giant);
}

#ifdef DDB
void
db_show_mtx(const struct lock_object *lock)
{
	struct thread *td;
	const struct mtx *m;

	m = (const struct mtx *)lock;

	db_printf(" flags: {");
	if (LOCK_CLASS(lock) == &lock_class_mtx_spin)
		db_printf("SPIN");
	else
		db_printf("DEF");
	if (m->lock_object.lo_flags & LO_RECURSABLE)
		db_printf(", RECURSE");
	if (m->lock_object.lo_flags & LO_DUPOK)
		db_printf(", DUPOK");
	db_printf("}\n");
	db_printf(" state: {");
	if (mtx_unowned(m))
		db_printf("UNOWNED");
	else if (mtx_destroyed(m))
		db_printf("DESTROYED");
	else {
		db_printf("OWNED");
		if (m->mtx_lock & MTX_CONTESTED)
			db_printf(", CONTESTED");
		if (m->mtx_lock & MTX_RECURSED)
			db_printf(", RECURSED");
	}
	db_printf("}\n");
	if (!mtx_unowned(m) && !mtx_destroyed(m)) {
		td = mtx_owner(m);
		db_printf(" owner: %p (tid %d, pid %d, \"%s\")\n", td,
		    td->td_tid, td->td_proc->p_pid, td->td_name);
		if (mtx_recursed(m))
			db_printf(" recursed: %d\n", m->mtx_recurse);
	}
}
#endif
