/*-
 * Copyright (c) 2025 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sbuf.h>

#include <machine/stdarg.h>

#include <vm/uma.h>

#include "ace2_syncpoint.h"
#include "ace2_syncpoint_internal.h"

static uma_zone_t	ace2_syncpoint_completion_zone;

/*
 * Global list of waiting completions, protected by a mutex.  This list exists
 * solely for monitoring purposes, and cannot be used to acquire a reference
 * outside of holding that mutex.  The global mutex is a leaf lock.
 */
static struct mtx	ace2_syncpoint_mtx;
static TAILQ_HEAD(, ace2_syncpoint_completion) ace2_syncpoint_completion_head;

static void	ace2_syncpoint_destroydev_cb(void *context);

void
ace2_syncpoint_module_load(void)
{

	mtx_init(&ace2_syncpoint_mtx, "asc2_syncpoint_mtx", NULL, MTX_DEF);
	TAILQ_INIT(&ace2_syncpoint_completion_head);
	ace2_syncpoint_completion_zone =
	    uma_zcreate("ACE2 syncpoint completions",
	    sizeof(struct ace2_syncpoint_completion), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
}

int
ace2_syncpoint_module_unload(void)
{

	/*
	 * XXXRW: This is not right, and we allow unload only for debugging
	 * reasons as currently implemented.  To do this properly we need to
	 * do some sort of destroy/drain thing on devices, etc.  In practice,
	 * once this code is stable, we will likely instead want to simply
	 * forbid unload.
	 */
	if (ace2_syncpoint_count)
		return (EBUSY);
	if (!TAILQ_EMPTY(&ace2_syncpoint_completion_head))
		panic("%s: !TAILQ_EMPTY", __func__);
	uma_zdestroy(ace2_syncpoint_completion_zone);
	mtx_destroy(&ace2_syncpoint_mtx);
	return (0);
}

static uint64_t
ace2_syncpoint_id_allocate(void)
{
	uint64_t v;

	/*
	 * This replicates SIFT's semantics for ID space exhaustion.
 	 */
	v = atomic_fetchadd_64(&ace2_syncpoint_nextid, 1);
	if (v == UINT64_MAX)
		panic("%s", __func__);
	return (v);
}

uint64_t
__ace2_syncpoint(const char *label, const char *caller_file,
    int caller_line, const char *caller_func, const char *fmt, ...)
{
	va_list ap;
	struct ace2_syncpoint_completion *ascp;
	uint64_t id;
	int error;

	if (!ace2_syncpoint_enabled)
		return (0);

	/* Allocate and initialize continuation state. */
	atomic_add_64(&ace2_syncpoint_count, 1);
	ascp = uma_zalloc(ace2_syncpoint_completion_zone, M_WAITOK | M_ZERO);
	mtx_init(&ascp->asc_mtx, "asc_mtx", NULL, MTX_DEF);
	cv_init(&ascp->asc_cv_written, "asc_cv_written");
	cv_init(&ascp->asc_cv_continued, "asc_cv_continued");
	id = ascp->asc_id = ace2_syncpoint_id_allocate();

	/*
	 * Assume that as the caller will be blocked for the duration of the
	 * lifetime of the completion, that the constant string pointers
	 * passed in will remain valid without further synchronisation.
	 */
	ascp->asc_label = label;
	ascp->asc_file = caller_file;
	ascp->asc_line = caller_line;
	ascp->asc_func = caller_func;

	/*
	 * Capure various bits of debugging information.
	 *
	 * XXXRW: Could add optional kernel stack trace?
	 */
	ascp->asc_pid = curthread->td_proc->p_pid;
	ascp->asc_tid = curthread->td_tid;
	bcopy(curthread->td_proc->p_comm, ascp->asc_pcomm,
	    sizeof(ascp->asc_pcomm));

	/*
	 * Hook up to global list for monitoring.  Note that monitoring APIs
	 * cannot rely on any initialization after this point being complete.
	 */ 
	mtx_lock(&ace2_syncpoint_mtx);
	TAILQ_INSERT_HEAD(&ace2_syncpoint_completion_head, ascp, asc_entry);
	mtx_unlock(&ace2_syncpoint_mtx);

	/*
	 * Print out the caller's log message.
	 *
	 * XXXRW: Check against the required format.  Probably we should be
	 * printing out the ID, etc., as, well.
	 */
	/*
	 * XXX: Not quite right on format string handling.
	 */
	pr_sift("ACE2_SYNC_BARRIER %s:%ju %s:%d:%s: %p\n", ascp->asc_label,
	    ascp->asc_id, ascp->asc_file, ascp->asc_line, ascp->asc_func,
	    &ap);
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);

	/*
	 * Create the device node synchronously before printing out a message
	 * that could cause userlevel to access the node.  This means checking
	 * for a write between the return of make_dev() and waiting on the
	 * conditional variable is especially important, as we don't want to
	 * have a race in which we miss the write here because it happened
	 * before acquiring the mutex below.
	 */
	error = ace2_syncpoint_makedev(ascp);
	if (error)
		panic("%s: makedev failed (%d)", __func__, error);

	/*
	 * Wait for observation and then notify completion; once we release
	 * the mutex after signaling completion, ascp becomes unusable.
	 */
	mtx_lock(&ascp->asc_mtx);
	while ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_WRITTEN) == 0)
		cv_wait(&ascp->asc_cv_written, &ascp->asc_mtx);
	ascp->asc_flags |= ACE2_SYNCPOINT_FLAG_CONTINUED;
	cv_signal(&ascp->asc_cv_continued);
	pr_sift("ACE2_SYNC_PASSED %s:%ju %s:%d:%s\n", ascp->asc_label,
	    ascp->asc_id, ascp->asc_file, ascp->asc_line, ascp->asc_func);
	mtx_unlock(&ascp->asc_mtx);
	return (id);
}

void
__ace2_observe(uint64_t seq_id, const char *label, const char *caller_file,
    int caller_line, const char *caller_func, const char *fmt, ...)
{
	va_list ap;

	/*
	 * XXX: Not quite right on format string handling.
	 */
	pr_sift("ACE2_OBSERVE %s:%ju %s:%d:%s: %p\n", label, seq_id,
	    caller_file, caller_line, caller_func, &ap);
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);
}

void
ace2_syncpoint_open(struct ace2_syncpoint_completion *ascp)
{

	pr_sift("ACE2_SYNC_OPEN %s:%ju\n", ascp->asc_label, ascp->asc_id);
}

void
ace2_syncpoint_write(struct ace2_syncpoint_completion *ascp)
{

	mtx_lock(&ascp->asc_mtx);

	/* Another write has already happened; suppress redundant signal. */
	if ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_WRITTEN) != 0) {
		mtx_unlock(&ascp->asc_mtx);
		pr_sift("ACE2_SYNC_WRITE_ALREADY_COMPLETE %s:%ju\n",
		    ascp->asc_label, ascp->asc_id);
		return;
	}

	pr_sift("ACE2_SYNC_WRITE_COMPLETE %s:%ju\n", ascp->asc_label,
	    ascp->asc_id);

	/*
	 * Wake up the blocked thread.
	 */
	ascp->asc_flags |= ACE2_SYNCPOINT_FLAG_WRITTEN;
	cv_signal(&ascp->asc_cv_written);

	/*
	 * Wait for the blocked thread to wake up.
	 */
	while ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_CONTINUED) == 0)
		cv_wait(&ascp->asc_cv_continued, &ascp->asc_mtx);
	mtx_unlock(&ascp->asc_mtx);

	/*
	 * XXXRW: In the SIFT code, the procfs direntry is scheduled for
	 * teardown here.  We currently do that in last close.
	 */

	pr_sift("ACE2_SYNC_WRITE_COMPLETE_OK %s:%ju\n", ascp->asc_label,
	    ascp->asc_id);
}

/*
 * Track reads on the syncpoint for debugging reasons only.
 */
void
ace2_syncpoint_read(struct ace2_syncpoint_completion *ascp)
{

	mtx_lock(&ascp->asc_mtx);
	ascp->asc_flags |= ACE2_SYNCPOINT_FLAG_READ;
	mtx_unlock(&ascp->asc_mtx);
}

/*
 * A portion of syncpoint device teardown is necessarily asynchronous, as we
 * cannot call destroy_dev() from within the "last close" of a device -- i.e.,
 * the close() after the userlevel process acknowledges the completion.
 */
static void
ace2_syncpoint_destroydev_cb(void *context)
{
	struct ace2_syncpoint_completion *ascp = context;

	/*
	 * It is a critical invariant that a syncpoint has been both written
	 * and the thread has continued before we tear down the syncpoint
	 * state, or the waiting thread might perform a use-after-free.  Check
	 * these invariants with prejudice.
	 */
	if ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_WRITTEN) == 0)
		panic("%s: !ACE2_SYNCPOINT_FLAG_WRITTEN", __func__);
	if ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_CONTINUED) == 0)
		panic("%s: !ACE2_SYNCPOINT_FLAG_CONTINUED", __func__);

	/*
	 * Remove from the global list.
	 */
	mtx_lock(&ace2_syncpoint_mtx);
	TAILQ_REMOVE(&ace2_syncpoint_completion_head, ascp, asc_entry);
	mtx_unlock(&ace2_syncpoint_mtx);

	/*
	 * Tear down last of state.
	 */
	cv_destroy(&ascp->asc_cv_written);
	cv_destroy(&ascp->asc_cv_continued);
	mtx_destroy(&ascp->asc_mtx);
#ifdef INVARIANTS
	bzero(&ascp, sizeof(ascp));
#endif
	uma_zfree(ace2_syncpoint_completion_zone, ascp);
	atomic_subtract_64(&ace2_syncpoint_count, 1);
}

/*
 * Function called on last close of a special device, whether before or after
 * acknowledgement.
 */
void
ace2_syncpoint_close(struct ace2_syncpoint_completion *ascp)
{

	/*
	 * If not yet written, either by this caller or another, then the
	 * device is left in place awaiting a future writer.
	 */
	mtx_lock(&ascp->asc_mtx);
	pr_sift("ACE2_SYNC_CLOSE %s:%ju\n", ascp->asc_label, ascp->asc_id);
	if ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_WRITTEN) == 0) {
		mtx_unlock(&ascp->asc_mtx);
		return;
	}
	pr_sift("ACE2_SYNC_CLOSE_LAST %s:%ju\n", ascp->asc_label,
	    ascp->asc_id);

	/*
	 * If the syncpoint has been written, then we now need to ensure that
	 * the waiting thread has continued before proceeding to tear down any
	 * data structures.
	 *
	 * XXXRW: We have shifted this wait to the tail end of the writes that
	 * trigger completion, and so we no longer need it.  Assert that this
	 * is the case.  Drop the ifdef'd out code at some point.
	 */
#if 0
	while ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_CONTINUED) == 0) {
		cv_wait(&ascp->asc_cv_continued, &ascp->asc_mtx);
	}
#else
	if ((ascp->asc_flags & ACE2_SYNCPOINT_FLAG_CONTINUED) == 0)
		panic("%s: !ACE2_SYNCPOINT_FLAG_CONTINUED", __func__);
#endif

	/*
	 * We can't destroy_dev() from within an active device operation, so
	 * schedule that, and the rest of the syncpoint teardown, for once we
	 * return.
	 *
	 * XXXRW: Need to carefully double check synchronisation around this.
	 * Do all concurrent device methods behave suitably if they occur
	 * after this point?
	 */
	mtx_unlock(&ascp->asc_mtx);
	ace2_syncpoint_destroydev(ascp, ace2_syncpoint_destroydev_cb);
}

#define	STR_LABEL	"LABEL"
#define	STR_FUNC	"FUNC"

void
ace2_syncpoint_list(struct sbuf *sb)
{
	struct ace2_syncpoint_completion *ascp;
	u_int min_label_len, min_func_len;

	/*
	 * XXXRW: In a more ideal world, we might have a sentinal structure we
	 * use to walk the list without needing to hold the mutex the entire
	 * time, allowing us to lift the arbitrary limit on buffer size since
	 * then the sbuf code could be allowed to sleep for a memory
	 * allocation mid-flight.
	 */
	mtx_lock(&ace2_syncpoint_mtx);
	min_label_len = strlen(STR_LABEL);
	min_func_len = strlen(STR_FUNC);
	TAILQ_FOREACH(ascp, &ace2_syncpoint_completion_head, asc_entry) {
		min_label_len = max(min_label_len, strlen(ascp->asc_label));
		min_func_len = max(min_func_len, strlen(ascp->asc_func));
	}
	sbuf_printf(sb, "%6s %*s %5s %6s %-12s %5s %*s %s\n",
	    "ID",
	    -1 * min_label_len, STR_LABEL,
	    "PID",
	    "TID",
	    "COMM",
	    "FLAGS",
	    -1 * min_func_len, STR_FUNC,
	    "LOCATION");
	TAILQ_FOREACH(ascp, &ace2_syncpoint_completion_head, asc_entry) {
		sbuf_printf(sb,
		    "%6ju %*s %5u %6u %-12s %c%c%c   %*s %s:%d\n",
		    ascp->asc_id,
		    -1 * min_label_len, ascp->asc_label,
		    ascp->asc_pid,
		    ascp->asc_tid,
		    ascp->asc_pcomm,
		    (ascp->asc_flags & ACE2_SYNCPOINT_FLAG_WRITTEN) ? 'w' :
		      '-',
		    (ascp->asc_flags & ACE2_SYNCPOINT_FLAG_CONTINUED) ? 'c' :
		      '-',
		    (ascp->asc_flags & ACE2_SYNCPOINT_FLAG_READ) ? 'r' : '-',
		    min_func_len, ascp->asc_func,
		    ascp->asc_file,
		    ascp->asc_line);
	}
	mtx_unlock(&ace2_syncpoint_mtx);
}
