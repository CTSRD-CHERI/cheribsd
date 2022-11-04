/*	$NetBSD: linux_reservation.c,v 1.11 2018/09/03 18:02:11 riastradh Exp $	*/

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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/select.h>

#include <linux/dma-fence.h>
#include <linux/reservation.h>
#include <linux/seqlock.h>
#include <linux/ww_mutex.h>

MALLOC_DEFINE(M_RESERVATION, "reservation", "reservation allocator");

DEFINE_WW_CLASS(reservation_ww_class);

static struct reservation_object_list *
objlist_tryalloc(uint32_t n)
{
	struct reservation_object_list *list;

	list = malloc(offsetof(typeof(*list), shared[n]), M_RESERVATION,
	   M_NOWAIT | M_ZERO);
	if (list == NULL)
		return(NULL);
	list->shared_max = n;

	return (list);
}

static void
objlist_free(struct reservation_object_list *list)
{

	free(list, M_RESERVATION);
}

static void
objlist_free_cb(struct rcu_head *rcu)
{
	struct reservation_object_list *list;

	list = container_of(rcu, struct reservation_object_list, rol_rcu);
	objlist_free(list);
}

static void
objlist_defer_free(struct reservation_object_list *list)
{

	call_rcu(&list->rol_rcu, objlist_free_cb);
}

/*
 * reservation_object_init(robj)
 *
 *	Initialize a reservation object.  Caller must later destroy it
 *	with reservation_object_fini.
 */
void
reservation_object_init(struct reservation_object *robj)
{

	ww_mutex_init(&robj->lock, &reservation_ww_class);
	seqcount_init(&robj->seq);
	robj->fence_excl = NULL;
	robj->fence = NULL;
	robj->robj_prealloc = NULL;
}

/*
 * reservation_object_fini(robj)
 *
 *	Destroy a reservation object, freeing any memory that had been
 *	allocated for it.  Caller must have exclusive access to it.
 */
void
reservation_object_fini(struct reservation_object *robj)
{
	unsigned i;

	if (robj->robj_prealloc)
		objlist_free(robj->robj_prealloc);
	if (robj->fence) {
		for (i = 0; i < robj->fence->shared_count; i++)
			dma_fence_put(robj->fence->shared[i]);
		objlist_free(robj->fence);
	}
	if (robj->fence_excl)
		dma_fence_put(robj->fence_excl);
	ww_mutex_destroy(&robj->lock);
}

/*
 * reservation_object_lock(robj, ctx)
 *
 *	Acquire a reservation object's lock.  Return 0 on success,
 *	-EALREADY if caller already holds it, -EDEADLK if a
 *	higher-priority owner holds it and the caller must back out and
 *	retry.
 */
int
reservation_object_lock(struct reservation_object *robj,
    struct ww_acquire_ctx *ctx)
{

	return ww_mutex_lock(&robj->lock, ctx);
}

/*
 * reservation_object_lock_interruptible(robj, ctx)
 *
 *	Acquire a reservation object's lock.  Return 0 on success,
 *	-EALREADY if caller already holds it, -EDEADLK if a
 *	higher-priority owner holds it and the caller must back out and
 *	retry, -ERESTART/-EINTR if interrupted.
 */
int
reservation_object_lock_interruptible(struct reservation_object *robj,
    struct ww_acquire_ctx *ctx)
{

	return ww_mutex_lock_interruptible(&robj->lock, ctx);
}

/*
 * reservation_object_trylock(robj)
 *
 *	Try to acquire a reservation object's lock without blocking.
 *	Return true on success, false on failure.
 */
bool
reservation_object_trylock(struct reservation_object *robj)
{

	return ww_mutex_trylock(&robj->lock);
}

/*
 * reservation_object_unlock(robj)
 *
 *	Release a reservation object's lock.
 */
void
reservation_object_unlock(struct reservation_object *robj)
{

	return ww_mutex_unlock(&robj->lock);
}

/*
 * reservation_object_held(robj)
 *
 *	True if robj is locked.
 */
bool
reservation_object_held(struct reservation_object *robj)
{

	return ww_mutex_is_locked(&robj->lock);
}

/*
 * reservation_object_assert_held(robj)
 *
 *	Panic if robj is not held, in DIAGNOSTIC builds.
 */
void
reservation_object_assert_held(struct reservation_object *robj)
{

	MPASS(reservation_object_held(robj));
}

/*
 * reservation_object_get_excl(robj)
 *
 *	Return a pointer to the exclusive fence of the reservation
 *	object robj.
 *
 *	Caller must have robj locked.
 */
struct dma_fence *
reservation_object_get_excl(struct reservation_object *robj)
{

	MPASS(reservation_object_held(robj));
	return (robj->fence_excl);
}

/*
 * reservation_object_get_list(robj)
 *
 *	Return a pointer to the shared fence list of the reservation
 *	object robj.
 *
 *	Caller must have robj locked.
 */
struct reservation_object_list *
reservation_object_get_list(struct reservation_object *robj)
{

	MPASS(reservation_object_held(robj));
	return (robj->fence);
}

/*
 * reservation_object_reserve_shared(robj)
 *
 *	Reserve space in robj to add a shared fence.  To be used only
 *	once before calling reservation_object_add_shared_fence.
 *
 *	Caller must have robj locked.
 *
 *	Internally, we start with room for four entries and double if
 *	we don't have enough.  This is not guaranteed.
 */
int
reservation_object_reserve_shared(struct reservation_object *robj)
{
	struct reservation_object_list *list, *prealloc;
	uint32_t n, nalloc;

	MPASS(reservation_object_held(robj));

	list = robj->fence;
	prealloc = robj->robj_prealloc;

	/* If there's an existing list, check it for space.  */
	if (list) {
		/* If there's too many already, give up.  */
		if (list->shared_count == UINT32_MAX)
			return -ENOMEM;

		/* Add one more. */
		n = list->shared_count + 1;

		/* If there's enough for one more, we're done.  */
		if (n <= list->shared_max)
			return 0;
	} else {
		/* No list already.  We need space for 1.  */
		n = 1;
	}

	/* If not, maybe there's a preallocated list ready.  */
	if (prealloc != NULL) {
		/* If there's enough room in it, stop here.  */
		if (n <= prealloc->shared_max)
			return 0;

		/* Try to double its capacity.  */
		nalloc = n > UINT32_MAX/2 ? UINT32_MAX : 2*n;
		prealloc = objlist_tryalloc(nalloc);
		if (prealloc == NULL)
			return -ENOMEM;

		/* Swap the new preallocated list and free the old one.  */
		objlist_free(robj->robj_prealloc);
		robj->robj_prealloc = prealloc;
	} else {
		/* Start with some spare.  */
		nalloc = n > UINT32_MAX/2 ? UINT32_MAX : MAX(2*n, 4);
		prealloc = objlist_tryalloc(nalloc);
		if (prealloc == NULL)
			return -ENOMEM;
		/* Save the new preallocated list.  */
		robj->robj_prealloc = prealloc;
	}

	/* Success!  */
	return 0;
}

struct reservation_object_write_ticket {
};

/*
 * reservation_object_write_begin(robj, ticket)
 *
 *	Begin an atomic batch of writes to robj, and initialize opaque
 *	ticket for it.  The ticket must be passed to
 *	reservation_object_write_commit to commit the writes.
 *
 *	Caller must have robj locked.
 *
 *	Implies membar_producer, i.e. store-before-store barrier.  Does
 *	NOT serve as an acquire operation, however.
 */
static void
reservation_object_write_begin(struct reservation_object *robj,
    struct reservation_object_write_ticket *ticket)
{

	MPASS(reservation_object_held(robj));

	write_seqcount_begin(&robj->seq);
}

/*
 * reservation_object_write_commit(robj, ticket)
 *
 *	Commit an atomic batch of writes to robj begun with the call to
 *	reservation_object_write_begin that returned ticket.
 *
 *	Caller must have robj locked.
 *
 *	Implies membar_producer, i.e. store-before-store barrier.  Does
 *	NOT serve as a release operation, however.
 */
static void
reservation_object_write_commit(struct reservation_object *robj,
    struct reservation_object_write_ticket *ticket)
{

	MPASS(reservation_object_held(robj));

	write_seqcount_end(&robj->seq);
}

struct reservation_object_read_ticket {
	unsigned version;
};

/*
 * reservation_object_read_begin(robj, ticket)
 *
 *	Begin a read section, and initialize opaque ticket for it.  The
 *	ticket must be passed to reservation_object_read_exit, and the
 *	caller must be prepared to retry reading if it fails.
 */
static void
reservation_object_read_begin(const struct reservation_object *robj,
    struct reservation_object_read_ticket *ticket)
{

	ticket->version = read_seqcount_begin(&robj->seq);
}

/*
 * reservation_object_read_valid(robj, ticket)
 *
 *	Test whether the read sections are valid.  Return true on
 *	success, or false on failure if the read ticket has been
 *	invalidated.
 */
static bool
reservation_object_read_valid(const struct reservation_object *robj,
    struct reservation_object_read_ticket *ticket)
{

	return !read_seqcount_retry(&robj->seq, ticket->version);
}

/*
 * reservation_object_add_excl_fence(robj, fence)
 *
 *	Empty and release all of robj's shared fences, and clear and
 *	release its exclusive fence.  If fence is nonnull, acquire a
 *	reference to it and save it as robj's exclusive fence.
 *
 *	Caller must have robj locked.
 */
void
reservation_object_add_excl_fence(struct reservation_object *robj,
    struct dma_fence *fence)
{
	struct dma_fence *old_fence = robj->fence_excl;
	struct reservation_object_list *old_list = robj->fence;
	uint32_t old_shared_count;
	struct reservation_object_write_ticket ticket;

	MPASS(reservation_object_held(robj));

	/*
	 * If we are setting rather than just removing a fence, acquire
	 * a reference for ourselves.
	 */
	if (fence)
		(void)dma_fence_get(fence);

	/* If there are any shared fences, remember how many.  */
	if (old_list)
		old_shared_count = old_list->shared_count;

	/* Begin an update.  */
	reservation_object_write_begin(robj, &ticket);

	/* Replace the fence and zero the shared count.  */
	robj->fence_excl = fence;
	if (old_list)
		old_list->shared_count = 0;

	/* Commit the update.  */
	reservation_object_write_commit(robj, &ticket);

	/* Release the old exclusive fence, if any.  */
	if (old_fence)
		dma_fence_put(old_fence);

	/* Release any old shared fences.  */
	if (old_list) {
		while (old_shared_count--)
			dma_fence_put(old_list->shared[old_shared_count]);
	}
}

/*
 * reservation_object_add_shared_fence(robj, fence)
 *
 *	Acquire a reference to fence and add it to robj's shared list.
 *	If any fence was already added with the same context number,
 *	release it and replace it by this one.
 *
 *	Caller must have robj locked, and must have preceded with a
 *	call to reservation_object_reserve_shared for each shared fence
 *	added.
 */
void
reservation_object_add_shared_fence(struct reservation_object *robj,
    struct dma_fence *fence)
{
	struct reservation_object_list *list = robj->fence;
	struct reservation_object_list *prealloc = robj->robj_prealloc;
	struct reservation_object_write_ticket ticket;
	struct dma_fence *replace = NULL;
	uint32_t i;

	MPASS(reservation_object_held(robj));

	/* Acquire a reference to the fence.  */
	MPASS(fence != NULL);
	(void)dma_fence_get(fence);

	/* Check for a preallocated replacement list.  */
	if (prealloc == NULL) {
		/*
		 * If there is no preallocated replacement list, then
		 * there must be room in the current list.
		 */
		MPASS(list != NULL);
		MPASS(list->shared_count < list->shared_max);

		/* Begin an update.  Implies membar_producer for fence.  */
		reservation_object_write_begin(robj, &ticket);

		/* Find a fence with the same context number.  */
		for (i = 0; i < list->shared_count; i++) {
			if (list->shared[i]->context == fence->context) {
				replace = list->shared[i];
				list->shared[i] = fence;
				break;
			}
		}

		/* If we didn't find one, add it at the end.  */
		if (i == list->shared_count)
			list->shared[list->shared_count++] = fence;

		/* Commit the update.  */
		reservation_object_write_commit(robj, &ticket);
	} else {
		/*
		 * There is a preallocated replacement list.  There may
		 * not be a current list.  If not, treat it as a zero-
		 * length list.
		 */
		uint32_t shared_count = (list == NULL? 0 : list->shared_count);

		/* There had better be room in the preallocated list.  */
		MPASS(shared_count < prealloc->shared_max);

		/*
		 * Copy the fences over, but replace if we find one
		 * with the same context number.
		 */
		for (i = 0; i < shared_count; i++) {
			if (replace == NULL &&
			    list->shared[i]->context == fence->context) {
				replace = list->shared[i];
				prealloc->shared[i] = fence;
			} else {
				prealloc->shared[i] = list->shared[i];
			}
		}
		prealloc->shared_count = shared_count;

		/* If we didn't find one, add it at the end.  */
		if (replace == NULL)
			prealloc->shared[prealloc->shared_count++] = fence;

		/*
		 * Now ready to replace the list.  Begin an update.
		 * Implies membar_producer for fence and prealloc.
		 */
		reservation_object_write_begin(robj, &ticket);

		/* Replace the list.  */
		robj->fence = prealloc;
		robj->robj_prealloc = NULL;

		/* Commit the update.  */
		reservation_object_write_commit(robj, &ticket);

		/*
		 * If there is an old list, free it when convenient.
		 * (We are not in a position at this point to sleep
		 * waiting for activity on all CPUs.)
		 */
		if (list)
			objlist_defer_free(list);
	}

	/* Release a fence if we replaced it.  */
	if (replace)
		dma_fence_put(replace);
}

/*
 * reservation_object_get_excl_rcu(robj)
 *
 *	Note: Caller need not call this from an RCU read section.
 */
struct dma_fence *
reservation_object_get_excl_rcu(const struct reservation_object *robj)
{
	struct dma_fence *fence;

	rcu_read_lock();
	fence = dma_fence_get_rcu_safe(&robj->fence_excl);
	rcu_read_unlock();

	return fence;
}

/*
 * reservation_object_get_fences_rcu(robj, fencep, nsharedp, sharedp)
 */
int
reservation_object_get_fences_rcu(const struct reservation_object *robj,
    struct dma_fence **fencep, unsigned *nsharedp, struct dma_fence ***sharedp)
{
	const struct reservation_object_list *list;
	struct dma_fence *fence;
	struct dma_fence **shared = NULL;
	unsigned shared_alloc, shared_count, i;
	struct reservation_object_read_ticket ticket;

top:
	/* Enter an RCU read section and get a read ticket.  */
	rcu_read_lock();
	reservation_object_read_begin(robj, &ticket);

	/* If there is a shared list, grab it.  */
	list = robj->fence;
//	__insn_barrier();
smp_rmb();
	if (list) {
		/* Make sure the content of the list has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/* Check whether we have a buffer.  */
		if (shared == NULL) {
			/*
			 * We don't have a buffer yet.  Try to allocate
			 * one without waiting.
			 */
			shared_alloc = list->shared_max;
//			__insn_barrier();
			shared = kcalloc(shared_alloc, sizeof(shared[0]),
			    GFP_NOWAIT);
			if (shared == NULL) {
				/*
				 * Couldn't do it immediately.  Back
				 * out of RCU and allocate one with
				 * waiting.
				 */
				rcu_read_unlock();
				shared = kcalloc(shared_alloc,
				    sizeof(shared[0]), GFP_KERNEL);
				if (shared == NULL)
					return -ENOMEM;
				goto top;
			}
		} else if (shared_alloc < list->shared_max) {
			/*
			 * We have a buffer but it's too small.  We're
			 * already racing in this case, so just back
			 * out and wait to allocate a bigger one.
			 */
			shared_alloc = list->shared_max;
//			__insn_barrier();
			rcu_read_unlock();
			kfree(shared);
			shared = kcalloc(shared_alloc, sizeof(shared[0]),
			    GFP_KERNEL);
			if (shared == NULL)
				return -ENOMEM;
		}

		/*
		 * We got a buffer large enough.  Copy into the buffer
		 * and record the number of elements.
		 */
		memcpy(shared, list->shared, shared_alloc * sizeof(shared[0]));
		shared_count = list->shared_count;
	} else {
		/* No shared list: shared count is zero.  */
		shared_count = 0;
	}

	/* If there is an exclusive fence, grab it.  */
	fence = robj->fence_excl;
smp_rmb();
//	__insn_barrier();
	if (fence) {
		/* Make sure the content of the fence has been published.  */
//		membar_datadep_consumer();
smp_rmb();
	}

	/*
	 * We are done reading from robj and list.  Validate our
	 * parking ticket.  If it's invalid, do not pass go and do not
	 * collect $200.
	 */
	if (!reservation_object_read_valid(robj, &ticket))
		goto restart;

	/*
	 * Try to get a reference to the exclusive fence, if there is
	 * one.  If we can't, start over.
	 */
	if (fence) {
		if (dma_fence_get_rcu(fence) == NULL)
			goto restart;
	}

	/*
	 * Try to get a reference to all of the shared fences.
	 */
	for (i = 0; i < shared_count; i++) {
		if (dma_fence_get_rcu(shared[i]) == NULL)
			goto put_restart;
	}

	/* Success!  */
	rcu_read_unlock();
	*fencep = fence;
	*nsharedp = shared_count;
	*sharedp = shared;
	return 0;

put_restart:
	/* Back out.  */
	while (i --> 0) {
		dma_fence_put(shared[i]);
		shared[i] = NULL; /* paranoia */
	}
	if (fence) {
		dma_fence_put(fence);
		fence = NULL;	/* paranoia */
	}

restart:
	rcu_read_unlock();
	goto top;
}

/*
 * reservation_object_copy_fences(dst, src)
 *
 *	Copy the exclusive fence and all the shared fences from src to
 *	dst.
 *
 *	Caller must have dst locked.
 */
int
reservation_object_copy_fences(struct reservation_object *dst_robj,
    const struct reservation_object *src_robj)
{
	const struct reservation_object_list *src_list;
	struct reservation_object_list *dst_list = NULL;
	struct reservation_object_list *old_list;
	struct dma_fence *fence = NULL;
	struct dma_fence *old_fence;
	uint32_t shared_count, i;
	struct reservation_object_read_ticket read_ticket;
	struct reservation_object_write_ticket write_ticket;

	MPASS(reservation_object_held(dst_robj));

top:
	/* Enter an RCU read section and get a read ticket.  */
	rcu_read_lock();
	reservation_object_read_begin(src_robj, &read_ticket);

	/* Get the shared list.  */
	src_list = src_robj->fence;
//	__insn_barrier();
smp_rmb();
	if (src_list) {
		/* Make sure the content of the list has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/* Find out how long it is.  */
		shared_count = src_list->shared_count;

		/*
		 * Make sure we saw a consistent snapshot of the list
		 * pointer and length.
		 */
		if (!reservation_object_read_valid(src_robj, &read_ticket))
			goto restart;

		/* Allocate a new list.  */
		dst_list = objlist_tryalloc(shared_count);
		if (dst_list == NULL)
			return -ENOMEM;

		/* Copy over all fences that are not yet signalled.  */
		dst_list->shared_count = 0;
		for (i = 0; i < shared_count; i++) {
			if ((fence = dma_fence_get_rcu(src_list->shared[i]))
			    != NULL)
				goto restart;
			if (dma_fence_is_signaled(fence)) {
				dma_fence_put(fence);
				fence = NULL;
				continue;
			}
			dst_list->shared[dst_list->shared_count++] = fence;
			fence = NULL;
		}
	}

	/* Get the exclusive fence.  */
	fence = src_robj->fence_excl;
smp_rmb();
//	__insn_barrier();
	if (fence != NULL) {
		/* Make sure the content of the fence has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/*
		 * Make sure we saw a consistent snapshot of the fence.
		 *
		 * XXX I'm not actually sure this is necessary since
		 * pointer writes are supposed to be atomic.
		 */
		if (!reservation_object_read_valid(src_robj, &read_ticket)) {
			fence = NULL;
			goto restart;
		}

		/*
		 * If it is going away, restart.  Otherwise, acquire a
		 * reference to it.
		 */
		if (!dma_fence_get_rcu(fence)) {
			fence = NULL;
			goto restart;
		}
	}

	/* All done with src; exit the RCU read section.  */
	rcu_read_unlock();

	/*
	 * We now have a snapshot of the shared and exclusive fences of
	 * src_robj and we have acquired references to them so they
	 * won't go away.  Transfer them over to dst_robj, releasing
	 * references to any that were there.
	 */

	/* Get the old shared and exclusive fences, if any.  */
	old_list = dst_robj->fence;
	old_fence = dst_robj->fence_excl;

	/* Begin an update.  */
	reservation_object_write_begin(dst_robj, &write_ticket);

	/* Replace the fences.  */
	dst_robj->fence = dst_list;
	dst_robj->fence_excl = fence;

	/* Commit the update.  */
	reservation_object_write_commit(dst_robj, &write_ticket);

	/* Release the old exclusive fence, if any.  */
	if (old_fence)
		dma_fence_put(old_fence);

	/* Release any old shared fences.  */
	if (old_list) {
		for (i = old_list->shared_count; i --> 0;)
			dma_fence_put(old_list->shared[i]);
	}

	/* Success!  */
	return 0;

restart:
	rcu_read_unlock();
	if (dst_list) {
		for (i = dst_list->shared_count; i --> 0;) {
			dma_fence_put(dst_list->shared[i]);
			dst_list->shared[i] = NULL;
		}
		objlist_free(dst_list);
		dst_list = NULL;
	}
	if (fence) {
		dma_fence_put(fence);
		fence = NULL;
	}
	goto top;
}

/*
 * reservation_object_test_signaled_rcu(robj, shared)
 *
 *	If shared is true, test whether all of the shared fences are
 *	signalled, or if there are none, test whether the exclusive
 *	fence is signalled.  If shared is false, test only whether the
 *	exclusive fence is signalled.
 *
 *	XXX Why does this _not_ test the exclusive fence if shared is
 *	true only if there are no shared fences?  This makes no sense.
 */
bool
reservation_object_test_signaled_rcu(const struct reservation_object *robj,
    bool shared)
{
	struct reservation_object_read_ticket ticket;
	struct reservation_object_list *list;
	struct dma_fence *fence;
	uint32_t i, shared_count;
	bool signaled = true;

top:
	/* Enter an RCU read section and get a read ticket.  */
	rcu_read_lock();
	reservation_object_read_begin(robj, &ticket);

	/* If shared is requested and there is a shared list, test it.  */
	if (!shared)
		goto excl;
	list = robj->fence;
//	__insn_barrier();
smp_rmb();
	if (list) {
		/* Make sure the content of the list has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/* Find out how long it is.  */
		shared_count = list->shared_count;

		/*
		 * Make sure we saw a consistent snapshot of the list
		 * pointer and length.
		 */
		if (!reservation_object_read_valid(robj, &ticket))
			goto restart;

		/*
		 * For each fence, if it is going away, restart.
		 * Otherwise, acquire a reference to it to test whether
		 * it is signalled.  Stop if we find any that is not
		 * signalled.
		 */
		for (i = 0; i < shared_count; i++) {
			fence = dma_fence_get_rcu(list->shared[i]);
			if (fence == NULL)
				goto restart;
			signaled &= dma_fence_is_signaled(fence);
			dma_fence_put(fence);
			if (!signaled)
				goto out;
		}
	}

excl:
	/* If there is an exclusive fence, test it.  */
	fence = robj->fence_excl;
smp_rmb();
//	__insn_barrier();
	if (fence) {
		/* Make sure the content of the fence has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/*
		 * Make sure we saw a consistent snapshot of the fence.
		 *
		 * XXX I'm not actually sure this is necessary since
		 * pointer writes are supposed to be atomic.
		 */
		if (!reservation_object_read_valid(robj, &ticket))
			goto restart;

		/*
		 * If it is going away, restart.  Otherwise, acquire a
		 * reference to it to test whether it is signalled.
		 */
		if ((fence = dma_fence_get_rcu(fence)) == NULL)
			goto restart;
		signaled &= dma_fence_is_signaled(fence);
		dma_fence_put(fence);
		if (!signaled)
			goto out;
	}

out:	rcu_read_unlock();
	return signaled;

restart:
	rcu_read_unlock();
	goto top;
}

/*
 * reservation_object_wait_timeout_rcu(robj, shared, intr, timeout)
 *
 *	If shared is true, wait for all of the shared fences to be
 *	signalled, or if there are none, wait for the exclusive fence
 *	to be signalled.  If shared is false, wait only for the
 *	exclusive fence to be signalled.  If timeout is zero, don't
 *	wait, only test.
 *
 *	XXX Why does this _not_ wait for the exclusive fence if shared
 *	is true only if there are no shared fences?  This makes no
 *	sense.
 */
long
reservation_object_wait_timeout_rcu(const struct reservation_object *robj,
    bool shared, bool intr, unsigned long timeout)
{
	struct reservation_object_read_ticket ticket;
	struct reservation_object_list *list;
	struct dma_fence *fence;
	uint32_t i, shared_count;
	long ret;

	if (timeout == 0)
		return reservation_object_test_signaled_rcu(robj, shared);

top:
	/* Enter an RCU read section and get a read ticket.  */
	rcu_read_lock();
	reservation_object_read_begin(robj, &ticket);

	/* If shared is requested and there is a shared list, wait on it.  */
	if (!shared)
		goto excl;
	list = robj->fence;
//	__insn_barrier();
smp_rmb();
	if (list) {
		/* Make sure the content of the list has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/* Find out how long it is.  */
		shared_count = list->shared_count;

		/*
		 * Make sure we saw a consistent snapshot of the list
		 * pointer and length.
		 */
		if (!reservation_object_read_valid(robj, &ticket))
			goto restart;

		/*
		 * For each fence, if it is going away, restart.
		 * Otherwise, acquire a reference to it to test whether
		 * it is signalled.  Stop and wait if we find any that
		 * is not signalled.
		 */
		for (i = 0; i < shared_count; i++) {
			fence = dma_fence_get_rcu(list->shared[i]);
			if (fence == NULL)
				goto restart;
			if (!dma_fence_is_signaled(fence))
				goto wait;
			dma_fence_put(fence);
		}
	}

excl:
	/* If there is an exclusive fence, test it.  */
	fence = robj->fence_excl;
smp_rmb();
//	__insn_barrier();
	if (fence) {
		/* Make sure the content of the fence has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/*
		 * Make sure we saw a consistent snapshot of the fence.
		 *
		 * XXX I'm not actually sure this is necessary since
		 * pointer writes are supposed to be atomic.
		 */
		if (!reservation_object_read_valid(robj, &ticket))
			goto restart;

		/*
		 * If it is going away, restart.  Otherwise, acquire a
		 * reference to it to test whether it is signalled.  If
		 * not, wait for it.
		 */
		if ((fence = dma_fence_get_rcu(fence)) == NULL)
			goto restart;
		if (!dma_fence_is_signaled(fence))
			goto wait;
		dma_fence_put(fence);
	}

	/* Success!  Return the number of ticks left.  */
	rcu_read_unlock();
	return timeout;

restart:
	rcu_read_unlock();
	goto top;

wait:
	/*
	 * Exit the RCU read section and wait for it.  If we time out
	 * or fail, bail.  Otherwise, go back to the top.
	 */
	MPASS(fence != NULL);
	rcu_read_unlock();
	ret = dma_fence_wait_timeout(fence, intr, timeout);
	if (ret <= 0)
		return ret;
	MPASS(ret <= timeout);
	timeout = ret;
	goto top;
}

/*
 * reservation_poll_init(rpoll, lock)
 *
 *	Initialize reservation poll state.
 */
void
reservation_poll_init(struct reservation_poll *rpoll)
{

	sx_init(&rpoll->rp_lock, " reservation poll");
	bzero(&rpoll->rp_selq, sizeof(rpoll->rp_selq));
	rpoll->rp_claimed = 0;
}

/*
 * reservation_poll_fini(rpoll)
 *
 *	Release any resource associated with reservation poll state.
 */
void
reservation_poll_fini(struct reservation_poll *rpoll)
{

	MPASS(rpoll->rp_claimed == 0);
	seldrain(&rpoll->rp_selq);
	sx_destroy(&rpoll->rp_lock);
}

/*
 * reservation_poll_cb(fence, fcb)
 *
 *	Callback to notify a reservation poll that a fence has
 *	completed.  Notify any waiters and allow the next poller to
 *	claim the callback.
 *
 *	If one thread is waiting for the exclusive fence only, and we
 *	spuriously notify them about a shared fence, tough.
 */
static void
reservation_poll_cb(struct dma_fence *fence, struct dma_fence_cb *fcb)
{
	struct reservation_poll *rpoll = container_of(fcb,
	    struct reservation_poll, rp_fcb);

	sx_xlock(&rpoll->rp_lock);
	selwakeup(&rpoll->rp_selq);
	rpoll->rp_claimed = 0;
	sx_xunlock(&rpoll->rp_lock);
}

/*
 * reservation_object_poll(robj, events, rpoll)
 *
 *	Poll for reservation object events using the reservation poll
 *	state in rpoll:
 *
 *	- POLLOUT	wait for all fences shared and exclusive
 *	- POLLIN	wait for the exclusive fence
 *
 *	Return the subset of events in events that are ready.  If any
 *	are requested but not ready, arrange to be notified with
 *	selwakeup when they are.
 */
int
reservation_object_poll(const struct reservation_object *robj, int events,
    struct reservation_poll *rpoll)
{
	struct reservation_object_read_ticket ticket;
	struct reservation_object_list *list;
	struct dma_fence *fence;
	uint32_t i, shared_count;
	int revents;
	bool recorded = false;	/* curlwp is on the selq */
	bool claimed = false;	/* we claimed the callback */
	bool callback = false;	/* we requested a callback */

	/*
	 * Start with the maximal set of events that could be ready.
	 * We will eliminate the events that are definitely not ready
	 * as we go at the same time as we add callbacks to notify us
	 * that they may be ready.
	 */
	revents = events & (POLLIN|POLLOUT);
	if (revents == 0)
		return 0;

top:
	/* Enter an RCU read section and get a read ticket.  */
	rcu_read_lock();
	reservation_object_read_begin(robj, &ticket);

	/* If we want to wait for all fences, get the shared list.  */
	if (!(events & POLLOUT))
		goto excl;
	list = robj->fence;
//	__insn_barrier();
smp_rmb();
	if (list) do {
		/* Make sure the content of the list has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/* Find out how long it is.  */
		shared_count = list->shared_count;

		/*
		 * Make sure we saw a consistent snapshot of the list
		 * pointer and length.
		 */
		if (!reservation_object_read_valid(robj, &ticket))
			goto restart;

		/*
		 * For each fence, if it is going away, restart.
		 * Otherwise, acquire a reference to it to test whether
		 * it is signalled.  Stop and request a callback if we
		 * find any that is not signalled.
		 */
		for (i = 0; i < shared_count; i++) {
			fence = dma_fence_get_rcu(list->shared[i]);
			if (fence == NULL)
				goto restart;
			if (!dma_fence_is_signaled(fence)) {
				dma_fence_put(fence);
				break;
			}
			dma_fence_put(fence);
		}

		/* If all shared fences have been signalled, move on.  */
		if (i == shared_count)
			break;

		/* Put ourselves on the selq if we haven't already.  */
		if (!recorded)
			goto record;

		/*
		 * If someone else claimed the callback, or we already
		 * requested it, we're guaranteed to be notified, so
		 * assume the event is not ready.
		 */
		if (!claimed || callback) {
			revents &= ~POLLOUT;
			break;
		}

		/*
		 * Otherwise, find the first fence that is not
		 * signalled, request the callback, and clear POLLOUT
		 * from the possible ready events.  If they are all
		 * signalled, leave POLLOUT set; we will simulate the
		 * callback later.
		 */
		for (i = 0; i < shared_count; i++) {
			fence = dma_fence_get_rcu(list->shared[i]);
			if (fence == NULL)
				goto restart;
			if (!dma_fence_add_callback(fence, &rpoll->rp_fcb,
				reservation_poll_cb)) {
				dma_fence_put(fence);
				revents &= ~POLLOUT;
				callback = true;
				break;
			}
			dma_fence_put(fence);
		}
	} while (0);

excl:
	/* We always wait for at least the exclusive fence, so get it.  */
	fence = robj->fence_excl;
smp_rmb();
//	__insn_barrier();
	if (fence) do {
		/* Make sure the content of the fence has been published.  */
//		membar_datadep_consumer();
smp_wmb();

		/*
		 * Make sure we saw a consistent snapshot of the fence.
		 *
		 * XXX I'm not actually sure this is necessary since
		 * pointer writes are supposed to be atomic.
		 */
		if (!reservation_object_read_valid(robj, &ticket))
			goto restart;

		/*
		 * If it is going away, restart.  Otherwise, acquire a
		 * reference to it to test whether it is signalled.  If
		 * not, stop and request a callback.
		 */
		if ((fence = dma_fence_get_rcu(fence)) == NULL)
			goto restart;
		if (dma_fence_is_signaled(fence)) {
			dma_fence_put(fence);
			break;
		}

		/* Put ourselves on the selq if we haven't already.  */
		if (!recorded) {
			dma_fence_put(fence);
			goto record;
		}

		/*
		 * If someone else claimed the callback, or we already
		 * requested it, we're guaranteed to be notified, so
		 * assume the event is not ready.
		 */
		if (!claimed || callback) {
			revents = 0;
			break;
		}

		/*
		 * Otherwise, try to request the callback, and clear
		 * all possible ready events.  If the fence has been
		 * signalled in the interim, leave the events set; we
		 * will simulate the callback later.
		 */
		if (!dma_fence_add_callback(fence, &rpoll->rp_fcb,
			reservation_poll_cb)) {
			dma_fence_put(fence);
			revents = 0;
			callback = true;
			break;
		}
		dma_fence_put(fence);
	} while (0);

	/* All done reading the fences.  */
	rcu_read_unlock();

	if (claimed && !callback) {
		/*
		 * We claimed the callback but we didn't actually
		 * request it because a fence was signalled while we
		 * were claiming it.  Call it ourselves now.  The
		 * callback doesn't use the fence nor rely on holding
		 * any of the fence locks, so this is safe.
		 */
		reservation_poll_cb(NULL, &rpoll->rp_fcb);
	}
	return revents;

restart:
	rcu_read_unlock();
	goto top;

record:
	rcu_read_unlock();
	sx_xlock(&rpoll->rp_lock);
	selrecord(curthread, &rpoll->rp_selq);
	if (!rpoll->rp_claimed)
		claimed = rpoll->rp_claimed = true;
	sx_xunlock(&rpoll->rp_lock);
	recorded = true;
	goto top;
}

/*
 * reservation_object_kqfilter(robj, kn, rpoll)
 *
 *	Kqueue filter for reservation objects.  Currently not
 *	implemented because the logic to implement it is nontrivial,
 *	and userland will presumably never use it, so it would be
 *	dangerous to add never-tested complex code paths to the kernel.
 */
int
reservation_object_kqfilter(const struct reservation_object *robj,
    struct knote *kn, struct reservation_poll *rpoll)
{

	return EINVAL;
}
