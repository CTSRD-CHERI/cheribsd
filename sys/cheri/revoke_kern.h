/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 SRI International
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

#ifndef __SYS_CHERI_REVOKE_KERN_H__
#define	__SYS_CHERI_REVOKE_KERN_H__

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/sysctl.h>
#else
#include <stdbool.h>
#endif

/*
 * The outermost capability revocation state machine.
 *
 *   We begin with no revocation in progress (CHERI_REVOKE_ST_NONE).
 *   We then select a revocation mode and optionally a unmapped entry
 *   to revoke along side capabilities without the SW_VMEM permission
 *   and quarantined in userspace.  It then transitions to one of
 *   CHERI_REVOKE_ST_INITING or CHERI_REVOKE_ST_CLOSING.
 *
 *   At this point, we enter the barrier phase, attemping to
 *   single thread the process (resetting to our initial state and
 *   restarting the call on failure).  We then revoke each trap frame
 *   and kernel capability horde before incrementing the GCLG and perform
 *   a TLB shootdown.  Finally we end single threading.  At this point,
 *   thread state can not be further contaminated with capabilities to be
 *   revoked as loads will fault and a scan will be performed.
 *
 *   If we're in CHERI_REVOKE_ST_INITING we then transition to
 *   CHERI_REVOKE_ST_INITED and publish our newly opened epoch.
 *   Alternatively, if we're in CHERI_REVOKE_ST_CLOSING we perform
 *   a final scan of all unscanned pages, before transitioning back to
 *   CHERI_REVOKE_ST_NONE and publishing the newly closed epoch.
 *
 *   We reenter the state machine at CHERI_REVOKE_ST_INITED and
 *   the CHERI_REVOKE_LAST_PASS flag set, we proceed as though we were
 *   in CHERI_REVOKE_ST_CLOSING as described above, scanning unscanned
 *   pages and transitioning to CHERI_REVOKE_ST_NONE.
 *
 *   Absent concurrent calls to cheri_revoke(2) we will always enter
 *   with the state CHERI_REVOKE_ST_NONE or CHERI_REVOKE_ST_INITED.
 *
 * The state and epoch counter are stored in the same per-address space word,
 * vm_cheri_revoke_st, in the VM map.
 *
 * To implement asynchronous revocation, vm_cheri_revoke_pass_async() signals a
 * kernel worker process, which maintains its own state in the
 * vm_cheri_async_revoke_st field of the VM map.  The states have similar
 * meanings:
 *
 *   CHERI_REVOKE_ST_NONE: No revocation is scheduled.
 *
 *   CHERI_REVOKE_ST_INITING: An asynchronous revocation request is pending but
 *   has not yet been observed by a worker thread.
 *
 *   CHERI_REVOKE_ST_INITED: A worker thread is currently processing the
 *   request and will update the state once it's finished.
 *
 *   CHERI_REVOKE_ST_CLOSING: A worker thread has finished the revocation pass.
 *   If it was successful, the epoch is advanced.  The return value of the
 *   vm_cheri_revoke_pass() call is stored in the VM map for consumption by the
 *   application.
 *
 * While an asynchronous revocation pass is pending, the main state is
 * CHERI_REVOKE_ST_INITED.  Once the async state has transitioned to
 * CHERI_REVOKE_ST_CLOSING, a subsequent call to cheri_revoke() will change the
 * main state to CHERI_REVOKE_ST_CLOSING if the pass was successful.
 */

typedef uint64_t cheri_revoke_state_t;

enum cheri_revoke_state {
	CHERI_REVOKE_ST_NONE    = 0, /* No revocation is in progress */
	CHERI_REVOKE_ST_INITING = 1, /* opening now */
	CHERI_REVOKE_ST_INITED  = 2, /* open (= 1 opens done) */
	CHERI_REVOKE_ST_CLOSING = 3, /* background working */
};

#define CHERI_REVOKE_ST_ST_MASK		0x3
#define CHERI_REVOKE_ST_EPOCH_SHIFT	2

static inline enum cheri_revoke_state
cheri_revoke_st_get_state(cheri_revoke_state_t st)
{
	return (st & CHERI_REVOKE_ST_ST_MASK);
}

static inline cheri_revoke_epoch_t
cheri_revoke_st_get_epoch(cheri_revoke_state_t st)
{
	return (st >> CHERI_REVOKE_ST_EPOCH_SHIFT);
}

static inline void
cheri_revoke_st_set(cheri_revoke_state_t *st, cheri_revoke_epoch_t epoch,
    enum cheri_revoke_state state)
{
	*st = (epoch << CHERI_REVOKE_ST_EPOCH_SHIFT) | state;
}

static inline bool
cheri_revoke_st_is_revoking(cheri_revoke_state_t st)
{
	switch (cheri_revoke_st_get_state(st)) {
	case CHERI_REVOKE_ST_INITING:
	case CHERI_REVOKE_ST_INITED:
	case CHERI_REVOKE_ST_CLOSING:
		return (true);
	case CHERI_REVOKE_ST_NONE:
		return (false);
	}
}

struct cheri_revoke_info_page {
	/* Userland will come to hold RO caps to this bit */
	struct cheri_revoke_info pub;

	/*
	 * The kernel is free to use the rest of this page for
	 * private data that is quite naturally associated with
	 * this VM space.
	 */
};

#ifdef _KERNEL
SYSCTL_DECL(_vm_cheri_revoke);

extern int security_cheri_runtime_revocation_default;
extern int security_cheri_runtime_revocation_every_free_default;
extern int security_cheri_runtime_revocation_async;

struct vmspace;
void cheri_revoke_vmspace_fork(struct vmspace *dst, struct vmspace *src);
#endif

#endif /* !__SYS_CHERI_REVOKE_KERN_H__ */
