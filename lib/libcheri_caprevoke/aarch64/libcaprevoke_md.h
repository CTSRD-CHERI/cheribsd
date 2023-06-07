/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018-2020 Nathaniel Wesley Filardo <nwf20@cl.cam.ac.uk>
 * Copyright (c) 2018-2022 Brett Guttstein <brett.gutstein@cst.cam.ac.uk>
 * Copyright (c) 2020-2022 Microsoft Corp.
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

/*
 * Revocation bitmap manipulation primitive operations for Morello.
 */

#pragma once

static inline uint64_t
caprev_shadow_set_fw(uint64_t * __capability fw, void * __capability user_obj,
    uint64_t fwm)
{
	uint64_t lshadow, scratch;
	int stxr_status = 1;

	__asm__ __volatile__ (
#ifndef __CHERI_PURE_CAPABILITY__
		"bx #4\n\t"
		".arch_extension c64\n\t"
#endif
		"1:\n\t"
		/* Load reserve first word */
		"ldxr %[lshadow], [%[fw]]\n\t"

		/* Jump out if shadow set */
		"ands %[scratch], %[lshadow], %[fwm]\n\t"
		"bne 2f\n\t"

		/*
		 * While under the same reservation for the atomic update to the
		 * shadow bitmap, we test properties of the user-provided cap (a
		 * copy of the thing we're about to cause to be eventually
		 * revoked).  Because this atomic sequence is, by presumption,
		 * targeting *the* first word of an allocation, concurrent
		 * double frees will be racing for the same word of the bitmap.
		 * These tests ensure that the object has not been already
		 * revoked, and running them under this reservation ensures that
		 * we will notice if it's revoked and cleared for reuse while
		 * we're off-core.  In particular, imagine that we ran these
		 * test prior to the atomic update to the bitmap and that we
		 * were descheduled between the tests and the atomic update; in
		 * that case, another thread could claim the object in the
		 * bitmap, run the revoker, and then clears the bitmap, we would
		 * successfully run the atomic with a revoked user_obj,
		 * effectively enabling a free in the wrong revocation epoch
		 * (with a revoked pointer).
		 */

		/* Jump out if object detagged */
		"gctag %[scratch], %[obj]\n\t"
		"cbz %[scratch], 2f\n\t"

		/* Jump out if zero perms */
		"gcperm %[scratch], %[obj]\n\t"
		"cbz %[scratch], 2f\n\t"

		/* bitwise or in the mask */
		"orr %[lshadow], %[lshadow], %[fwm]\n\t"

		/* SC the updated mask - status nonzero on failure */
		"stxr %w[stxr_status], %[lshadow], [%[fw]]\n\t"
		"cbnz %w[stxr_status], 1b\n\t"
		"2:\n\t"
#ifndef __CHERI_PURE_CAPABILITY__
		"bx #4\n\t"
		".arch_extension noc64\n\t"
		".arch_extension a64c\n\t"
#endif
	: /* outputs */
		[stxr_status] "+&r" (stxr_status),
		[lshadow] "=&r" (lshadow),
		[scratch] "=&r" (scratch)
	: /* inputs */
		[obj] "C" (user_obj),
		[fw] "C" (fw),
		[fwm] "r" (fwm)
	: /* clobbers */
		"memory"
	);

	return (stxr_status == 0);
}

/*
 * XXX In principle, this could be built for hybrid-CHERI, but
 * https://git.morello-project.org/morello/llvm-project/-/issues/26 means that
 * the atomics used below break the compiler.  In practice, this library is only
 * ever used in purecap programs and the kernel revoker to which this library
 * speaks is gated on the user program being purecap.
 */

static inline void
caprev_shadow_set_lw(_Atomic(uint64_t) * __capability lw, uint64_t lwm)
{
	atomic_fetch_or_explicit(lw, lwm, memory_order_relaxed);
}

static inline void
caprev_shadow_clear_w(_Atomic(uint64_t) * __capability w, uint64_t m)
{
	atomic_fetch_and_explicit(w, m, memory_order_relaxed);
}
