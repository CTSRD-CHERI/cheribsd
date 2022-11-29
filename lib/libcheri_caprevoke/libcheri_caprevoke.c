/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018-2020 Nathaniel Wesley Filardo <nwf20@cl.cam.ac.uk>
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
 * Revocation bitmap manipulation operations for allocators' use.
 */

#include <sys/endian.h>
#include <sys/param.h>

#include <cheri/cheric.h>
#include <cheri/revoke.h>

#include <assert.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libcaprevoke.h"
#include "libcaprevoke_md.h"

static ptrdiff_t caprev_shadow_nomap_first_word_offset(ptraddr_t base);
static ptrdiff_t caprev_shadow_nomap_last_word_offset(ptraddr_t base,
    size_t len);
static uint64_t caprev_shadow_nomap_first_word_mask(ptraddr_t base, size_t len);
static uint64_t caprev_shadow_nomap_last_word_mask(ptraddr_t base, size_t len);

/*
 * Given a base address of an object, derive the offset relative to the base
 * of the fine-grained bitmap where the first word would be located.
 */

static ptrdiff_t
caprev_shadow_nomap_first_word_offset(ptraddr_t base)
{
	return (ptrdiff_t)(
	    base / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8 / sizeof(uint64_t)) *
	    sizeof(uint64_t);
}

static ptrdiff_t
caprev_shadow_nomap_last_word_offset(ptraddr_t base, size_t len)
{
	if (len == 0)
		return caprev_shadow_nomap_first_word_offset(base);

	return (ptrdiff_t)((base + len - 1) / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8
	    / sizeof(uint64_t)) * sizeof(uint64_t);
}

/*
 * Derive the mask to be or'd in to the first word to mark the object's
 * bottom granules as revoked.
 */

static uint64_t
caprev_shadow_nomap_first_word_mask(ptraddr_t base, size_t len)
{
	uint64_t res;
	int lsb;

	/* What's the least significant bit's position within the word? */
	lsb = (base / VM_CHERI_REVOKE_GSZ_MEM_NOMAP) % (8 *
	    sizeof(uint64_t));

	if (caprev_shadow_nomap_first_word_offset(base) ==
	    caprev_shadow_nomap_last_word_offset(base, len)) {
		/* The object occupies only some bits in the first word */

		int setwidth = len / VM_CHERI_REVOKE_GSZ_MEM_NOMAP;

		if (lsb + setwidth == 64) {
			/* Object fills this word completely, but does not spill
			 * to the next */

			res = ~(((uint64_t)1 << lsb) - 1);
		} else {
			res = (~(((uint64_t)1 << (lsb + setwidth)) - 1) ^
			    (~(((uint64_t)1 << lsb) - 1)));
		}
	} else {
		/* The object runs off the end of this word. */

		res = ~(((uint64_t)1 << lsb) - 1);
	}

	return (htole64(res));
}

static uint64_t
caprev_shadow_nomap_last_word_mask(ptraddr_t base, size_t len)
{
	uint64_t res;
	int msb;

	if (caprev_shadow_nomap_first_word_offset(base) ==
	    caprev_shadow_nomap_last_word_offset(base, len)) {

		/*
		 * There are no more bits to set that haven't been taken care of
		 * by the the first word, so just return 0.
		 */

		return 0;
	}

	msb = ((base + len - 1) / VM_CHERI_REVOKE_GSZ_MEM_NOMAP) %
	    (8 * sizeof(uint64_t));

	if (msb == 63) {
		/* This object runs to the end of its last word */

		return ~(uint64_t)0;
	}

	res = ((uint64_t)1 << (msb + 1)) - 1;

	return (htole64(res));
}

/*
 * Exposed for testing, but hopefully inlined into the actual update
 * functions below.
 *
 * XXX Slightly less polluting of the external namespace than having all four
 * functions available, maybe?
 */
void
caprev_shadow_nomap_offsets(
    ptraddr_t ob, size_t len, ptrdiff_t *fwo, ptrdiff_t *lwo)
{
	*fwo = caprev_shadow_nomap_first_word_offset(ob);
	*lwo = caprev_shadow_nomap_last_word_offset(ob, len);
}

void
caprev_shadow_nomap_masks(ptraddr_t ob, size_t len, uint64_t *fwm,
    uint64_t *lwm)
{
	*fwm = caprev_shadow_nomap_first_word_mask(ob, len);
	*lwm = caprev_shadow_nomap_last_word_mask(ob, len);
}

/*
 * A helper function for some things both setting and clearing shadow masks
 * need up front.
 */
static inline void
caprev_shadow_nomap_common_pfx(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t ob, size_t len, ptrdiff_t *fwo, ptrdiff_t *lwo,
    uint64_t * __capability *fw)
{
	caprev_shadow_nomap_offsets(ob, len, fwo, lwo);
	*fw = cheri_setaddress(sb, sbase + *fwo);
}

/*
 * Mark an object for revocation using the indicated capability to the
 * correct fragment of the shadow bitmap.
 *
 * The region of memory whose corresponding shadow space will be set is given
 * by a base vaddr ob and a length len. The "user" object capability is
 * expected to govern a subset of this region and, importantly, must be
 * subject to revocation; it is used to guard against double-frees. The two
 * are provided separately because the bounds of the "user" capability may
 * have been shrunk so that they do not cover the entire underlying allocation.
 *
 * The masks here are additive: they're going to be OR'd with the shadow.
 *
 * Returns 0 on success or 1 if the calling free() should skip this
 * capability, as it has either become de-tagged or is at least partially
 * already marked in the bitmap (as might happen, for example, with a
 * racing second call to free on the same pointer).
 */
int
caprev_shadow_nomap_set_len(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t ob, size_t len, void * __capability user_obj)
{
	ptrdiff_t fwo, lwo;
	uint64_t * __capability fw;
	uint64_t fwm;

	caprev_shadow_nomap_common_pfx(sbase, sb, ob, len, &fwo, &lwo, &fw);

	fwm = caprev_shadow_nomap_first_word_mask(ob, len);

	/*
	 * The first word is tricky to handle, since we use it to gate frees,
	 * ensuring that double-frees are idempotent.  There are three reasons
	 * we might bail out:
	 *
	 *   - another thread has quarantined this object (bits already set)
	 *
	 *   - this object is detagged
	 *
	 *   - this object has been revoked while we held a pointer to it in
	 *   free() (and so its permissions have been stripped; see
	 * cheri_revoke)
	 *
	 * We have to check the permissions inside the ll/sc we use to update
	 * the shadow bitmask so that we interlock against the stop-the-world
	 * (and maybe read-side) phases of revocation.
	 *
	 * It's possible the SC fails for neither of the above reasons, of
	 * course, not the least of which is that a concurrent thread might be
	 * mutating the shadow.  In that case, just go around again.
	 *
	 * We're going to do this dance with some inline assembler hidden behind
	 * a veneer of abstraction, because it's a little much to expect of C.
	 */
	if (!caprev_shadow_set_fw(fw, user_obj, fwm)) {
		return 1;
	}

	if (lwo != fwo) {
		uint64_t * __capability lw;
		uint64_t lwm;
		uint64_t * __capability sbo;
		ptrdiff_t wo;

		/*
		 * If this object straddles a word boundary, the first and last
		 * word offets will not be equal; the last word might also need
		 * special handling.
		 */

		lw = cheri_setaddress(sb, sbase + lwo);
		lwm = caprev_shadow_nomap_last_word_mask(ob, len);

		/*
		 * We might overlap a concurrent object's attempt to mutate bits
		 * in the last word, so do the OR atomically unless we're
		 * setting the whole word, in which case, the write cannot
		 * possibly race.
		 */

		if (lwm != ~(uint64_t)0) {
			caprev_shadow_set_lw(
			    (_Atomic(uint64_t) * __capability)lw, lwm);
		} else {
			*lw = ~(uint64_t)0;
		}

		/*
		 * Any words between the first and last we can just set all at
		 * once; there's nothing else to see here.
		 */

		wo = fwo + sizeof(uint64_t);
		sbo = fw + 1;
		for (; wo < lwo; wo += sizeof(uint64_t), sbo++) {
			*sbo = ~(uint64_t)0;
		}
	}

	/*
	 * There is no need to store-barrier or any such here; we can enforce
	 * store order before grabbing the epoch clock for this *chunk* of the
	 * quarantine. By ensuring that we make all cores aware of our bits
	 * before looking at the clock, we guarantee that the revocation
	 * epoch(s) upon which we are waiting will be done with at least our
	 * stores visible.
	 */

	return 0;
}

/*
 * Mark an object for revocation using the indicated capability to the
 * correct fragment of the shadow bitmap.
 *
 * The "privileged" object capability is expected to point to the full,
 * actual bounds of the allocation and may (or may not) be subject to
 * revocation; this capability determines which bits of the bitmap are in
 * scope for changes.  The "user" object capability is expected to be a
 * subset of the privileged object capability and, importantly, must be
 * subject to revocation; this capability is used to guard against
 * double-frees.  The two are provided separately to remove from the
 * allocator the need to construct the privileged capability while
 * respecting (concurrently mutable!) tagged-ness of the user capability.
 *
 * The masks here are additive: they're going to be OR'd with the shadow.
 *
 * Returns 0 on success or 1 if the calling free() should skip this
 * capability, as it has either become de-tagged or is at least partially
 * already marked in the bitmap (as might happen, for example, with a
 * racing second call to free on the same pointer).
 */
int
caprev_shadow_nomap_set(ptraddr_t sbase, uint64_t * __capability sb,
    void * __capability priv_obj, void * __capability user_obj)
{
	return caprev_shadow_nomap_set_len(sbase, sb,
	    (__cheri_addr ptraddr_t)priv_obj, cheri_getlen(priv_obj), user_obj);
}

/*
 * Clear a region from the shadow bitmap.
 *
 * The masks here are subtractive: they're going to be AND'd with the shadow.
 */
void
caprev_shadow_nomap_clear_len(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t ob, size_t len)
{
	ptrdiff_t fwo, lwo;
	uint64_t * __capability fw;
	uint64_t fwm;

	caprev_shadow_nomap_common_pfx(sbase, sb, ob, len, &fwo, &lwo, &fw);

	fwm = ~caprev_shadow_nomap_first_word_mask(ob, len);

	/*
	 * The first word must be handled atomically, so that it interlocks
	 * with the atomic manipulation in caprev_shadow_nomap_set.
	 */
	caprev_shadow_clear_w((_Atomic(uint64_t) * __capability)fw, fwm);

	if (lwo != fwo) {
		uint64_t * __capability lw;
		uint64_t lwm;
		uint64_t * __capability sbo;
		ptrdiff_t wo;

		lw = cheri_setaddress(sb, sbase + lwo);
		lwm = ~caprev_shadow_nomap_last_word_mask(ob, len);

		/*
		 * The last word may also need to be handled atomically.
		 */
		if (lwm != 0) {
			caprev_shadow_clear_w(
			    (_Atomic(uint64_t) * __capability)lw, lwm);
		} else {
			*lw = 0;
		}

		/*
		 * Any words between the first and last we can just clear all at
		 * once.
		 */

		wo = fwo + sizeof(uint64_t);
		sbo = fw + 1;
		for (; wo < lwo; wo += sizeof(uint64_t), sbo++) {
			*sbo = (uint64_t)0;
		}
	}

	/*
	 * There is no need to store-barrier or any such here either.  It
	 * suffices to store-barrier at the end of whatever set of objects is
	 * being cleared from the shadow, before those objects may be released
	 * to the application.
	 */
}

/*
 * Clear an object from the shadow bitmap.
 *
 * The masks here are subtractive: they're going to be AND'd with the shadow.
 */
void
caprev_shadow_nomap_clear(ptraddr_t sbase, uint64_t * __capability sb,
    void * __capability obj)
{
	return caprev_shadow_nomap_clear_len(sbase, sb,
	    (__cheri_addr ptraddr_t)obj, cheri_getlen(obj));
}

/*
 * The "raw" interfaces presume that all interlocking has already been
 * managed by the caller and so contain no atomics or such.
 *
 * This requires that the caller be managing regions of the address space
 * inclusive of all 64-bit words that will be manipulated here.  Assuming
 * one bit per 16 bytes, this corresponds to 1Ki-aligned regions of the
 * address space, almost certainly smaller than an architectural page,
 * likely a divisor of the units of management by the caller.
 */
void
caprev_shadow_nomap_set_raw(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t heap_start, ptraddr_t heap_end)
{
	ptrdiff_t fwo, lwo;
	uint64_t * __capability fw;
	size_t len = heap_end - heap_start;

	caprev_shadow_nomap_offsets(heap_start, len, &fwo, &lwo);

	fw = cheri_setaddress(sb, sbase + fwo);
	*fw |= caprev_shadow_nomap_first_word_mask(heap_start, len);

	if (lwo != fwo) {
		uint64_t * __capability w = fw + 1;
		ptrdiff_t wo = fwo + sizeof(uint64_t);
		w = fw + 1;
		for (; wo < lwo; wo += sizeof(uint64_t), w++) {
			*w = ~(uint64_t)0;
		}

		w = cheri_setaddress(sb, sbase + lwo);
		*w |= caprev_shadow_nomap_last_word_mask(heap_start, len);
	}
}

void
caprev_shadow_nomap_clear_raw(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t heap_start, ptraddr_t heap_end)
{
	ptrdiff_t fwo, lwo;
	uint64_t * __capability fw;
	size_t len = heap_end - heap_start;

	caprev_shadow_nomap_offsets(heap_start, len, &fwo, &lwo);

	fw = cheri_setaddress(sb, sbase + fwo);
	*fw &= ~caprev_shadow_nomap_first_word_mask(heap_start, len);

	if (lwo != fwo) {
		uint64_t * __capability w = fw + 1;
		ptrdiff_t wo = fwo + sizeof(uint64_t);
		w = fw + 1;
		for (; wo < lwo; wo += sizeof(uint64_t), w++) {
			*w = 0;
		}

		w = cheri_setaddress(sb, sbase + lwo);
		*w &= ~caprev_shadow_nomap_last_word_mask(heap_start, len);
	}
}
