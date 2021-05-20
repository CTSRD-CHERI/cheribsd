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
		// Load reserve first word
		"ldxr %[lshadow], [%[fw]]\n\t"

		// Jump out if shadow set
		"ands %[scratch], %[lshadow], %[fwm]\n\t"
		"bne 2f\n\t"

		// Jump out if object detagged
		"gctag %[scratch], %[obj]\n\t"
		"cbz %[scratch], 2f\n\t"

		// Jump out if zero perms
		"gcperm %[scratch], %[obj]\n\t"
		"cbz %[scratch], 2f\n\t"

		// bitwise or in the mask
		"orr %[lshadow], %[lshadow], %[fwm]\n\t"

		// SC the updated mask - status nonzero on failure
		"stxr %w[stxr_status], %[lshadow], [%[fw]]\n\t"
		"cbnz %w[stxr_status], 1b\n\t"
		"2:\n\t"
#ifndef __CHERI_PURE_CAPABILITY__
		"bx #4\n\t"
		".arch_extension noc64\n\t"
		".arch_extension a64c\n\t"
#endif
	: // outputs
		[stxr_status] "+&r" (stxr_status),
		[lshadow] "=&r" (lshadow),
		[scratch] "=&r" (scratch)
	: // inputs
		[obj] "C" (user_obj),
		[fw] "C" (fw),
		[fwm] "r" (fwm)
	: // clobbers
		"memory"
	);

	return (stxr_status == 0);
}

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
