#pragma once

static inline uint64_t
caprev_shadow_set_fw(uint64_t * __capability fw, void * __capability user_obj,
		     uint64_t fwm)
{
	uint64_t lshadow, scratch;
	uint64_t asmres = 1;

	__asm__ __volatile__ (
		"1:\n\t"
		// Load reserve first word
		"clr.d %[lshadow], (%[fw])\n\t"

		// Jump out if shadow set
		"and %[scratch], %[lshadow], %[fwm]\n\t"
		"bnez %[scratch], 2f\n\t"

		// Jump out if object detagged
		"cgettag %[scratch], %[obj]\n\t"
		"beqz %[scratch], 2f\n\t"

		// Jump out if zero perms
		"cgetperm %[scratch], %[obj]\n\t"
		"beqz %[scratch], 2f\n\t"

		// bitwise or in the mask
		"or %[lshadow], %[lshadow], %[fwm]\n\t"

		// SC the updated mask
		"csc.d %[asmres], %[lshadow], (%[fw])\n\t"
		"bnez %[asmres], 1b\n\t"
		"2:\n\t"
	: // outputs
		[asmres] "+&r" (asmres),
		[lshadow] "=&r" (lshadow),
		[scratch] "=&r" (scratch)
	: // inputs
		[obj] "C" (user_obj),
		[fw] "C" (fw),
		[fwm] "r" (fwm)
	: // clobbers
		"memory"
	);

	return (asmres == 0);
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
