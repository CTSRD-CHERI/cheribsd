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
		"lr.d.cap %[lshadow], (%[fw])\n\t"

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
		"or %[asmres], %[lshadow], %[fwm]\n\t"

		// SC the updated mask
		"sc.d.cap %[asmres], (%[fw])\n\t"
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
	uint64_t scratch;

	__asm__ __volatile__ (
		"1:\n\t"
		"lr.d.cap %[scratch], (%[fw])\n\t"
		"or %[scratch], %[scratch], %[fwm]\n\t"
		"sc.d.cap %[scratch], (%[fw])\n\t"
		"beqz %[scratch], 1b\n\t"
	: // outputs
		[scratch] "=&r" (scratch)
	: // inputs
		[fw] "C" (lw),
		[fwm] "r" (lwm)
	: // clobbers
		"memory"
	);
}

static inline void
caprev_shadow_clear_w(_Atomic(uint64_t) * __capability w, uint64_t wm)
{
	uint64_t scratch;

	__asm__ __volatile__ (
		"1:\n\t"
		"lr.d.cap %[scratch], (%[w])\n\t"
		"and %[scratch], %[scratch], %[wm]\n\t"
		"sc.d.cap %[scratch], (%[w])\n\t"
		"beqz %[scratch], 1b\n\t"
	: // outputs
		[scratch] "=&r" (scratch)
	: // inputs
		[w] "C" (w),
		[wm] "r" (wm)
	: // clobbers
		"memory"
	);
}
