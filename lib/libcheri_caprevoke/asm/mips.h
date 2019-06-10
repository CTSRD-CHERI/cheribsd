#pragma once

static inline uint64_t
caprev_shadow_set_fw(
    uint64_t * __capability fw, void * __capability user_obj, uint64_t fwm)
{
	uint64_t lshadow, scratch;
	uint64_t asmres = 0;

	__asm__ __volatile__ (
		".set push\n\t"
		".set noreorder\n\t"
		"1:\n\t"
		// Load linked the first word
		"clld %[lshadow], %[fw]\n\t"

		// Jump out if shadow set
		"and %[scratch], %[lshadow], %[fwm]\n\t"
		"bnez %[scratch], 2f\n\t"
		"nop\n\t" // [delay slot fill]

		// Jump out if object detagged
		"cbtu %[obj], 2f\n\t"

		// Jump out if perms 0 [in delay slot]
		"cgetperm %[scratch], %[obj]\n\t"
		"beqz %[scratch], 2f\n\t"

		// bitwise or in mask [in delay slot]
		"or %[lshadow], %[lshadow], %[fwm]\n\t"

		// SC the updated mask, go again if fail
		"cscd %[asmres], %[lshadow], %[fw]\n\t"
		"beqz %[asmres], 1b\n\t"
		"nop\n\t" // [delay slot fill]

		"2:\n\t"
		".set pop\n\t"
	: // output operands
		[asmres] "+&r" (asmres),
		[lshadow] "=&r" (lshadow),
		[scratch] "=&r" (scratch)
	: // input operands
		[obj] "C" (user_obj),
		[fw] "C" (fw),
		[fwm] "r" (fwm)
	: // clobbers
		"memory"
	);

	return (asmres != 0);
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
