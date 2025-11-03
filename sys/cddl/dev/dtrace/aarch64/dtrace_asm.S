/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define _ASM
#define _LOCORE

#include <sys/cpuvar_defs.h>
#include <sys/dtrace.h>
#include <sys/elf_common.h>

#include <machine/armreg.h>
#include <machine/asm.h>

#include "assym.inc"

/*
void dtrace_membar_producer(void)
*/
ENTRY(dtrace_membar_producer)
	RET
END(dtrace_membar_producer)

/*
void dtrace_membar_consumer(void)
*/
ENTRY(dtrace_membar_consumer)
	RET
END(dtrace_membar_consumer)

/*
dtrace_icookie_t dtrace_interrupt_disable(void)
*/
ENTRY(dtrace_interrupt_disable)
	mrs	x0, daif
	msr	daifset, #2
	RET
END(dtrace_interrupt_disable)

/*
void dtrace_interrupt_enable(dtrace_icookie_t cookie)
*/
ENTRY(dtrace_interrupt_enable)
	msr	daif, x0
	RET
END(dtrace_interrupt_enable)
/*
uint8_t
dtrace_fuword8_nocheck(void *addr)
*/
ENTRY(dtrace_fuword8_nocheck)
#if __has_feature(capabilities)
	ENTER_C64
	ldtrb	w0, [c0]
	EXIT_C64
#else
	ldtrb	w0, [x0]
#endif
	RET
END(dtrace_fuword8_nocheck)

/*
uint16_t
dtrace_fuword16_nocheck(void *addr)
*/
ENTRY(dtrace_fuword16_nocheck)
#if __has_feature(capabilities)
	ENTER_C64
	ldtrh	w0, [c0]
	EXIT_C64
#else
	ldtrh	w0, [x0]
#endif
	RET
END(dtrace_fuword16_nocheck)

/*
uint32_t
dtrace_fuword32_nocheck(void *addr)
*/
ENTRY(dtrace_fuword32_nocheck)
#if __has_feature(capabilities)
	ENTER_C64
	ldtr	w0, [c0]
	EXIT_C64
#else
	ldtr	w0, [x0]
#endif
	RET
END(dtrace_fuword32_nocheck)

/*
uint64_t
dtrace_fuword64_nocheck(void *addr)
*/
ENTRY(dtrace_fuword64_nocheck)
#if __has_feature(capabilities)
	ENTER_C64
	ldtr	x0, [c0]
	EXIT_C64
#else
	ldtr	x0, [x0]
#endif
	RET
END(dtrace_fuword64_nocheck)

#if __has_feature(capabilities)
/*
uintptr_t
dtrace_fuwordcap_nocheck(void *addr)
*/
ENTRY(dtrace_fucap_nocheck)
	ENTER_C64
	ldtr	c0, [c0]
	EXIT_C64
	RET
END(dtrace_fucap_nocheck)
#endif

/*
void
dtrace_copy(uintptr_t uaddr, uintptr_t kaddr, size_t size)
*/
ENTRY(dtrace_copy)
	cbz	x2, 2f		/* If len == 0 then skip loop */
	ENTER_C64
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cvtd	c1, x1			/* Store through a capability */
	scbnds	c1, c1, x2		/* Set the bounds */
#endif
1:
#if __has_feature(capabilities)
	ldtrb	w4, [c0]	/* Load from uaddr */
	add	c0, c0, #1
	strb	w4, [c1], #1	/* Store in kaddr */
#else
	ldtrb	w4, [x0]	/* Load from uaddr */
	add	x0, x0, #1
	strb	w4, [x1], #1	/* Store in kaddr */
#endif
	sub	x2, x2, #1	/* len-- */
	cbnz	x2, 1b
2:
	EXIT_C64
	RET
END(dtrace_copy)

/*
void
dtrace_copystr(uintptr_t uaddr, uintptr_t kaddr, size_t size,
    volatile uint16_t *flags)
XXX: Check for flags?
*/
ENTRY(dtrace_copystr)
	cbz     x2, 2f          /* If len == 0 then skip loop */
	ENTER_C64
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cvtd	c1, x1			/* Store through a capability */
	scbnds	c1, c1, x2		/* Set the bounds */
#endif
1:
#if __has_feature(capabilities)
	ldtrb	w4, [c0]	/* Load from uaddr */
	add	c0, c0, #1
	strb    w4, [c1], #1    /* Store in kaddr */
#else
	ldtrb	w4, [x0]	/* Load from uaddr */
	add	x0, x0, #1
	strb    w4, [x1], #1    /* Store in kaddr */
#endif
	cbz     w4, 2f          /* If == 0 then break */
	sub     x2, x2, #1      /* len-- */
	cbnz    x2, 1b
2:
	EXIT_C64
	RET
END(dtrace_copystr)

/*
uintptr_t
dtrace_caller(int aframes)
*/
ENTRY(dtrace_caller)
	mov	x0, #-1
	RET
END(dtrace_caller)

/*
uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
*/
ENTRY(dtrace_cas32)
1:	ldxr	w3, [PTR(0)]	/* Load target */
	cmp	w3, w1		/* Check if *target == cmp */
	bne	2f		/* No, return */
	stxr	w12, w2, [PTR(0)] /* Store new to target */
	cbnz	w12, 1b		/* Try again if store not succeed */
2:	mov	w0, w3		/* Return the value loaded from target */
	RET
END(dtrace_cas32)

/*
void *
dtrace_casptr(volatile void *target, volatile void *cmp, volatile void *new)
*/
ENTRY(dtrace_casptr)
1:	ldxr	PTR(3), [PTR(0)]	/* Load target */
	cmp	PTR(3), PTR(1)		/* Check if *target == cmp */
	bne	2f			/* No, return */
	stxr	w12, PTR(2), [PTR(0)]	/* Store new to target */
	cbnz	w12, 1b			/* Try again if store not succeed */
2:	mov	PTR(0), PTR(3)		/* Return the value loaded from target */
	RET
END(dtrace_casptr)

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
