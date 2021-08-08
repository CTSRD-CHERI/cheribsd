/*-
 * Copyright (c) 2015 The FreeBSD Foundation
 *
 * This software was developed by Andrew Turner under
 * sponsorship from the FreeBSD Foundation.
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
 *
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#include <sys/errno.h>

#include <machine/vmparam.h>

#include "assym.inc"

.macro check_user_access user_arg, size_arg, bad_access_func
#if __has_feature(capabilities)
	gcvalue	x7, c\user_arg		/* Read the user capability value */
	adds	x6, x7, x\size_arg
#else
	adds	x6, x\user_arg, x\size_arg
#endif
	b.cs	\bad_access_func
	ldr	x7, =VM_MAXUSER_ADDRESS
	cmp	x6, x7
	b.hi	\bad_access_func
.endm

/*
 * Fault handler for the copy{in,out} functions below.
 */
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	.arch_extension	c64
#endif
ENTRY(copyio_c64_fault)
	EXIT_C64
EENTRY(copyio_fault)
	SET_FAULT_HANDLER(xzr, PTR(1)) /* Clear the handler */
	EXIT_USER_ACCESS_CHECK(w0, PTR(1))
copyio_fault_nopcb:
	mov	x0, #EFAULT
	ret
EEND(copyio_fault)
END(copyio_c64_fault)

/*
 * Copies from a kernel to user address
 *
 * int copyout(const void *kaddr, void * __capability udaddr, size_t len)
 */
ENTRY(copyout)
	cbz	x2, 1f
	check_user_access 1, 2, copyio_fault_nopcb

#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cvtd	c0, x0			/* Store through a capability */
	scbnds	c0, c0, x2		/* Set the bounds */
#endif
	b	copycommon

1:	mov	x0, xzr		/* return 0 */
	ret

END(copyout)

/*
 * Copies from a user to kernel address
 *
 * int copyin(const void * __capability uaddr, void *kdaddr, size_t len)
 */
ENTRY(copyin)
	cbz	x2, 1f
	check_user_access 0, 2, copyio_fault_nopcb

#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cvtd	c1, x1			/* Store through a capability */
	scbnds	c1, c1, x2		/* Set the bounds */
#endif

	b	copycommon

1:	mov	x0, xzr		/* return 0 */
	ret

END(copyin)

/*
 * Copies a string from a user to kernel address
 *
 * int copyinstr(const void * __capability udaddr, void *kaddr, size_t len,
 *         size_t *done)
 */
ENTRY(copyinstr)
	mov	x5, xzr		/* count = 0 */
	mov	w4, #1		/* If zero return faulure */
	cbz	x2, 3f		/* If len == 0 then skip loop */

#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cvtd	c1, x1			/* Store through a capability */
	scbnds	c1, c1, x2		/* Set the bounds */
#endif

	adr	PTR(6), copyio_fault /* Get the handler address */
	SET_FAULT_HANDLER(PTR(6), PTR(7)) /* Set the handler */

	ldr	x7, =VM_MAXUSER_ADDRESS
	ENTER_C64
1:
#if __has_feature(capabilities)
	gcvalue	x9, c0
	cmp	x9, x7
#else
	cmp	x0, x7
#endif
	b.cs	copyio_c64_fault
#if __has_feature(capabilities)
	ldtrb	w4, [c0]	/* Load from uaddr */
	add	c0, c0, #1	/* Next char */
	strb	w4, [c1], #1	/* Store in kaddr */
#else
	ldtrb	w4, [x0]	/* Load from uaddr */
	add	x0, x0, #1	/* Next char */
	strb	w4, [x1], #1	/* Store in kaddr */
#endif
	add	x5, x5, #1	/* count++ */
	cbz	w4, 2f		/* Break when NUL-terminated */
	sub	x2, x2, #1	/* len-- */
	cbnz	x2, 1b

2:	EXIT_C64
	SET_FAULT_HANDLER(xzr, PTR(7)) /* Clear the handler */


3:	cbz	x3, 4f		/* Check if done != NULL */
	str	x5, [PTR(3)]	/* done = count */

4:	mov	w1, #ENAMETOOLONG /* Load ENAMETOOLONG to return if failed */
	cmp	w4, #0		/* Check if we saved the NUL-terminator */
	csel	w0, wzr, w1, eq	/* If so return success, else failure */
	ret
END(copyinstr)

#if !__has_feature(capabilities)
/*
 * Local helper
 *
 * x0 - src pointer
 * x1 - dst pointer
 * x2 - size
 * lr - the return address, so jump here instead of calling
 *
 * This function is optimized to minimize concurrent memory accesses. In
 * present form it is suited for cores with a single memory prefetching
 * unit.
 * ARM64TODO: 
 *   Consider using separate functions for each ARM64 core. Adding memory
 *   access interleaving might increase a total throughput on A57 or A72.
 */
	.text
	.align	4
	.local	copycommon
	.type	copycommon,@function

copycommon:
	adr	x6, copyio_fault /* Get the handler address */
	SET_FAULT_HANDLER(x6, x7) /* Set the handler */
	ENTER_USER_ACCESS(w6, x7)

	/* Check alignment */
	orr	x3, x0, x1
	ands	x3, x3, 0x07
	b.eq	aligned

	/* Unaligned is byte by byte copy */
byte_by_byte:
	ldrb	w3, [x0], #0x01
	strb	w3, [x1], #0x01
	subs	x2, x2, #0x01
	b.ne	byte_by_byte
	b	ending

aligned:
	cmp	x2, #0x10
	b.lt	lead_out
	cmp	x2, #0x40
	b.lt	by_dwords_start

	/* Block copy */
	lsr	x15, x2, #0x06
by_blocks:
	ldp	x3, x4, [x0], #0x10
	ldp	x5, x6, [x0], #0x10
	ldp	x7, x8, [x0], #0x10
	ldp	x9, x10, [x0], #0x10
	stp	x3, x4, [x1], #0x10
	stp	x5, x6, [x1], #0x10
	stp	x7, x8, [x1], #0x10
	stp	x9, x10, [x1], #0x10

	subs	x15, x15, #0x01
	b.ne	by_blocks

	and	x2, x2, #0x3f

by_dwords_start:
	lsr	x15, x2, #0x04
	cbz	x15, lead_out
by_dwords:
	ldp	x3, x4, [x0], #0x10
	stp	x3, x4, [x1], #0x10
	subs	x15, x15, #0x01
	b.ne  	by_dwords

	/* Less than 16 bytes to copy */
lead_out:
	tbz	x2, #0x03, last_word
	ldr	x3, [x0], #0x08
	str	x3, [x1], #0x08

last_word:
	tbz	x2, #0x02, last_hword
	ldr	w3, [x0], #0x04
	str	w3, [x1], #0x04

last_hword:
	tbz	x2, #0x01, last_byte
	ldrh	w3, [x0], #0x02
	strh	w3, [x1], #0x02

last_byte:
	tbz	x2, #0x00, ending
	ldrb	w3, [x0]
	strb	w3, [x1]

ending:
	EXIT_USER_ACCESS_CHECK(w6, x7)
	SET_FAULT_HANDLER(xzr, x7) /* Clear the handler */

	mov	x0, xzr		/* return 0 */
	ret
	.size	copycommon, . - copycommon
#endif /* !__has_feature(capabilities) */

#if __has_feature(capabilities)
/*
 * Copy specified amount of data from the user to kernel space, preserving
 * capability tags
 *
 * int copyincap(const void * __capability uaddr, void *kdaddr, size_t len)
 */
ENTRY(copyincap)
	cbz	x2, 1f
	check_user_access 0, 2, copyio_fault_nopcb

	/* Create a capability from kdaddr */
#ifndef __CHERI_PURE_CAPABILITY__
	cvtd	c1, x1			/* Store through a capability */
	scbnds	c1, c1, x2		/* Set the bounds */
#endif

	/* Check the length is greater than 1 capability */
	cmp	x2, #16
	b.lo	copycommon

	/* And the addresses will both align on a capability */
	gcvalue	x6, c0			/* Get uaddr's address */
	eor	x3, x1, x6		/* Compare the addresses */
	and	x3, x3, #0xf		/* Check the lower bits */
	cbnz	x3, copycommon		/* If different don't copy tags */

	b	copycapcommon

1:	mov	x0, xzr		/* return 0 */
	ret
END(copyincap)

/*
 * Copy specified amount of data from kernel to the user space, preserving
 * capability tags
 *
 * int copyoutcap(const void *kaddr, void * __capability udaddr, size_t len)
 */
ENTRY(copyoutcap)
	cbz	x2, 1f
	check_user_access 1, 2, copyio_fault_nopcb

	/* Create a capability from kaddr */
#ifndef __CHERI_PURE_CAPABILITY__
	cvtd	c0, x0			/* Store through a capability */
	scbnds	c0, c0, x2		/* Set the bounds */
#endif

	/* Check the length is greater than 1 capability */
	cmp	x2, #16
	b.lo	copycommon

	/* And the addresses will both align on a capability */
	gcvalue	x6, c1			/* Get uaddr's address */
	eor	x3, x0, x6		/* Compare the addresses */
	and	x3, x3, #0xf		/* Check the lower bits */
	cbnz	x3, copycommon		/* If different don't copy tags */

	b	copycapcommon

1:	mov	x0, xzr		/* return 0 */
	ret
END(copyoutcap)

/*
 * Local helpers to copy through capabilities
 *
 * c0 - src pointer
 * c1 - dst pointer
 * x2 - size
 * lr - the return address, so jump here instead of calling
 *
 * In copycapcommon the bottom 4 bits of c0 and c1 must be identical so
 * they can both be aligned load & store capabilities, and size must be at
 * least one capability; if not, copycommon must be used instead, and will copy
 * dwords at a time when posible.
 */
	.text
	.align	4
	.local	copycapcommon
	.type	copycapcommon,@function

copycapcommon:
	adr	PTR(6), copyio_fault	/* Get the handler address */
	SET_FAULT_HANDLER(PTR(6), PTR(7))	/* Set the handler */
	ENTER_USER_ACCESS(w6, PTR(7))

	mov	x5, #0			/* x5 is the offset to load/store */

	/*
	 * We require c0 and c1 to have the same lower bits so need only check
	 * one of them.
	 */
	gcvalue	x3, c0
	and	x3, x3, #0x0f
	cbz	x3, copycap_main	/* Already capability-aligned, skip ahead */

	/* Byte copy until the first capability-aligned address */
copycap_byte_by_byte:
	ldrb	w4, [c0, x5]		/* Load byte from src */
	strb	w4, [c1, x5]		/* Store byte in dest */
	sub	x2, x2, #1		/* len-- */
	add	x3, x3, #1		/* cap_off++ */
	add	x5, x5, #1		/* off++ */
	cmp	x3, #16
	b.lt	copycap_byte_by_byte	/* Again if cap_off < 16 */

	/* Copy capabilities */
copycap_main:
	cmp	x2, #16
	b.lo	copycap_end_bytes
1:	ldr	c4, [c0, x5]		/* Load dword from src */
	str	c4, [c1, x5]		/* Store dword in dest */
	sub	x2, x2, #16		/* len -= 16 */
	add	x5, x5, #16		/* off += 16 */
	cmp	x2, #16
	b.ge	1b			/* Again if len >= 16 */

	/* Check if we're finished */
	cbz	x2, copycap_done

	/* Copy any remaining bytes */
copycap_end_bytes:
	ldrb	w3, [c0, x5]		/* Load byte from src */
	strb	w3, [c1, x5]		/* Store byte in dest */
	sub	x2, x2, #1		/* len-- */
	add	x5, x5, #1		/* off++ */
	cbnz	x2, copycap_end_bytes

copycap_done:
	EXIT_USER_ACCESS(w6)
	SET_FAULT_HANDLER(xzr, PTR(7))	/* Clear the handler */

	mov	x0, xzr			/* Return 0 */
	ret
	.size	copycapcommon, . - copycapcommon

	.text
	.align	4
	.local	copycommon
	.type	copycommon,@function

copycommon:
	adr	PTR(6), copyio_fault	/* Get the handler address */
	SET_FAULT_HANDLER(PTR(6), PTR(7))	/* Set the handler */
	ENTER_USER_ACCESS(w6, PTR(7))

	mov	x5, #0			/* x5 is the offset to load/store */

	/* Copy words */
copy_main:
	cmp	x2, #8
	b.lo	copy_end_bytes
1:	ldr	x4, [c0, x5]		/* Load dword from src */
	str	x4, [c1, x5]		/* Store dword in dest */
	sub	x2, x2, #8		/* len -= 8 */
	add	x5, x5, #8		/* off += 8 */
	cmp	x2, #8
	b.ge	1b			/* Again if len >= 8 */

	/* Check if we're finished */
	cbz	x2, copy_done

	/* Copy any remaining bytes */
copy_end_bytes:
	ldrb	w3, [c0, x5]		/* Load byte from src */
	strb	w3, [c1, x5]		/* Store byte in dest */
	sub	x2, x2, #1		/* len-- */
	add	x5, x5, #1		/* off++ */
	cbnz	x2, copy_end_bytes

copy_done:
	EXIT_USER_ACCESS(w6)
	SET_FAULT_HANDLER(xzr, PTR(7))	/* Clear the handler */

	mov	x0, xzr			/* Return 0 */
	ret
	.size	copycommon, . - copycommon
#endif
