/*-
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * Copyright (c) 2019 Mitchell Horne
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#include <machine/riscvreg.h>
#include <sys/errno.h>

#include "assym.inc"

/*
 * Hybrid kernels use .cap loads and stores whereas purecap kernels use
 * capmode loads and stores.
 */
#ifdef __CHERI_PURE_CAPABILITY__
#define	CLB		clb
#define	CSB		csb
#define	CLD		cld
#define	CSD		csd
#define	CLC		clc
#define	CSC		csc
#else
#define	CLB		lb.cap
#define	CSB		sb.cap
#define	CLD		ld.cap
#define	CSD		sd.cap
#define	CLC		lc.cap
#define	CSC		sc.cap
#endif

/*
 * Fault handler for the copy{in,out} functions below.
 */
ENTRY(copyio_fault)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca1)
#else
	SET_FAULT_HANDLER(x0, a1) /* Clear the handler */
#endif
	EXIT_USER_ACCESS(a1)
copyio_fault_nopcb:
	li	a0, EFAULT
	RETURN
END(copyio_fault)

/*
 * copycommon - common copy routine
 *
 * [c]a0 - Source address
 * [c]a1 - Destination address
 * a2 - Size of copy
 */
	.macro copycommon
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, copyio_fault	/* Get the handler address */
	SET_FAULT_HANDLER(ca6, ca7)	/* Set the handler */
#else
	la	a6, copyio_fault	/* Get the handler address */
	SET_FAULT_HANDLER(a6, a7)	/* Set the handler */
#endif
	ENTER_USER_ACCESS(a7)

	li	t2, XLEN_BYTES
	blt	a2, t2, 4f		/* Byte-copy if len < XLEN_BYTES */

	/*
	 * Compare lower bits of src and dest.
	 * If they are aligned with each other, we can do word copy.
	 */
	andi	t0, a0, (XLEN_BYTES-1)	/* Low bits of src */
	andi	t1, a1, (XLEN_BYTES-1)	/* Low bits of dest */
	bne	t0, t1, 4f		/* Misaligned. Go to byte copy */
	beqz	t0, 2f			/* Already word-aligned, skip ahead */

	/* Byte copy until the first word-aligned address */
1:
#if __has_feature(capabilities)
	CLB	a4, 0(ca0)		/* Load byte from src */
	cincoffset	ca0, ca0, 1
	CSB	a4, 0(ca1)		/* Store byte in dest */
	cincoffset	ca1, ca1, 1
#else
	lb	a4, 0(a0)		/* Load byte from src */
	addi	a0, a0, 1
	sb	a4, 0(a1)		/* Store byte in dest */
	addi	a1, a1, 1
#endif
	addi	a2, a2, -1		/* len-- */
	andi	t0, a0, (XLEN_BYTES-1)
	bnez	t0, 1b
	j	3f

	/* Copy words */
2:
#if __has_feature(capabilities)
	CLD	a4, 0(ca0)		/* Load word from src */
	cincoffset	ca0, ca0, XLEN_BYTES
	CSD	a4, 0(ca1)		/* Store word in dest */
	cincoffset	ca1, ca1, XLEN_BYTES
#else
	ld	a4, 0(a0)		/* Load word from src */
	addi	a0, a0, XLEN_BYTES
	sd	a4, 0(a1)		/* Store word in dest */
	addi	a1, a1, XLEN_BYTES
#endif
	addi	a2, a2, -XLEN_BYTES	/* len -= XLEN_BYTES */
3:	bgeu	a2, t2, 2b		/* Again if len >= XLEN_BYTES */

	/* Check if we're finished */
	beqz	a2, 5f

	/* Copy any remaining bytes */
4:
#if __has_feature(capabilities)
	CLB	a4, 0(ca0)		/* Load byte from src */
	cincoffset	ca0, ca0, 1
	CSB	a4, 0(ca1)		/* Store byte in dest */
	cincoffset	ca1, ca1, 1
#else
	lb	a4, 0(a0)		/* Load byte from src */
	addi	a0, a0, 1
	sb	a4, 0(a1)		/* Store byte in dest */
	addi	a1, a1, 1
#endif
	addi	a2, a2, -1		/* len-- */
	bnez	a2, 4b

5:	EXIT_USER_ACCESS(a7)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca7)	/* Clear the handler */
#else
	SET_FAULT_HANDLER(x0, a7)	/* Clear the handler */
#endif
	.endm

/*
 * Copies from a kernel to user address
 *
 * int copyout(const void *kaddr, void * __capability udaddr, size_t len)
 */
ENTRY(copyout)
	beqz	a2, copyout_end	/* If len == 0 then skip loop */
	add	a3, a1, a2
	li	a4, VM_MAXUSER_ADDRESS
	bgt	a3, a4, copyio_fault_nopcb

#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cspecialr	ca3, ddc
	csetoffset	ca3, ca3, a0
	csetbounds	ca0, ca3, a2
#endif

	copycommon

copyout_end:
	li	a0, 0		/* return 0 */
	RETURN
END(copyout)

/*
 * Copies from a user to kernel address
 *
 * int copyin(const void * __capability uaddr, void *kaddr, size_t len)
 */
ENTRY(copyin)
	beqz	a2, copyin_end	/* If len == 0 then skip loop */
	add	a3, a0, a2
	li	a4, VM_MAXUSER_ADDRESS
	bgt	a3, a4, copyio_fault_nopcb

#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cspecialr	ca3, ddc
	csetoffset	ca3, ca3, a1
	csetbounds	ca1, ca3, a2
#endif

	copycommon

copyin_end:
	li	a0, 0		/* return 0 */
	RETURN
END(copyin)



/*
 * Copies a string from a user to kernel address
 *
 * int copyinstr(const void * __capability udaddr, void *kaddr, size_t len,
 *	size_t *done)
 */
ENTRY(copyinstr)
	mv	a5, x0		/* count = 0 */
	beqz	a2, 3f		/* If len == 0 then skip loop */

#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, copyio_fault /* Get the handler address */
	SET_FAULT_HANDLER(ca6, ca7) /* Set the handler */
#else
	la	a6, copyio_fault /* Get the handler address */
	SET_FAULT_HANDLER(a6, a7) /* Set the handler */
#endif
	ENTER_USER_ACCESS(a7)

#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	cspecialr	ca4, ddc
	csetoffset	ca4, ca4, a1
	csetbounds	ca1, ca4, a2
#endif

	li	a7, VM_MAXUSER_ADDRESS
1:	bgt	a0, a7, copyio_fault
#if __has_feature(capabilities)
	CLB	a4, 0(ca0)	/* Load from uaddr */
	cincoffset	ca0, ca0, 1
	CSB	a4, 0(ca1)	/* Store in kaddr */
	cincoffset	ca1, ca1, 1
#else
	lb	a4, 0(a0)	/* Load from uaddr */
	addi	a0, a0, 1
	sb	a4, 0(a1)	/* Store in kaddr */
	addi	a1, a1, 1
#endif
	beqz	a4, 2f
	addi	a2, a2, -1	/* len-- */
	addi	a5, a5, 1	/* count++ */
	bnez	a2, 1b

2:	EXIT_USER_ACCESS(a7)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca7) /* Clear the handler */
#else
	SET_FAULT_HANDLER(x0, a7) /* Clear the handler */
#endif

3:	beqz	a3, 4f		/* Check if done != NULL */
	addi	a5, a5, 1	/* count++ */
#ifdef __CHERI_PURE_CAPABILITY__
	csd	a5, 0(ca3)	/* done = count */
#else
	sd	a5, 0(a3)	/* done = count */
#endif

4:	mv	a0, x0		/* return 0 */
	beqz	a4, 5f
	li	a0, ENAMETOOLONG
5:
	RETURN
END(copyinstr)

#if __has_feature(capabilities)
/*
 * copycapcommon - common capcopy routine
 *
 * ca0 - Source address
 * ca1 - Destination address
 * a2 - Size of copy
 */
	.macro copycapcommon
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ca6, copyio_fault	/* Get the handler address */
	SET_FAULT_HANDLER(ca6, ca7)	/* Set the handler */
#else
	la	a6, copyio_fault	/* Get the handler address */
	SET_FAULT_HANDLER(a6, a7)	/* Set the handler */
#endif
	ENTER_USER_ACCESS(a7)

	li	t2, CLEN_BYTES
	blt	a2, t2, 4f		/* Byte-copy if len < CLEN_BYTES */

	/*
	 * Compare lower bits of src and dest.
	 * If they are aligned with each other, we can do capability copy.
	 */
	andi	t0, a0, (CLEN_BYTES-1)	/* Low bits of src */
	andi	t1, a1, (CLEN_BYTES-1)	/* Low bits of dest */
	bne	t0, t1, 4f		/* Misaligned. Go to byte copy */
	beqz	t0, 2f			/* Already cap-aligned, skip ahead */

	/* Byte copy until the first capability-aligned address */
1:
	CLB	a4, 0(ca0)		/* Load byte from src */
	cincoffset	ca0, ca0, 1
	CSB	a4, 0(ca1)		/* Store byte in dest */
	cincoffset	ca1, ca1, 1
	addi	a2, a2, -1		/* len-- */
	andi	t0, a0, (CLEN_BYTES-1)
	bnez	t0, 1b
	j	3f

	/* Copy capabilities */
2:
	CLC	ca4, 0(ca0)		/* Load capability from src */
	cincoffset	ca0, ca0, CLEN_BYTES
	CSC	ca4, 0(ca1)		/* Store capability in dest */
	cincoffset	ca1, ca1, CLEN_BYTES
	addi	a2, a2, -CLEN_BYTES	/* len -= CLEN_BYTES */
3:	bgeu	a2, t2, 2b		/* Again if len >= CLEN_BYTES */

	/* Check if we're finished */
	beqz	a2, 5f

	/* Copy any remaining bytes */
4:
	CLB	a4, 0(ca0)		/* Load byte from src */
	cincoffset	ca0, ca0, 1
	CSB	a4, 0(ca1)		/* Store byte in dest */
	cincoffset	ca1, ca1, 1
	addi	a2, a2, -1		/* len-- */
	bnez	a2, 4b

5:	EXIT_USER_ACCESS(a7)
#ifdef __CHERI_PURE_CAPABILITY__
	SET_FAULT_HANDLER(cnull, ca7) /* Clear the handler */
#else
	SET_FAULT_HANDLER(x0, a7)	/* Clear the handler */
#endif
	.endm

/*
 * Copies from a kernel to user address preserving tags
 *
 * int copyoutcap(const void *kaddr, void * __capability udaddr, size_t len)
 */
ENTRY(copyoutcap)
	beqz	a2, copyoutcap_end	/* If len == 0 then skip loop */
	add	a3, a1, a2
	li	a4, VM_MAXUSER_ADDRESS
	bgt	a3, a4, copyio_fault_nopcb

#ifndef __CHERI_PURE_CAPABILITY__
	cspecialr	ca3, ddc
	csetoffset	ca3, ca3, a0
	csetbounds	ca0, ca3, a2
#endif

	copycapcommon

copyoutcap_end:
	li	a0, 0		/* return 0 */
	RETURN
END(copyoutcap)

/*
 * Copies from a user to kernel address preserving tags
 *
 * int copyincap(const void * __capability uaddr, void *kaddr, size_t len)
 */
ENTRY(copyincap)
	beqz	a2, copyincap_end	/* If len == 0 then skip loop */
	add	a3, a0, a2
	li	a4, VM_MAXUSER_ADDRESS
	bgt	a3, a4, copyio_fault_nopcb

#ifndef __CHERI_PURE_CAPABILITY__
	cspecialr	ca3, ddc
	csetoffset	ca3, ca3, a1
	csetbounds	ca1, ca3, a2
#endif

	copycapcommon

copyincap_end:
	li	a0, 0		/* return 0 */
	RETURN
END(copyincap)
#endif

/*
 * Copies between two user addresses
 *
 * int copyuser(const void * __capability usrc, void * __capability udst,
 *     size_t len)
 */
ENTRY(copyuser)
	beqz	a2, copyuser_end	/* If len == 0 then skip loop */
	add	a3, a0, a2
	li	a4, VM_MAXUSER_ADDRESS
	bgeu	a3, a4, copyio_fault_nopcb
	add	a3, a1, a2
	bgeu	a3, a4, copyio_fault_nopcb

#if __has_feature(capabilities)
	copycapcommon
#else
	copycommon
#endif

copyuser_end:
	li	a0, 0		/* return 0 */
	RETURN
END(copyuser)

/*
 * CHERI CHANGES START
 * {
 *   "updated": 20200804,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
