/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Architecture specific syscalls (MIPS)
 */
#ifndef _MACHINE_SYSARCH_H_
#define _MACHINE_SYSARCH_H_

#define	MIPS_SET_TLS	1
#define	MIPS_GET_TLS	2

/*
 * CHERI sysarch()s to get and set the trusted stack.
 *
 * XXXRW: These have imperfect ABIs since we'd like the kernel to be able to
 * grow the stack, and the API here assumes a fixed-size structure (as does
 * sysarch() itself).  We may want to move to actual system calls (or
 * sysctl()).
 *
 * XXXRW: Is there an ifdef of some sort I should be using here?  The kernel
 * code is ifdef'd so it probably doesn't matter.
 */
#define	CHERI_GET_STACK		4	/* Get trusted stack. */
#define	CHERI_SET_STACK		5	/* Set trusted stack. */

/*
 * Query the root of the object-type sealing capability provenance tree.  This
 * allows us to avoid setting CHERI_PERM_SEAL and CHERI_PERM_UNSEAL on data
 * and code capabilities.
 */
#define	CHERI_GET_SEALCAP	6	/* Get root sealing capability. */

/*
 * Manipulate the mmap capability.
 */
#define	CHERI_MMAP_GETPERM	7	/* Get permissions */
#define	CHERI_MMAP_ANDPERM	8	/* Reduce permissions */
#define	CHERI_MMAP_GETBASE	9	/* Get capability base. */
#define	CHERI_MMAP_GETLEN	10	/* Get capability length. */
/*
 * XXX-BD: we may want to replaced these with a two argument atomic bounds
 * setting operation and require zero offsets.
 */
#define	CHERI_MMAP_GETOFFSET	11	/* Get capability offset. */
#define	CHERI_MMAP_SETOFFSET	12	/* Set capability offset. */
#define	CHERI_MMAP_SETBOUNDS	13	/* Set capability bounds. */

/*
 * Query, enable, and disable QEMU ISA-level tracing on threads. To use this
 * feature, the sysctl hw.qemu_trace_perthread must be enabled.
 */
#define	QEMU_GET_QTRACE		100	/* Get QEMU tracing. */
#define	QEMU_SET_QTRACE		101	/* Set (or clear) QEMU tracing. */

#ifndef _KERNEL
#include <sys/cdefs.h>

__BEGIN_DECLS
int sysarch(int, void *);
__END_DECLS
#endif

#endif /* !_MACHINE_SYSARCH_H_ */
// CHERI CHANGES START
// {
//   "updated": 20180629,
//   "target_type": "header",
//   "changes": [
//     "support"
//   ],
//   "change_comment": "mmap cap"
// }
// CHERI CHANGES END
