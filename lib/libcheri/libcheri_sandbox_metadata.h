/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
 * Copyright (c) 2015 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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

#ifndef _LIBCHERI_SANDBOX_METADATA_H_
#define	_LIBCHERI_SANDBOX_METADATA_H_

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

/*
 * This section defines the interface between 'inside' and 'outside' the
 * sandbox model.
 */

/*
 * Per-sandbox meta-data structure mapped read-only within the sandbox at a
 * fixed address to allow sandboxed code to find its vtable, heap, return
 * capabilities, etc.
 *
 * NB: This data structure (and its base address) are part of the ABI between
 * libcheri and programs running in sandboxes.  Only ever append to this,
 * don't modify the order, lengths, or interpretations of existing fields.  If
 * this reaches a page in size, then allocation code in sandbox.c will need
 * updating.  See also sandbox.c and sandboxasm.h.
 */
struct sandbox_metadata {
	register_t	sbm_heapbase;			/* Offset: 0 */
	register_t	sbm_heaplen;			/* Offset: 8 */
	uint64_t	_sbm_reserved0;			/* Offset: 16 */
	uint64_t	_sbm_reserved1;			/* Offset: 24 */
	struct cheri_object	sbm_system_object;	/* Offset: 32 */
	__capability vm_offset_t	*sbm_vtable;	/* Cap-offset: 2 */
	__capability void	*_sbm_reserved2;	/* Cap-offset: 3 */
	struct cheri_object	 sbm_creturn_object;	/* Cap-offset: 4, 5 */
};

#endif /* !_LIBCHERI_SANDBOX_METADATA_H_ */
