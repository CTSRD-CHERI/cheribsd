/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
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

#ifndef _CHERI_CLASS_H_
#define	_CHERI_CLASS_H_

/*
 * Fields to insert at the front of the 'sandbox_object' data structure that
 * will be used during protection-domain switching to set up the target
 * execution context.  These are used for both loaded classes and system
 * classes.
 *
 * __sandbox_object_idc		IDC to install for both rtld and invocation
 *				entry.  The entry vector code will also use
 *				this capability, with offset set to zero, as
 *				the installed DDC.
 *
 * __sandbox_object_rtld_pcc	PCC to install for rtld operations.
 *
 * __sandbox_object_invoke_pcc	PCC to install on invocation.
 *
 * __sandbox_vtable		VTable pointer used for CHERI system classes;
 *				unused for loaded (confined) classes.
 */
#define	LIBCHERI_SANDBOX_OBJECT_FIELDS					\
	__capability void	*__sandbox_object_idc;			\
	__capability void	*__sandbox_object_rtld_pcc;		\
	__capability void	*__sandbox_object_invoke_pcc;		\
	__capability intptr_t	*__sandbox_vtable

#define	LIBCHERI_SANDBOX_OBJECT_INIT(sbop, idc, rtld_pcc, invoke_pcc, vtable)\
	(sbop)->__sandbox_object_idc = (idc);				\
	(sbop)->__sandbox_object_rtld_pcc = (rtld_pcc);			\
	(sbop)->__sandbox_object_invoke_pcc = (invoke_pcc);		\
	(sbop)->__sandbox_vtable = (vtable)

#define	LIBCHERI_SANDBOX_OBJECT_FINI(sbop)				\
	(sbop)->__sandbox_object_idc = NULL;				\
	(sbop)->__sandbox_object_rtld_pcc = NULL;			\
	(sbop)->__sandbox_object_invoke_pcc = NULL;			\
	free((__cheri_cast intptr_t *)(sbop)->__sandbox_vtable);	\
	(sbop)->__sandbox_vtable = NULL

#endif /* _CHERI_CLASS_H_ */
