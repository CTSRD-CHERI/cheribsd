/*-
 * Copyright (c) 2017 Robert N. M. Watson
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

#ifndef _LIBCHERI_ERRNO_H_
#define	_LIBCHERI_ERRNO_H_

#ifndef LIBCHERI_ERRNO_ASM
/*
 * The libcheri error number variable.  If an error occurs during rtld entry,
 * invocation, or return, then this will be set to indicate the error.  On
 * success, then invocation/return leave this value unmodified.
 *
 * NB: C-language definitions are masked when including libcheri_errno.h in
 * the domain-transition trampoline assembly.
 */
extern _Thread_local int	libcheri_errno;
#endif

/*
 * These values may be returned from the rtld, invocation, and return
 * trampolines via libcheri_errno.
 */
#define	CHERI_ERRNO_INVOKE_LOCAL_ARG	1	/* Local capability passed. */
#define	CHERI_ERRNO_INVOKE_OVERFLOW	2	/* Trusted-stack overflow. */
#define	CHERI_ERRNO_INVOKE_BUSY		3	/* Sandbox object is in use. */

#define	CHERI_ERRNO_RETURN_LOCAL_RETVAL	80	/* Local capability returned. */
#define	CHERI_ERRNO_RETURN_UNDERFLOW	81	/* Trusted-stack underflow. */

#endif /* _LIBCHERI_ERRNO_H_ */
