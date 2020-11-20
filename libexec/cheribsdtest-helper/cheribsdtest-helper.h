/*-
 * Copyright (c) 2013-2016 Robert N. M. Watson
 * Copyright (c) 2014-2015 SRI International
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

#ifndef _LIBEXEC_CHERIBSDTEST_CHERIBSDTEST_HELPER_H_
#define	_LIBEXEC_CHERIBSDTEST_CHERIBSDTEST_HELPER_H_

#define	CHERIBSDTEST_HELPER_CAP_FAULT_CP2_BOUND		1
#define	CHERIBSDTEST_HELPER_CAP_FAULT_CP2_PERM_LOAD	2
#define	CHERIBSDTEST_HELPER_CAP_FAULT_CP2_PERM_STORE	3
#define	CHERIBSDTEST_HELPER_CAP_FAULT_CP2_TAG		4
#define	CHERIBSDTEST_HELPER_CAP_FAULT_CP2_SEAL		5

#define	CHERIBSDTEST_HELPER_VM_FAULT_RFAULT		1
#define	CHERIBSDTEST_HELPER_VM_FAULT_WFAULT		2
#define	CHERIBSDTEST_HELPER_VM_FAULT_XFAULT		3

/*
 * We use system-class extensions to allow cheribsdtest-helper code to call back
 * into cheribsdtest to exercise various cases (e.g., stack-related tests).
 * These are the corresponding method numbers.
 */
#define	CHERIBSDTEST_USERFN_RETURNARG	(CHERI_SYSTEM_USER_BASE)
#define	CHERIBSDTEST_USERFN_GETSTACK	(CHERI_SYSTEM_USER_BASE + 1)
#define	CHERIBSDTEST_USERFN_SETSTACK	(CHERI_SYSTEM_USER_BASE + 2)

/*
 * Constants used to test BSS, .data, and constructor-based variable
 * initialisation in sandboxes.
 */
#define	CHERIBSDTEST_VALUE_BSS		0x00	/* Of course. */
#define	CHERIBSDTEST_VALUE_DATA		0xaa
#define	CHERIBSDTEST_VALUE_INVALID		0xbb
#define	CHERIBSDTEST_VALUE_CONSTRUCTOR	0xcc


#ifdef LIST_ONLY
#define CHERIBSDTEST_CCALL
#define CHERIBSDTEST_CCALL2
#define BEGIN_CAPABILITIES
#define END_CAPABILITIES
#else
#if __has_feature(pointer_interpretation)
#define BEGIN_CAPABILITIES \
    _Pragma("pointer_interpretation push") \
    _Pragma("pointer_interpretation capability")
#define END_CAPABILITIES \
    _Pragma("pointer_interpretation pop")
#else
#error Compiler does not support capabilities.
#endif
extern struct cheri_object cheribsdtest;
#ifdef CHERIBSDTEST_INTERNAL
#define	CHERIBSDTEST_CCALL				\
    __attribute__((cheri_ccallee))			\
    __attribute__((cheri_method_class(cheribsdtest)))
#else
#define	CHERIBSDTEST_CCALL				\
    __attribute__((cheri_ccall))			\
    __attribute__((cheri_method_suffix("_cap")))	\
    __attribute__((cheri_method_class(cheribsdtest)))
#endif
extern struct cheri_object cheribsdtest2;
#ifdef CHERIBSDTEST_INTERNAL
#define	CHERIBSDTEST_CCALL2				\
    __attribute__((cheri_ccallee))			\
    __attribute__((cheri_method_class(cheribsdtest2)))
#else
#define	CHERIBSDTEST_CCALL2				\
    __attribute__((cheri_ccall))			\
    __attribute__((cheri_method_suffix("_cap")))	\
    __attribute__((cheri_method_class(cheribsdtest2)))
#endif
#endif

struct cheri_object;

BEGIN_CAPABILITIES
CHERIBSDTEST_CCALL int	invoke_divzero(void);
CHERIBSDTEST_CCALL int	invoke_cheri_system_helloworld(void);
CHERIBSDTEST_CCALL int	invoke_cheri_system_puts(void);
CHERIBSDTEST_CCALL int	invoke_cheri_system_putchar(void);
CHERIBSDTEST_CCALL int	invoke_cheri_system_printf(void);

CHERIBSDTEST_CCALL int	invoke_abort(void);
CHERIBSDTEST_CCALL int	invoke_md5(size_t len, char *data_input,
			    char *data_output);
CHERIBSDTEST_CCALL int	invoke_cap_fault(register_t op);
CHERIBSDTEST_CCALL int	invoke_vm_fault(register_t op);
CHERIBSDTEST_CCALL int	invoke_syscall(void);
CHERIBSDTEST_CCALL int	invoke_fd_fstat_c(struct cheri_object fd_object);
CHERIBSDTEST_CCALL int	invoke_fd_lseek_c(struct cheri_object fd_object);
CHERIBSDTEST_CCALL int	invoke_fd_read_c(struct cheri_object fd_object,
			    void *buf, size_t nbytes);
CHERIBSDTEST_CCALL int	invoke_fd_write_c(struct cheri_object fd_object,
			    char *arg, size_t nbytes);
CHERIBSDTEST_CCALL int	invoke_malloc(void);
CHERIBSDTEST_CCALL int	invoke_system_calloc(void);
CHERIBSDTEST_CCALL int	invoke_clock_gettime(void);
CHERIBSDTEST_CCALL int	invoke_libcheri_userfn(register_t arg, size_t len);
CHERIBSDTEST_CCALL int	invoke_libcheri_userfn_setstack(register_t arg);
CHERIBSDTEST_CCALL int	invoke_libcheri_save_capability_in_heap(
			    void *data_input);

CHERIBSDTEST_CCALL register_t	invoke_store_capability_in_bss(void *);
CHERIBSDTEST_CCALL register_t	invoke_store_local_capability_in_bss(void *);
CHERIBSDTEST_CCALL register_t	invoke_store_capability_in_stack(void *);
CHERIBSDTEST_CCALL register_t	invoke_store_local_capability_in_stack(void *);
CHERIBSDTEST_CCALL void	*invoke_return_capability(void *);
CHERIBSDTEST_CCALL void	*invoke_return_local_capability(void *);

CHERIBSDTEST_CCALL register_t	invoke_get_var_bss(void);
CHERIBSDTEST_CCALL register_t	invoke_get_var_data(void);
CHERIBSDTEST_CCALL register_t	invoke_set_var_data(register_t v);
CHERIBSDTEST_CCALL register_t	invoke_get_var_constructor(void);
struct zstream_proxy;
CHERIBSDTEST_CCALL register_t	invoke_inflate(struct zstream_proxy *zspp);
CHERIBSDTEST_CCALL register_t	invoke_spin(void);

/* Test calling with a different default object */
CHERIBSDTEST_CCALL2 int	call_invoke_md5(size_t len, char *data_input,
			    char *data_output);

CHERIBSDTEST_CCALL	int	sandbox_test_ptrdiff(void);
CHERIBSDTEST_CCALL int	sandbox_test_varargs(void);
CHERIBSDTEST_CCALL int	sandbox_test_va_copy(void);
END_CAPABILITIES

#endif /* !_LIBEXEC_CHERIBSDTEST_CHERIBSDTEST_HELPER_H_ */
