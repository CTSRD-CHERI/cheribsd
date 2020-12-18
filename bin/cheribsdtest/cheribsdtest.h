/*-
 * Copyright (c) 2012-2018, 2020 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
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

#ifndef _CHERIBSDTEST_H_
#define	_CHERIBSDTEST_H_

#include <string.h>
#include <cheri/cheric.h>

#include "cheribsdtest_md.h"

#define	CHERI_CAP_PRINT(cap) do {					\
	printf("tag %ju s %ju perms %08jx type %016jx\n",		\
	    (uintmax_t)cheri_gettag(cap),				\
	    (uintmax_t)cheri_getsealed(cap),				\
	    (uintmax_t)cheri_getperm(cap),				\
	    (uintmax_t)cheri_gettype(cap));				\
	printf("\tbase %016jx length %016jx\n",				\
	    (uintmax_t)cheri_getbase(cap),				\
	    (uintmax_t)cheri_getlen(cap));				\
} while (0)

#define	CHERI_CAPREG_PRINT(crn) do {					\
	void * __capability cap;						\
	if (crn == 0)							\
		cap = cheri_getdefault();				\
	else								\
		cap = cheri_getreg(crn);				\
	printf("C%u ", crn);						\
	CHERI_CAP_PRINT(cap);						\
} while (0)

#define	CHERI_PCC_PRINT() do {						\
	void * __capability cap;						\
	cap = cheri_getpcc();						\
	printf("PCC ");							\
	CHERI_CAP_PRINT(cap);						\
} while (0)

/*
 * Shared memory interface between tests and the test controller process.
 */
#define	TESTRESULT_STR_LEN	1024
struct cheribsdtest_child_state {
	/* Fields filled in by the child signal handler. */
	int		ccs_signum;
	int		ccs_si_code;
	int		ccs_si_trapno;
#ifdef __mips__
	register_t	ccs_cp2_cause;
#endif
	int		ccs_unwound;  /* If any trusted-stack frames unwound. */

	/* Fields filled in by the test itself. */
	int		ccs_testresult;
	char		ccs_testresult_str[TESTRESULT_STR_LEN];
};
extern struct cheribsdtest_child_state *ccsp;

/*
 * If the test runs to completion, it must set ccs_testresult to SUCCESS or
 * FAILURE.  If the latter, it should also fill ccs_testresult_str with a
 * suitable message to display to the user.
 */
#define	TESTRESULT_UNKNOWN	0	/* Default initialisation. */
#define	TESTRESULT_SUCCESS	1	/* Test declares success. */
#define	TESTRESULT_FAILURE	2	/* Test declares failure. */

/*
 * Description structure for each test -- passed to the test in case it needs
 * access to configuration state, such as strings passed to/from stdio.
 */
#define	CT_FLAG_SIGNAL		0x00000001  /* Should fault; checks signum. */
#define	CT_FLAG_SI_TRAPNO	0x00000002  /* Check signal si_trapno. */
#define	CT_FLAG_STDOUT_STRING	0x00000008  /* Check stdout for a string. */
#define	CT_FLAG_STDIN_STRING	0x00000010  /* Provide string on stdin. */
#define	CT_FLAG_STDOUT_IGNORE	0x00000020  /* Standard output produced,
					       but not checkable */
#define CT_FLAG_SLOW		0x00000040  /* Test is expected to take a 
					       long time to run */
#define	CT_FLAG_SIGNAL_UNWIND	0x00000080  /* Should fault and unwind
					       trusted stack; checks signum
					       and result. */
#define	CT_FLAG_SANDBOX		0x00000100  /* Test requires that a libcheri
					     * sandbox be created. */
#define	CT_FLAG_SI_CODE		0x00000200  /* Check signal si_code. */
#define	CT_FLAG_SIGEXIT		0x00000400  /* Exits with uncaught signal;
					       checks status signum. */

#define	CHERIBSDTEST_SANDBOX_UNWOUND	0x123456789ULL

/*
 * Macros defined in one or more cheribsdtest_md.h to indicate the
 * reason for failure or flaky behavior.  Define to NULL here to
 * reduce the size of MD headers.
 */
#ifndef FLAKY_COMPILER_BOUNDS
#define	FLAKY_COMPILER_BOUNDS	NULL
#endif

#ifndef	XFAIL_HYBRID_BOUNDS_GLOBALS
#ifdef __CHERI_PURE_CAPABILITY__
#define	XFAIL_HYBRID_BOUNDS_GLOBALS	NULL
#else
#define	XFAIL_HYBRID_BOUNDS_GLOBALS \
    "Bounds not supported for globals in hybrid ABI"
#endif
#endif

#ifndef	XFAIL_HYBRID_BOUNDS_GLOBALS_EXTERN
#ifdef __CHERI_PURE_CAPABILITY__
#define	XFAIL_HYBRID_BOUNDS_GLOBALS_EXTERN	NULL
#else
#define	XFAIL_HYBRID_BOUNDS_GLOBALS_EXTERN \
    "Bounds not supported for extern globals in hybrid ABI"
#endif
#endif

#ifndef	XFAIL_HYBRID_BOUNDS_GLOBALS_STATIC
#ifdef __CHERI_PURE_CAPABILITY__
#define	XFAIL_HYBRID_BOUNDS_GLOBALS_STATIC	NULL
#else
#define	XFAIL_HYBRID_BOUNDS_GLOBALS_STATIC \
    "Bounds not supported for static globals in hybrid ABI"
#endif
#endif

#ifndef XFAIL_VARARG_BOUNDS
#define	XFAIL_VARARG_BOUNDS	NULL
#endif

struct cheri_test {
	const char	*ct_name;
	const char	*ct_desc;
	int		 ct_arg;	/* 0: ct_func; otherwise ct_func_arg. */
	void		(*ct_func)(const struct cheri_test *);
	void		(*ct_func_arg)(const struct cheri_test *, int);
	const char *	(*ct_check_xfail)(const char *);
	u_int		 ct_flags;
	int		 ct_signum;
	int		 ct_si_code;
	int		 ct_si_trapno;
	const char	*ct_stdin_string;
	const char	*ct_stdout_string;
	const char	*ct_xfail_reason;
	const char	*ct_flaky_reason;
};

/*
 * Useful APIs for tests.  These terminate the process returning either
 * success or failure with a test-defined, human-readable string describing
 * the error.
 */
void	cheribsdtest_failure_err(const char *msg, ...) __dead2  __printflike(1, 2);
void	cheribsdtest_failure_errc(int code, const char *msg, ...) __dead2
    __printflike(2, 3);
void	cheribsdtest_failure_errx(const char *msg, ...) __dead2  __printflike(1, 2);
void	cheribsdtest_success(void) __dead2;
void	signal_handler_clear(int sig);

/**
 * Like CHERIBSDTEST_VERIFY but instead of printing condition details prints
 * the provided printf-like message @p fmtargs
 */
#define CHERIBSDTEST_VERIFY2(cond, fmtargs...)		\
	do { if (!(cond)) { 				\
		cheribsdtest_failure_errx(fmtargs);	\
	} } while(0)

/** If @p cond is false fail the test and print the failed condition */
#define CHERIBSDTEST_VERIFY(cond) \
	CHERIBSDTEST_VERIFY2(cond, "%s", "\'" #cond "\' is FALSE!")

#define CHERIBSDTEST_CHECK_EQ(type, fmt, a, b, a_str, b_str)	do {	\
		type __a = (a);						\
		type __b = (b);						\
		CHERIBSDTEST_VERIFY2(__a == __b, "%s (" fmt ") == %s ("	\
		    fmt ") failed!", a_str, __a, b_str, __b);		\
	} while (0)

#define CHERIBSDTEST_CHECK_EQ_BOOL(a, b)	\
	CHERIBSDTEST_CHECK_EQ(_Bool, "%d", a, b, __STRING(a), __STRING(b))
#define CHERIBSDTEST_CHECK_EQ_INT(a, b)	\
	CHERIBSDTEST_CHECK_EQ(int, "0x%x", a, b, __STRING(a), __STRING(b))
#define CHERIBSDTEST_CHECK_EQ_LONG(a, b)	\
	CHERIBSDTEST_CHECK_EQ(long, "0x%lx", a, b, __STRING(a), __STRING(b))
#define CHERIBSDTEST_CHECK_EQ_SIZE(a, b)	\
	CHERIBSDTEST_CHECK_EQ(size_t, "0x%zx", a, b, __STRING(a), __STRING(b))

static inline void
_cheribsdtest_check_cap_eq(void *__capability a, void *__capability b,
    const char *a_str, const char *b_str)
{
	/* TODO: This should use CExEq instead once RISC-V has it */
#define CHECK_CAP_ATTR(accessor, fmt)						\
	CHERIBSDTEST_VERIFY2(accessor(a) == accessor(b),			\
	    __STRING(accessor) "(%s) (" fmt ") == " __STRING(accessor)		\
	    "(%s) (" fmt ") failed!", a_str, accessor(a), b_str, accessor(b))
	CHECK_CAP_ATTR(cheri_getaddress, "0x%lx");
	CHECK_CAP_ATTR(cheri_gettag, "%d");
	CHECK_CAP_ATTR(cheri_getoffset, "0x%lx");
	CHECK_CAP_ATTR(cheri_getlength, "0x%lx");
	CHECK_CAP_ATTR(cheri_getperm, "0x%lx");
	CHECK_CAP_ATTR(cheri_gettype, "%ld");
	CHECK_CAP_ATTR(cheri_getflags, "0x%lx");
#undef CHECK_CAP_ATTR
}
#define CHERIBSDTEST_CHECK_EQ_CAP(a, b)	\
	_cheribsdtest_check_cap_eq(a, b, __STRING(a), __STRING(b))

/**
 * Like CHERIBSDTEST_CHECK_SYSCALL but instead of printing call details prints
 * the provided printf-like message @p fmtargs
 */
#define CHERIBSDTEST_CHECK_SYSCALL2(call, fmtargs...) __extension__({	\
		__typeof(call) __result = call;				\
		if (__result == ((__typeof(__result))-1)) {		\
			cheribsdtest_failure_err(fmtargs);		\
		}							\
		__result;						\
	})
/**
 * If result of @p call is equal to -1 fail the test and print the failed call
 * followed by the string representation of @c errno
 */
#define CHERIBSDTEST_CHECK_SYSCALL(call) \
	CHERIBSDTEST_CHECK_SYSCALL2(call, "Call \'" #call "\' failed")

static inline void
_cheribsdtest_check_errno(const char *context, int actual, int expected)
{
	char actual_str[256];
	char expected_str[256];

	if (expected == actual)
		return;
	if (strerror_r(actual, actual_str, sizeof(actual_str)) != 0)
		cheribsdtest_failure_err("sterror_r(%d)", actual);
	if (strerror_r(expected, expected_str, sizeof(expected_str)) != 0)
		cheribsdtest_failure_err("sterror_r(%d)", expected);
	cheribsdtest_failure_errx("%s errno %d (%s) != expected errno %d (%s)",
	    context, actual, actual_str, expected, expected_str);
}

/** Check that @p call fails and errno is set to @p expected_errno */
#define CHERIBSDTEST_CHECK_CALL_ERROR(call, expected_errno)			\
	do {									\
		errno = 0;							\
		int __ret = call;						\
		int call_errno = errno;						\
		CHERIBSDTEST_VERIFY2(__ret == -1,				\
		    #call " unexpectedly returned %d", __ret);			\
		_cheribsdtest_check_errno(#call, call_errno, expected_errno);	\
	} while (0)

#define DECLARE_CHERIBSD_TEST_IMPL(name, args...) void name(args)
#define DECLARE_CHERIBSD_TEST_WITH_ARGS(name, args...) \
	DECLARE_CHERIBSD_TEST_IMPL(name, const struct cheri_test *ctp, args)
#define DECLARE_CHERIBSD_TEST(name) \
	DECLARE_CHERIBSD_TEST_IMPL(name, const struct cheri_test *ctp)


/* cheribsdtest_bounds_globals.c */
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint16);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint16);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint32);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint32);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint64);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint64);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array1);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array1);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array3);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array3);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array17);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array17);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array65537);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array65537);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array32);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array32);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array64);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array64);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array128);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array128);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array256);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array256);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array512);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array512);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array1024);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array1024);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array2048);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array2048);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array4096);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array4096);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array8192);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array8192);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array16384);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array16384);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array32768);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array32768);
DECLARE_CHERIBSD_TEST(test_bounds_global_static_uint8_array65536);
DECLARE_CHERIBSD_TEST(test_bounds_global_uint8_array65536);

/* cheribsdtest_bounds_global.c, but dependent on cheribsdtest_bounds_global_x.c */
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_uint8);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_uint16);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_uint32);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_uint64);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_array1);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_array7);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_array65537);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_array16);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_array256);
DECLARE_CHERIBSD_TEST(test_bounds_extern_global_array65536);

/* cheribsdtest_bounds_heap.c */
DECLARE_CHERIBSD_TEST(test_bounds_calloc);

/* cheribsdtest_bounds_stack.c */
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_uint8);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_uint16);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_uint32);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_uint64);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_cap);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_16);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_32);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_64);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_128);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_256);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_512);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_1024);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_2048);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_4096);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_8192);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_16384);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_32768);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_65536);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_131072);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_262144);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_524288);
DECLARE_CHERIBSD_TEST(test_bounds_stack_static_1048576);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_uint8);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_uint16);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_uint32);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_uint64);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_cap);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_16);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_32);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_64);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_128);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_256);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_512);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_1024);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_2048);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_4096);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_8192);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_16384);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_32768);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_65536);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_131072);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_262144);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_524288);
DECLARE_CHERIBSD_TEST(test_bounds_stack_dynamic_1048576);

/* cheribsdtest_bounds_varargs.c */
DECLARE_CHERIBSD_TEST(test_bounds_varargs_empty_pointer_null);
DECLARE_CHERIBSD_TEST(test_bounds_varargs_vaarg_overflow);
DECLARE_CHERIBSD_TEST(test_bounds_varargs_printf_load);
DECLARE_CHERIBSD_TEST(test_bounds_varargs_printf_store);

/* cheribsdtest_ccall.c */
void	cheribsdtest_ccall_setup(void);
DECLARE_CHERIBSD_TEST(test_nofault_ccall_creturn);
DECLARE_CHERIBSD_TEST(test_nofault_ccall_nop_creturn);
DECLARE_CHERIBSD_TEST(test_nofault_ccall_dli_creturn);
DECLARE_CHERIBSD_TEST(test_fault_creturn);
DECLARE_CHERIBSD_TEST(test_fault_ccall_code_untagged);
DECLARE_CHERIBSD_TEST(test_fault_ccall_data_untagged);
DECLARE_CHERIBSD_TEST(test_fault_ccall_code_unsealed);
DECLARE_CHERIBSD_TEST(test_fault_ccall_data_unsealed);
DECLARE_CHERIBSD_TEST(test_fault_ccall_typemismatch);
DECLARE_CHERIBSD_TEST(test_fault_ccall_code_noexecute);
DECLARE_CHERIBSD_TEST(test_fault_ccall_data_execute);

/* cheribsdtest_cheriabi.c */
DECLARE_CHERIBSD_TEST(test_cheriabi_mmap_nospace);
DECLARE_CHERIBSD_TEST(test_cheriabi_mmap_perms);
DECLARE_CHERIBSD_TEST(test_cheriabi_mmap_unrepresentable);
DECLARE_CHERIBSD_TEST(test_cheriabi_malloc_zero_size);
DECLARE_CHERIBSD_TEST(test_cheriabi_munmap_invalid_ptr);
DECLARE_CHERIBSD_TEST(test_cheriabi_mprotect_invalid_ptr);
DECLARE_CHERIBSD_TEST(test_cheriabi_minherit_invalid_ptr);
DECLARE_CHERIBSD_TEST(test_cheriabi_shmdt_invalid_ptr);

/* cheribsdtest_cheriabi_libc.c */
DECLARE_CHERIBSD_TEST(test_cheriabi_libc_memchr);

/* cheribsdtest_cheriabi_open.c */
DECLARE_CHERIBSD_TEST(test_cheriabi_open_ordinary);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_offset);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_shortened);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_bad_addr);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_bad_addr_2);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_bad_len);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_bad_len_2);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_bad_tag);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_bad_perm);
DECLARE_CHERIBSD_TEST(test_cheriabi_open_sealed);

/* cheribsdtest_fault.c */
DECLARE_CHERIBSD_TEST(test_fault_bounds);
DECLARE_CHERIBSD_TEST(test_fault_cgetcause);
DECLARE_CHERIBSD_TEST(test_nofault_cfromptr);
DECLARE_CHERIBSD_TEST(test_fault_perm_load);
DECLARE_CHERIBSD_TEST(test_nofault_perm_load);
DECLARE_CHERIBSD_TEST(test_fault_perm_seal);
DECLARE_CHERIBSD_TEST(test_fault_perm_store);
DECLARE_CHERIBSD_TEST(test_nofault_perm_store);
DECLARE_CHERIBSD_TEST(test_fault_perm_unseal);
DECLARE_CHERIBSD_TEST(test_fault_tag);
DECLARE_CHERIBSD_TEST(test_fault_ccheck_user_fail);
DECLARE_CHERIBSD_TEST(test_fault_read_kr1c);
DECLARE_CHERIBSD_TEST(test_fault_read_kr2c);
DECLARE_CHERIBSD_TEST(test_fault_read_kcc);
DECLARE_CHERIBSD_TEST(test_fault_read_kdc);
DECLARE_CHERIBSD_TEST(test_fault_read_epcc);
DECLARE_CHERIBSD_TEST(test_nofault_ccheck_user_pass);

/* cheribsdtest_fd.c */
#define	CHERIBSDTEST_FD_READ_STR	"read123"
#define	CHERIBSDTEST_FD_WRITE_STR	"write123"

extern int			 zero_fd;

extern struct sandbox_object	*sbop_stdin;
extern struct sandbox_object	*sbop_stdout;
extern struct sandbox_object	*sbop_zero;

DECLARE_CHERIBSD_TEST(test_sandbox_fd_fstat);
DECLARE_CHERIBSD_TEST(test_sandbox_fd_lseek);
DECLARE_CHERIBSD_TEST(test_sandbox_fd_read);
DECLARE_CHERIBSD_TEST(test_sandbox_fd_read_revoke);
DECLARE_CHERIBSD_TEST(test_sandbox_fd_write);
DECLARE_CHERIBSD_TEST(test_sandbox_fd_write_revoke);

/* cheribsdtest_flag_captured.c */
DECLARE_CHERIBSD_TEST(test_flag_captured);
DECLARE_CHERIBSD_TEST(test_flag_captured_incorrect_key);
DECLARE_CHERIBSD_TEST(test_flag_captured_null);
#ifdef __CHERI_PURE_CAPABILITY__
DECLARE_CHERIBSD_TEST(test_flag_captured_empty);
#endif

/* cheribsdtest_kbounce.c */
DECLARE_CHERIBSD_TEST(test_kbounce);

/* cheribsdtest_libcheri.c */
extern struct sandbox_class	*cheribsdtest_classp;
extern struct sandbox_object	*cheribsdtest_objectp;

DECLARE_CHERIBSD_TEST(test_sandbox_abort);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_calloc);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_clock_gettime);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_clock_gettime_default);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_clock_gettime_deny);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_helloworld);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_putchar);
DECLARE_CHERIBSD_TEST(test_sandbox_cs_puts);
DECLARE_CHERIBSD_TEST(test_sandbox_cxx_exception);
DECLARE_CHERIBSD_TEST(test_sandbox_cxx_no_exception);
DECLARE_CHERIBSD_TEST(test_sandbox_malloc);
DECLARE_CHERIBSD_TEST_WITH_ARGS(test_sandbox_md5_ccall, int class2);
DECLARE_CHERIBSD_TEST(test_sandbox_printf);
DECLARE_CHERIBSD_TEST(test_sandbox_ptrdiff);
DECLARE_CHERIBSD_TEST(test_sandbox_varargs);
DECLARE_CHERIBSD_TEST(test_sandbox_va_copy);
DECLARE_CHERIBSD_TEST(test_sandbox_spin);
DECLARE_CHERIBSD_TEST(test_sandbox_userfn);
DECLARE_CHERIBSD_TEST(test_2sandbox_newdestroy);
int	cheribsdtest_libcheri_setup(void);
void	cheribsdtest_libcheri_destroy(void);

/* cheribsdtest_libcheribsdtest_fault.c */
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_bound_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_bound_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_bound_nocatch_noaltstack);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_perm_load_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_perm_load_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_perm_store_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_perm_store_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_tag_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_tag_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_seal_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_cp2_seal_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_divzero_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_divzero_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_vm_rfault_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_vm_rfault_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_vm_wfault_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_vm_wfault_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_vm_xfault_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_vm_xfault_nocatch);

/* cheribsdtest_libcheri_local.c */
DECLARE_CHERIBSD_TEST(test_sandbox_store_global_capability_in_bss);
DECLARE_CHERIBSD_TEST(test_sandbox_store_local_capability_in_bss_catch);
DECLARE_CHERIBSD_TEST(test_sandbox_store_local_capability_in_bss_nocatch);
DECLARE_CHERIBSD_TEST(test_sandbox_store_global_capability_in_stack);
DECLARE_CHERIBSD_TEST(test_sandbox_store_local_capability_in_stack);
DECLARE_CHERIBSD_TEST(test_sandbox_return_global_capability);
DECLARE_CHERIBSD_TEST(test_sandbox_return_local_capability);
DECLARE_CHERIBSD_TEST(test_sandbox_pass_local_capability_arg);

/* cheribsdtest_libcheri_pthreads.c */
DECLARE_CHERIBSD_TEST(test_sandbox_pthread_abort);
DECLARE_CHERIBSD_TEST(test_sandbox_pthread_cs_helloworld);

/* cheribsdtest_libcheri_trustedstack.c */
register_t	cheribsdtest_libcheri_userfn_getstack(void);
register_t	cheribsdtest_libcheri_userfn_setstack(register_t arg);
DECLARE_CHERIBSD_TEST(test_sandbox_getstack);
DECLARE_CHERIBSD_TEST(test_sandbox_setstack);
DECLARE_CHERIBSD_TEST(test_sandbox_setstack_nop);
DECLARE_CHERIBSD_TEST(test_sandbox_trustedstack_underflow);

/* cheribsdtest_libcheri_var.c */
DECLARE_CHERIBSD_TEST(test_sandbox_var_bss);
DECLARE_CHERIBSD_TEST(test_sandbox_var_data);
DECLARE_CHERIBSD_TEST(test_sandbox_var_data_getset);
DECLARE_CHERIBSD_TEST(test_2sandbox_var_data_getset);
DECLARE_CHERIBSD_TEST(test_sandbox_var_constructor);

/* cheribsdtest_longjmp.c */
DECLARE_CHERIBSD_TEST(cheribsdtest_setjmp);
DECLARE_CHERIBSD_TEST(cheribsdtest_setjmp_longjmp);

/* cheribsdtest_printf.c */
DECLARE_CHERIBSD_TEST(test_printf_cap);

/* cheribsdtest_sealcap.c */
DECLARE_CHERIBSD_TEST(test_sealcap_sysctl);
DECLARE_CHERIBSD_TEST(test_sealcap_seal);
DECLARE_CHERIBSD_TEST(test_sealcap_seal_unseal);

/* cheribsdtest_signal.c */
DECLARE_CHERIBSD_TEST(test_signal_handler_usr1);
DECLARE_CHERIBSD_TEST(test_signal_sigaction_usr1);
DECLARE_CHERIBSD_TEST(test_signal_sigaltstack);
DECLARE_CHERIBSD_TEST(test_signal_sigaltstack_disable);
#ifdef __CHERI_PURE_CAPABILITY__
DECLARE_CHERIBSD_TEST(test_signal_returncap);
#endif

/* cheribsdtest_string.c */
DECLARE_CHERIBSD_TEST(test_string_kern_memcpy_c);
DECLARE_CHERIBSD_TEST(test_string_kern_memmove_c);
DECLARE_CHERIBSD_TEST(test_string_memcpy);
DECLARE_CHERIBSD_TEST(test_string_memcpy_c);
DECLARE_CHERIBSD_TEST(test_string_memmove);
DECLARE_CHERIBSD_TEST(test_string_memmove_c);

DECLARE_CHERIBSD_TEST(test_unaligned_capability_copy_memcpy);
DECLARE_CHERIBSD_TEST(test_unaligned_capability_copy_memmove);

/* cheribsdtest_syscall.c */
DECLARE_CHERIBSD_TEST(test_sandbox_syscall);
DECLARE_CHERIBSD_TEST(test_sig_dfl_neq_ign);
DECLARE_CHERIBSD_TEST(test_sig_dfl_ign);
DECLARE_CHERIBSD_TEST(test_ptrace_basic);
DECLARE_CHERIBSD_TEST(test_aio_sival);

/* cheribsdtest_registers.c */
DECLARE_CHERIBSD_TEST(test_initregs_default);
#ifdef __CHERI_PURE_CAPABILITY__
DECLARE_CHERIBSD_TEST(test_initregs_stack);
DECLARE_CHERIBSD_TEST(test_initregs_stack_user_perms);
DECLARE_CHERIBSD_TEST(test_initregs_returncap);
#endif
DECLARE_CHERIBSD_TEST(test_initregs_idc);
DECLARE_CHERIBSD_TEST(test_initregs_pcc);
DECLARE_CHERIBSD_TEST(test_copyregs);
DECLARE_CHERIBSD_TEST(test_listregs);

/* cheribsdtest_sentries.c */
#ifdef __CHERI_PURE_CAPABILITY__
#ifdef CHERIBSD_DYNAMIC_TESTS
DECLARE_CHERIBSD_TEST(test_sentry_dlsym);
#endif
DECLARE_CHERIBSD_TEST(test_sentry_libc);
DECLARE_CHERIBSD_TEST(test_sentry_static);
#endif

/* cheribsdtest_tls.c */
DECLARE_CHERIBSD_TEST(test_tls_align_4k);
DECLARE_CHERIBSD_TEST(test_tls_align_cap);
DECLARE_CHERIBSD_TEST(test_tls_align_ptr);

/* cheribsdtest_tls_threads.c */
DECLARE_CHERIBSD_TEST(test_tls_threads);

/* cheribsdtest_vm.c */
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_mmap_anon);;
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_shm_open_anon_shared);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_shm_open_anon_private);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_shm_open_anon_shared2x);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_shm_open_anon_unix_surprise);
#ifdef __CHERI_PURE_CAPABILITY__
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_cap_share_fd_kqueue);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_cap_share_sigaction);
#endif
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_dev_zero_shared);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_dev_zero_private);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_notag_tmpfile_shared);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_tmpfile_private);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_tag_tmpfile_private_prefault);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_cow_read);
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_cow_write);
const char	*xfail_need_writable_tmp(const char *name);

#if 0
/* cheribsdtest_vm_swap.c */
DECLARE_CHERIBSD_TEST(cheribsdtest_vm_swap);
const char	*xfail_swap_required(const char *name);
#endif

/* cheribsdtest_zlib.c */
DECLARE_CHERIBSD_TEST(test_deflate_zeroes);
DECLARE_CHERIBSD_TEST(test_inflate_zeroes);
DECLARE_CHERIBSD_TEST(test_sandbox_inflate_zeroes);

/* For libc_memcpy and libc_memset tests and the unaligned copy tests: */
extern void *cheribsdtest_memcpy(void *dst, const void *src, size_t n);
extern void *cheribsdtest_memmove(void *dst, const void *src, size_t n);

#ifdef CHERI_C_TESTS
#define	DECLARE_TEST(name, desc) \
    void cheri_c_test_ ## name(const struct cheri_test *ctp __unused);
#define DECLARE_TEST_FAULT(name, desc)	\
    void cheri_c_test_ ## name(const struct cheri_test *ctp __unused);
#include <cheri_c_testdecls.h>
#undef DECLARE_TEST
#undef DECLARE_TEST_FAULT
#endif

#endif /* !_CHERIBSDTEST_H_ */
