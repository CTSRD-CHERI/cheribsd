/*-
 * Copyright (c) 2012-2018, 2020-2021 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
 * Copyright (c) 2021 Microsoft Corp.
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

#include <sys/linker_set.h>

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
 * Convert a pointer to a null-derived void * with the same address. This is
 * useful for getting the correct value for ccs_si_addr_expected.
 */
#define	NULL_DERIVED_VOIDP(x) ((void *)(uintptr_t)(ptraddr_t)(x))

/*
 * Shared memory interface between tests and the test controller process.
 */
#define	TESTRESULT_STR_LEN	1024
struct cheribsdtest_child_state {
	/* Fields filled in by the child signal handler. */
	int		ccs_signum;
	int		ccs_si_code;
	int		ccs_si_trapno;
	void		*ccs_si_addr;

	/* Fields filled in by the test itself. */
	int		ccs_testresult;
	char		ccs_testresult_str[TESTRESULT_STR_LEN];
	void		*ccs_si_addr_expected;
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
#define	CT_FLAG_SI_CODE		0x00000200  /* Check signal si_code. */
#define	CT_FLAG_SIGEXIT		0x00000400  /* Exits with uncaught signal;
					       checks status signum. */
#define	CT_FLAG_SI_ADDR		0x00000800  /* Check signal si_addr. */

/*
 * Macros defined in one or more cheribsdtest_md.h to indicate the
 * reason for failure or flaky behavior.  Provide defaults here to
 * reduce the size of MD headers.
 */
#ifndef	SI_CODE_STORELOCAL
#define	SI_CODE_STORELOCAL	PROT_CHERI_STORELOCAL
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
	void		(*ct_func)(const struct cheri_test *);
	void		(*ct_child_func)(const struct cheri_test *);
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

#define	_CHERIBSDTEST_DECLARE(func, desc, ...)				\
	static void func(const struct cheri_test *ctp);			\
	static struct cheri_test __CONCAT(__cheri_test, __LINE__) = {	\
		.ct_name = #func,					\
		.ct_desc = (desc),					\
		.ct_func = func,					\
		__VA_ARGS__						\
	};								\
	DATA_SET(cheri_tests_set, __CONCAT(__cheri_test, __LINE__))

#define	CHERIBSDTEST(func, desc, ...)					\
	_CHERIBSDTEST_DECLARE(func, (desc), __VA_ARGS__);		\
	static void func(const struct cheri_test * __unused ctp)

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
void	cheribsdtest_set_expected_si_addr(void *addr);

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

static inline void
_cheribsdtest_check_cap_bounds_precise(void *__capability c,
    size_t expected_len)
{
	size_t len, offset;

	offset = cheri_getoffset(c);
	len = cheri_getlen(c);

	/* Confirm precise lower bound: offset of zero. */
	CHERIBSDTEST_VERIFY2(offset == 0,
	    "offset (%jd) not zero: %#lp", offset, c);

	/* Confirm precise upper bound: length of expected size for type. */
	CHERIBSDTEST_VERIFY2(len == expected_len,
	    "length (%jd) not expected %jd: %#lp", len, expected_len, c);
}
#define	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(c, expected_len) \
	_cheribsdtest_check_cap_bounds_precise((c), (expected_len))

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

/* For libc_memcpy and libc_memset tests and the unaligned copy tests: */
extern void *cheribsdtest_memcpy(void *dst, const void *src, size_t n);
extern void *cheribsdtest_memmove(void *dst, const void *src, size_t n);

/*
 * (co)exec a new copy of cheribsdtest and run the test's associated child
 * function.
 */
extern void cheribsdtest_coexec_child(const struct cheri_test *ctp);
extern void cheribsdtest_exec_child(const struct cheri_test *ctp);

#endif /* !_CHERIBSDTEST_H_ */
