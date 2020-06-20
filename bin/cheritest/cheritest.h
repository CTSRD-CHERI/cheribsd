/*-
 * Copyright (c) 2012-2018 Robert N. M. Watson
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

#ifndef _CHERITEST_H_
#define	_CHERITEST_H_

#include <cheri/cheric.h>

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
struct cheritest_child_state {
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
extern struct cheritest_child_state *ccsp;

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

#define	CHERITEST_SANDBOX_UNWOUND	0x123456789ULL

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
};

/*
 * Useful APIs for tests.  These terminate the process returning either
 * success or failure with a test-defined, human-readable string describing
 * the error.
 */
void	cheritest_failure_err(const char *msg, ...) __dead2  __printflike(1, 2);
void	cheritest_failure_errx(const char *msg, ...) __dead2  __printflike(1, 2);
void	cheritest_success(void) __dead2;
void	signal_handler_clear(int sig);

/**
 * Like CHERITEST_VERIFY but instead of printing condition details prints
 * the provided printf-like message @p fmtargs
 */
#define CHERITEST_VERIFY2(cond, fmtargs...)		\
	do { if (!(cond)) { 				\
		cheritest_failure_errx(fmtargs);	\
	} } while(0)

/** If @p cond is false fail the test and print the failed condition */
#define CHERITEST_VERIFY(cond) \
	CHERITEST_VERIFY2(cond, "%s", "\'" #cond "\' is FALSE!")

#define CHERITEST_CHECK_EQ(type, fmt, a, b, a_str, b_str)	do {	\
		type __a = (a);						\
		type __b = (b);						\
		CHERITEST_VERIFY2(__a == __b, "%s (" fmt ") == %s ("	\
		    fmt ") failed!", a_str, __a, b_str, __b);		\
	} while (0)

#define CHERITEST_CHECK_EQ_BOOL(a, b)	\
	CHERITEST_CHECK_EQ(_Bool, "%d", a, b, __STRING(a), __STRING(b))
#define CHERITEST_CHECK_EQ_INT(a, b)	\
	CHERITEST_CHECK_EQ(int, "0x%lx", a, b, __STRING(a), __STRING(b))
#define CHERITEST_CHECK_EQ_LONG(a, b)	\
	CHERITEST_CHECK_EQ(long, "0x%lx", a, b, __STRING(a), __STRING(b))
#define CHERITEST_CHECK_EQ_SIZE(a, b)	\
	CHERITEST_CHECK_EQ(size_t, "0x%zx", a, b, __STRING(a), __STRING(b))

static inline void
_cheritest_check_cap_eq(void *__capability a, void *__capability b,
    const char *a_str, const char *b_str)
{
	/* TODO: This should use CExEq instead once RISC-V has it */
#define CHECK_CAP_ATTR(accessor, fmt)						\
	CHERITEST_VERIFY2(accessor(a) == accessor(b),				\
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
#define CHERITEST_CHECK_EQ_CAP(a, b)	\
	_cheritest_check_cap_eq(a, b, __STRING(a), __STRING(b))

/**
 * Like CHERITEST_CHECK_SYSCALL but instead of printing call details prints
 * the provided printf-like message @p fmtargs
 */
#define CHERITEST_CHECK_SYSCALL2(call, fmtargs...) __extension__({	\
		__typeof(call) __result = call;				\
		if (__result == ((__typeof(__result))-1)) {		\
			cheritest_failure_err(fmtargs);			\
		}							\
		__result;						\
	})
/**
 * If result of @p call is equal to -1 fail the test and print the failed call
 * followed by the string representation of @c errno
 */
#define CHERITEST_CHECK_SYSCALL(call) \
	CHERITEST_CHECK_SYSCALL2(call, "Call \'" #call "\' failed")

#define DECLARE_CHERI_TEST_IMPL(name, args...) void name(args)
#define DECLARE_CHERI_TEST_WITH_ARGS(name, args...) \
	DECLARE_CHERI_TEST_IMPL(name, const struct cheri_test *ctp, args)
#define DECLARE_CHERI_TEST(name) \
	DECLARE_CHERI_TEST_IMPL(name, const struct cheri_test *ctp)


/* cheritest_bounds_globals.c */
DECLARE_CHERI_TEST(test_bounds_global_static_uint8);
DECLARE_CHERI_TEST(test_bounds_global_uint8);
DECLARE_CHERI_TEST(test_bounds_global_static_uint16);
DECLARE_CHERI_TEST(test_bounds_global_uint16);
DECLARE_CHERI_TEST(test_bounds_global_static_uint32);
DECLARE_CHERI_TEST(test_bounds_global_uint32);
DECLARE_CHERI_TEST(test_bounds_global_static_uint64);
DECLARE_CHERI_TEST(test_bounds_global_uint64);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array1);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array1);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array3);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array3);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array17);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array17);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array65537);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array65537);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array32);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array32);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array64);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array64);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array128);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array128);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array256);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array256);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array512);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array512);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array1024);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array1024);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array2048);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array2048);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array4096);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array4096);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array8192);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array8192);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array16384);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array16384);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array32768);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array32768);
DECLARE_CHERI_TEST(test_bounds_global_static_uint8_array65536);
DECLARE_CHERI_TEST(test_bounds_global_uint8_array65536);

/* cheritest_bounds_global.c, but dependent on cheritest_bounds_global_x.c */
DECLARE_CHERI_TEST(test_bounds_extern_global_uint8);
DECLARE_CHERI_TEST(test_bounds_extern_global_uint16);
DECLARE_CHERI_TEST(test_bounds_extern_global_uint32);
DECLARE_CHERI_TEST(test_bounds_extern_global_uint64);
DECLARE_CHERI_TEST(test_bounds_extern_global_array1);
DECLARE_CHERI_TEST(test_bounds_extern_global_array7);
DECLARE_CHERI_TEST(test_bounds_extern_global_array65537);
DECLARE_CHERI_TEST(test_bounds_extern_global_array16);
DECLARE_CHERI_TEST(test_bounds_extern_global_array256);
DECLARE_CHERI_TEST(test_bounds_extern_global_array65536);

/* cheritest_bounds_heap.c */
DECLARE_CHERI_TEST(test_bounds_calloc);

/* cheritest_bounds_stack.c */
DECLARE_CHERI_TEST(test_bounds_stack_static_uint8);
DECLARE_CHERI_TEST(test_bounds_stack_static_uint16);
DECLARE_CHERI_TEST(test_bounds_stack_static_uint32);
DECLARE_CHERI_TEST(test_bounds_stack_static_uint64);
DECLARE_CHERI_TEST(test_bounds_stack_static_cap);
DECLARE_CHERI_TEST(test_bounds_stack_static_16);
DECLARE_CHERI_TEST(test_bounds_stack_static_32);
DECLARE_CHERI_TEST(test_bounds_stack_static_64);
DECLARE_CHERI_TEST(test_bounds_stack_static_128);
DECLARE_CHERI_TEST(test_bounds_stack_static_256);
DECLARE_CHERI_TEST(test_bounds_stack_static_512);
DECLARE_CHERI_TEST(test_bounds_stack_static_1024);
DECLARE_CHERI_TEST(test_bounds_stack_static_2048);
DECLARE_CHERI_TEST(test_bounds_stack_static_4096);
DECLARE_CHERI_TEST(test_bounds_stack_static_8192);
DECLARE_CHERI_TEST(test_bounds_stack_static_16384);
DECLARE_CHERI_TEST(test_bounds_stack_static_32768);
DECLARE_CHERI_TEST(test_bounds_stack_static_65536);
DECLARE_CHERI_TEST(test_bounds_stack_static_131072);
DECLARE_CHERI_TEST(test_bounds_stack_static_262144);
DECLARE_CHERI_TEST(test_bounds_stack_static_524288);
DECLARE_CHERI_TEST(test_bounds_stack_static_1048576);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_uint8);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_uint16);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_uint32);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_uint64);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_cap);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_16);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_32);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_64);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_128);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_256);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_512);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_1024);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_2048);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_4096);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_8192);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_16384);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_32768);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_65536);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_131072);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_262144);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_524288);
DECLARE_CHERI_TEST(test_bounds_stack_dynamic_1048576);

/* cheritest_ccall.c */
void	cheritest_ccall_setup(void);
DECLARE_CHERI_TEST(test_nofault_ccall_creturn);
DECLARE_CHERI_TEST(test_nofault_ccall_nop_creturn);
DECLARE_CHERI_TEST(test_nofault_ccall_dli_creturn);
DECLARE_CHERI_TEST(test_fault_creturn);
DECLARE_CHERI_TEST(test_fault_ccall_code_untagged);
DECLARE_CHERI_TEST(test_fault_ccall_data_untagged);
DECLARE_CHERI_TEST(test_fault_ccall_code_unsealed);
DECLARE_CHERI_TEST(test_fault_ccall_data_unsealed);
DECLARE_CHERI_TEST(test_fault_ccall_typemismatch);
DECLARE_CHERI_TEST(test_fault_ccall_code_noexecute);
DECLARE_CHERI_TEST(test_fault_ccall_data_execute);

/* cheritest_cheriabi.c */
DECLARE_CHERI_TEST(test_cheriabi_mmap_nospace);
DECLARE_CHERI_TEST(test_cheriabi_mmap_perms);
DECLARE_CHERI_TEST(test_cheriabi_mmap_unrepresentable);
DECLARE_CHERI_TEST(test_cheriabi_malloc_zero_size);

/* cheritest_cheriabi_open.c */
DECLARE_CHERI_TEST(test_cheriabi_open_ordinary);
DECLARE_CHERI_TEST(test_cheriabi_open_offset);
DECLARE_CHERI_TEST(test_cheriabi_open_shortened);
DECLARE_CHERI_TEST(test_cheriabi_open_bad_addr);
DECLARE_CHERI_TEST(test_cheriabi_open_bad_addr_2);
DECLARE_CHERI_TEST(test_cheriabi_open_bad_len);
DECLARE_CHERI_TEST(test_cheriabi_open_bad_len_2);
DECLARE_CHERI_TEST(test_cheriabi_open_bad_tag);
DECLARE_CHERI_TEST(test_cheriabi_open_bad_perm);
DECLARE_CHERI_TEST(test_cheriabi_open_sealed);

/* cheritest_fault.c */
DECLARE_CHERI_TEST(test_fault_bounds);
DECLARE_CHERI_TEST(test_fault_cgetcause);
DECLARE_CHERI_TEST(test_nofault_cfromptr);
DECLARE_CHERI_TEST(test_fault_perm_load);
DECLARE_CHERI_TEST(test_nofault_perm_load);
DECLARE_CHERI_TEST(test_fault_perm_seal);
DECLARE_CHERI_TEST(test_fault_perm_store);
DECLARE_CHERI_TEST(test_nofault_perm_store);
DECLARE_CHERI_TEST(test_fault_perm_unseal);
DECLARE_CHERI_TEST(test_fault_tag);
DECLARE_CHERI_TEST(test_fault_ccheck_user_fail);
DECLARE_CHERI_TEST(test_fault_read_kr1c);
DECLARE_CHERI_TEST(test_fault_read_kr2c);
DECLARE_CHERI_TEST(test_fault_read_kcc);
DECLARE_CHERI_TEST(test_fault_read_kdc);
DECLARE_CHERI_TEST(test_fault_read_epcc);
DECLARE_CHERI_TEST(test_nofault_ccheck_user_pass);

/* cheritest_fd.c */
#define	CHERITEST_FD_READ_STR	"read123"
#define	CHERITEST_FD_WRITE_STR	"write123"

extern int			 zero_fd;

extern struct sandbox_object	*sbop_stdin;
extern struct sandbox_object	*sbop_stdout;
extern struct sandbox_object	*sbop_zero;

DECLARE_CHERI_TEST(test_sandbox_fd_fstat);
DECLARE_CHERI_TEST(test_sandbox_fd_lseek);
DECLARE_CHERI_TEST(test_sandbox_fd_read);
DECLARE_CHERI_TEST(test_sandbox_fd_read_revoke);
DECLARE_CHERI_TEST(test_sandbox_fd_write);
DECLARE_CHERI_TEST(test_sandbox_fd_write_revoke);

/* cheritest_flag_captured.c */
DECLARE_CHERI_TEST(test_flag_captured);
DECLARE_CHERI_TEST(test_flag_captured_null);
#ifdef __CHERI_PURE_CAPABILITY__
DECLARE_CHERI_TEST(test_flag_captured_empty);
#endif

/* cheritest_kbounce.c */
DECLARE_CHERI_TEST(test_kbounce);

/* cheritest_libcheri.c */
extern struct sandbox_class	*cheritest_classp;
extern struct sandbox_object	*cheritest_objectp;

DECLARE_CHERI_TEST(test_sandbox_abort);
DECLARE_CHERI_TEST(test_sandbox_cs_calloc);
DECLARE_CHERI_TEST(test_sandbox_cs_clock_gettime);
DECLARE_CHERI_TEST(test_sandbox_cs_clock_gettime_default);
DECLARE_CHERI_TEST(test_sandbox_cs_clock_gettime_deny);
DECLARE_CHERI_TEST(test_sandbox_cs_helloworld);
DECLARE_CHERI_TEST(test_sandbox_cs_putchar);
DECLARE_CHERI_TEST(test_sandbox_cs_puts);
DECLARE_CHERI_TEST(test_sandbox_cxx_exception);
DECLARE_CHERI_TEST(test_sandbox_cxx_no_exception);
DECLARE_CHERI_TEST(test_sandbox_malloc);
DECLARE_CHERI_TEST_WITH_ARGS(test_sandbox_md5_ccall, int class2);
DECLARE_CHERI_TEST(test_sandbox_printf);
DECLARE_CHERI_TEST(test_sandbox_ptrdiff);
DECLARE_CHERI_TEST(test_sandbox_varargs);
DECLARE_CHERI_TEST(test_sandbox_va_copy);
DECLARE_CHERI_TEST(test_sandbox_spin);
DECLARE_CHERI_TEST(test_sandbox_userfn);
DECLARE_CHERI_TEST(test_2sandbox_newdestroy);
int	cheritest_libcheri_setup(void);
void	cheritest_libcheri_destroy(void);

/* cheritest_libcheritest_fault.c */
DECLARE_CHERI_TEST(test_sandbox_cp2_bound_catch);
DECLARE_CHERI_TEST(test_sandbox_cp2_bound_nocatch);
DECLARE_CHERI_TEST(test_sandbox_cp2_bound_nocatch_noaltstack);
DECLARE_CHERI_TEST(test_sandbox_cp2_perm_load_catch);
DECLARE_CHERI_TEST(test_sandbox_cp2_perm_load_nocatch);
DECLARE_CHERI_TEST(test_sandbox_cp2_perm_store_catch);
DECLARE_CHERI_TEST(test_sandbox_cp2_perm_store_nocatch);
DECLARE_CHERI_TEST(test_sandbox_cp2_tag_catch);
DECLARE_CHERI_TEST(test_sandbox_cp2_tag_nocatch);
DECLARE_CHERI_TEST(test_sandbox_cp2_seal_catch);
DECLARE_CHERI_TEST(test_sandbox_cp2_seal_nocatch);
DECLARE_CHERI_TEST(test_sandbox_divzero_catch);
DECLARE_CHERI_TEST(test_sandbox_divzero_nocatch);
DECLARE_CHERI_TEST(test_sandbox_vm_rfault_catch);
DECLARE_CHERI_TEST(test_sandbox_vm_rfault_nocatch);
DECLARE_CHERI_TEST(test_sandbox_vm_wfault_catch);
DECLARE_CHERI_TEST(test_sandbox_vm_wfault_nocatch);
DECLARE_CHERI_TEST(test_sandbox_vm_xfault_catch);
DECLARE_CHERI_TEST(test_sandbox_vm_xfault_nocatch);

/* cheritest_libcheri_local.c */
DECLARE_CHERI_TEST(test_sandbox_store_global_capability_in_bss);
DECLARE_CHERI_TEST(test_sandbox_store_local_capability_in_bss_catch);
DECLARE_CHERI_TEST(test_sandbox_store_local_capability_in_bss_nocatch);
DECLARE_CHERI_TEST(test_sandbox_store_global_capability_in_stack);
DECLARE_CHERI_TEST(test_sandbox_store_local_capability_in_stack);
DECLARE_CHERI_TEST(test_sandbox_return_global_capability);
DECLARE_CHERI_TEST(test_sandbox_return_local_capability);
DECLARE_CHERI_TEST(test_sandbox_pass_local_capability_arg);

/* cheritest_libcheri_pthreads.c */
DECLARE_CHERI_TEST(test_sandbox_pthread_abort);
DECLARE_CHERI_TEST(test_sandbox_pthread_cs_helloworld);

/* cheritest_libcheri_trustedstack.c */
register_t	cheritest_libcheri_userfn_getstack(void);
register_t	cheritest_libcheri_userfn_setstack(register_t arg);
DECLARE_CHERI_TEST(test_sandbox_getstack);
DECLARE_CHERI_TEST(test_sandbox_setstack);
DECLARE_CHERI_TEST(test_sandbox_setstack_nop);
DECLARE_CHERI_TEST(test_sandbox_trustedstack_underflow);

/* cheritest_libcheri_var.c */
DECLARE_CHERI_TEST(test_sandbox_var_bss);
DECLARE_CHERI_TEST(test_sandbox_var_data);
DECLARE_CHERI_TEST(test_sandbox_var_data_getset);
DECLARE_CHERI_TEST(test_2sandbox_var_data_getset);
DECLARE_CHERI_TEST(test_sandbox_var_constructor);

/* cheritest_longjmp.c */
DECLARE_CHERI_TEST(cheritest_setjmp);
DECLARE_CHERI_TEST(cheritest_setjmp_longjmp);

/* cheritest_sealcap.c */
DECLARE_CHERI_TEST(test_sealcap_sysarch);
DECLARE_CHERI_TEST(test_sealcap_seal);
DECLARE_CHERI_TEST(test_sealcap_seal_unseal);

/* cheritest_signal.c */
DECLARE_CHERI_TEST(test_signal_handler_usr1);
DECLARE_CHERI_TEST(test_signal_sigaction_usr1);
DECLARE_CHERI_TEST(test_signal_sigaltstack);
DECLARE_CHERI_TEST(test_signal_sigaltstack_disable);

/* cheritest_string.c */
DECLARE_CHERI_TEST(test_string_kern_memcpy_c);
DECLARE_CHERI_TEST(test_string_kern_memmove_c);
DECLARE_CHERI_TEST(test_string_memcpy);
DECLARE_CHERI_TEST(test_string_memcpy_c);
DECLARE_CHERI_TEST(test_string_memmove);
DECLARE_CHERI_TEST(test_string_memmove_c);

DECLARE_CHERI_TEST(test_unaligned_capability_copy_memcpy);
DECLARE_CHERI_TEST(test_unaligned_capability_copy_memmove);

/* cheritest_syscall.c */
DECLARE_CHERI_TEST(test_sandbox_syscall);
DECLARE_CHERI_TEST(test_sig_dfl_neq_ign);
DECLARE_CHERI_TEST(test_sig_dfl_ign);
DECLARE_CHERI_TEST(test_ptrace_basic);

/* cheritest_registers.c */
DECLARE_CHERI_TEST(test_initregs_default);
#ifdef __CHERI_PURE_CAPABILITY__
DECLARE_CHERI_TEST(test_initregs_stack);
DECLARE_CHERI_TEST(test_initregs_stack_user_perms);
#endif
DECLARE_CHERI_TEST(test_initregs_idc);
DECLARE_CHERI_TEST(test_initregs_pcc);
DECLARE_CHERI_TEST(test_copyregs);
DECLARE_CHERI_TEST(test_listregs);

/* cheritest_tls.c */
DECLARE_CHERI_TEST(test_tls_align_4k);
DECLARE_CHERI_TEST(test_tls_align_cap);
DECLARE_CHERI_TEST(test_tls_align_ptr);

/* cheritest_tls_threads.c */
DECLARE_CHERI_TEST(test_tls_threads);

/* cheritest_vm.c */
DECLARE_CHERI_TEST(cheritest_vm_tag_mmap_anon);;
DECLARE_CHERI_TEST(cheritest_vm_tag_shm_open_anon_shared);
DECLARE_CHERI_TEST(cheritest_vm_tag_shm_open_anon_private);
DECLARE_CHERI_TEST(cheritest_vm_tag_shm_open_anon_shared2x);
DECLARE_CHERI_TEST(cheritest_vm_shm_open_anon_unix_surprise);
#ifdef CHERIABI_TESTS
DECLARE_CHERI_TEST(cheritest_vm_cap_share_fd_kqueue);
DECLARE_CHERI_TEST(cheritest_vm_cap_share_sigaction);
#endif
DECLARE_CHERI_TEST(cheritest_vm_tag_dev_zero_shared);
DECLARE_CHERI_TEST(cheritest_vm_tag_dev_zero_private);
DECLARE_CHERI_TEST(cheritest_vm_notag_tmpfile_shared);
DECLARE_CHERI_TEST(cheritest_vm_tag_tmpfile_private);
DECLARE_CHERI_TEST(cheritest_vm_tag_tmpfile_private_prefault);
DECLARE_CHERI_TEST(cheritest_vm_cow_read);
DECLARE_CHERI_TEST(cheritest_vm_cow_write);
const char	*xfail_need_writable_tmp(const char *name);

/* cheritest_vm_swap.c */
DECLARE_CHERI_TEST(cheritest_vm_swap);
const char	*xfail_swap_required(const char *name);

/* cheritest_zlib.c */
DECLARE_CHERI_TEST(test_deflate_zeroes);
DECLARE_CHERI_TEST(test_inflate_zeroes);
DECLARE_CHERI_TEST(test_sandbox_inflate_zeroes);

/* For libc_memcpy and libc_memset tests and the unaligned copy tests: */
extern void *cheritest_memcpy(void *dst, const void *src, size_t n);
extern void *cheritest_memmove(void *dst, const void *src, size_t n);

#ifdef CHERI_C_TESTS
#define	DECLARE_TEST(name, desc) \
    void cheri_c_test_ ## name(const struct cheri_test *ctp __unused);
#define DECLARE_TEST_FAULT(name, desc)	\
    void cheri_c_test_ ## name(const struct cheri_test *ctp __unused);
#include <cheri_c_testdecls.h>
#undef DECLARE_TEST
#undef DECLARE_TEST_FAULT
#endif

#endif /* !_CHERITEST_H_ */
