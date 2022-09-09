/*-
 * Copyright (c) 2012-2018, 2020 Robert N. M. Watson
 * Copyright (c) 2014-2016 SRI International
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

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/param.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/wait.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/frame.h>
#include <machine/trap.h>

#include <machine/sysarch.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stringlist.h>
#include <sysexits.h>
#include <unistd.h>
#include <vis.h>

#include <libxo/xo.h>

#include "cheribsdtest.h"

SET_DECLARE(cheri_tests_set, struct cheri_test);

static StringList* cheri_failed_tests;
static StringList* cheri_xfailed_tests;
static StringList* cheri_xpassed_tests;

/* Shared memory page with child process. */
struct cheribsdtest_child_state *ccsp;

static char *argv0;

static int tests_run;
static int tests_failed, tests_passed, tests_xfailed, tests_xpassed;
static int execed;
static int expected_failures;
static int list;
static int run_all;
static int fast_tests_only;
static int qtrace;
static int qtrace_user_mode_only;
static int sleep_after_test;
static int verbose;
static int coredump_enabled;
static int debugger_enabled;

static void
usage(void)
{

	fprintf(stderr,
"usage:\n"
"    " PROG " [options] -l               -- List tests\n"
"    " PROG " [options] -a               -- Run all tests\n"
"    " PROG " [options] <test> [...]     -- Run specified tests\n"
"    " PROG " [options] -g <glob> [...]  -- Run matching tests\n"
"\n"
"options:\n"
"    -f  -- Only include \"fast\" tests\n"
"    -c  -- Enable core dumps\n"
"    -d  -- Attach debugger before running test\n"
"    -s  -- Sleep one second after each test\n"
"    -q  -- Enable qemu tracing in test process\n"
"    -Q  -- Enable qemu tracing in test process (user-mode only)\n"
"    -v  -- Increase verbosity\n"
"    -x  -- Output JUnit XML format\n"
	     );
	exit(EX_USAGE);
}

static void
list_tests(void)
{
	const char *xfail_reason;
	struct cheri_test **ctp, *ct;

	xo_attr("name", "%s", PROG);
	xo_open_container("testsuite");
	xo_open_list("testcase");
	SET_FOREACH(ctp, cheri_tests_set) {
		ct = *ctp;
		if (fast_tests_only && (ct->ct_flags & CT_FLAG_SLOW))
			continue;
		xo_open_instance("testcase");
		if (verbose)
			xo_emit("{cw:name/%s}{:description/%s}",
			    ct->ct_name, ct->ct_desc);
		else
			xo_emit("{:name/%s}{e:description/%s}",
			    ct->ct_name, ct->ct_desc);
		if (ct->ct_check_xfail)
			xfail_reason = ct->ct_check_xfail(ct->ct_name);
		else
			xfail_reason = ct->ct_xfail_reason;
		if (xfail_reason)
			xo_emit("{e:expected-failure-reason/%s}",
			    xfail_reason);
		if (ct->ct_flags & CT_FLAG_SLOW)
			xo_emit("{e:timeout/%s}", "LONG");
		xo_emit("\n");
		xo_close_instance("testcase");
	}
	xo_close_list("testcase");
	xo_close_container("testsuite");
	xo_finish();

	exit(EX_OK);
}

static void
signal_handler(int signum, siginfo_t *info, void *vuap __unused)
{
	ccsp->ccs_signum = signum;
	ccsp->ccs_si_code = info->si_code;
	ccsp->ccs_si_trapno = info->si_trapno;
	ccsp->ccs_si_addr = info->si_addr;

	/*
	 * Signal delivered outside of a sandbox; catch but terminate
	 * test.  Use EX_SOFTWARE as the parent handler will recognise
	 * this as an appropriate exit code when a signal is handled.
	 */
	_exit(EX_SOFTWARE);
}

void
signal_handler_clear(int sig)
{
	struct sigaction sa;

	/* XXXRW: Possibly should just not be registering it? */
	bzero(&sa, sizeof(sa));
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, NULL) < 0)
		cheribsdtest_failure_err("clearing handler for sig %d", sig);
}

static inline void
set_thread_tracing(void)
{
#ifdef CHERI_START_TRACE
	int error, intval;

	intval = 1;
	error = sysarch(QEMU_SET_QTRACE, &intval);
	if (error)
		err(EX_OSERR, "QEMU_SET_QTRACE");
	/*
	 * Change won't take affect until next context switch; make sure we have
	 * tracing on right from the start.
	 */
	CHERI_START_TRACE;
	if (qtrace_user_mode_only)
		CHERI_START_USER_TRACE;
#else
	err(EX_OSERR, "%s", __func__);
#endif
}

/* Maximum size of stdout data we will check if called for by a test. */
#define	TEST_BUFFER_LEN	1024

static void
cheribsdtest_run_test(const struct cheri_test *ctp)
{
	struct sigaction sa;
	pid_t childpid;
	int status, pipefd_stdin[2], pipefd_stdout[2];
	char reason[TESTRESULT_STR_LEN * 2]; /* Potential output, plus some extra */
	char visreason[sizeof(reason) * 4]; /* Space for vis(3) the string */
	char buffer[TEST_BUFFER_LEN];
	const char *xfail_reason, *flaky_reason;
	char* failure_message;
	ssize_t len;
	xo_attr("classname", "%s.%s", PROG, ctp->ct_name);
	xo_attr("name", "%s", ctp->ct_desc);
	xo_open_instance("testcase");
	bzero(ccsp, sizeof(*ccsp));
	xo_emit("TEST: {d:name/%s}: {d:description/%s}\n", ctp->ct_name,
		    ctp->ct_desc);
	reason[0] = '\0';
	visreason[0] = '\0';

	if (fast_tests_only && (ctp->ct_flags & CT_FLAG_SLOW))
		return;

	if (ctp->ct_check_xfail != NULL)
		xfail_reason = ctp->ct_check_xfail(ctp->ct_name);
	else
		xfail_reason = ctp->ct_xfail_reason;
	flaky_reason = ctp->ct_flaky_reason;
	if (xfail_reason != NULL) {
		expected_failures++;
	}

	if (pipe(pipefd_stdin) < 0)
		err(EX_OSERR, "pipe");
	if (pipe(pipefd_stdout) < 0)
		err(EX_OSERR, "pipe");

	/* If stdin is to be filled, fill it. */
	if (ctp->ct_flags & CT_FLAG_STDIN_STRING) {
		len = write(pipefd_stdin[1], ctp->ct_stdin_string,
		    strlen(ctp->ct_stdin_string));
		if (len < 0) {
			snprintf(reason, sizeof(reason),
			    "write() on test stdin failed with -1 (%d)",
			    errno);
			goto fail;
		}
		if (len != (ssize_t)strlen(ctp->ct_stdin_string)) {
			snprintf(reason, sizeof(reason),
			    "write() on test stdin expected %lu but got %ld",
			    strlen(ctp->ct_stdin_string), len);
			goto fail;
		}
	}

	/*
	 * Flush stdout and stderr before forking so that we don't risk seeing
	 * the output again in the child process, which could confuse the test
	 * framework.
	 */
	fflush(stdout);
	fflush(stderr);

	/*
	 * Create a child process with suitable signal handling and stdio set
	 * up; execute the test case.
	 */
	childpid = fork();
	if (childpid < 0)
		err(EX_OSERR, "fork");
	if (childpid == 0) {
		/* Install signal handlers. */
		sa.sa_sigaction = signal_handler;
		sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGALRM, &sa, NULL) < 0)
			err(EX_OSERR, "sigaction(SIGALRM)");
		if (sigaction(SIGPROT, &sa, NULL) < 0)
			err(EX_OSERR, "sigaction(SIGPROT)");
		if (sigaction(SIGSEGV, &sa, NULL) < 0)
			err(EX_OSERR, "sigaction(SIGSEGV)");
		if (sigaction(SIGBUS, &sa, NULL) < 0)
			err(EX_OSERR, "sigaction(SIGBUS");
		if (sigaction(SIGEMT, &sa, NULL) < 0)
			err(EX_OSERR, "sigaction(SIGEMT)");
		if (sigaction(SIGTRAP, &sa, NULL) < 0)
			err(EX_OSERR, "sigaction(SIGEMT)");

		/*
		 * Set up synthetic stdin and stdout.
		 */
		if (dup2(pipefd_stdin[0], STDIN_FILENO) < 0)
			err(EX_OSERR, "dup2(STDIN_FILENO)");
		if (dup2(pipefd_stdout[1], STDOUT_FILENO) < 0)
			err(EX_OSERR, "dup2(STDOUT_FILENO)");
		close(pipefd_stdin[0]);
		close(pipefd_stdin[1]);
		close(pipefd_stdout[0]);
		close(pipefd_stdout[1]);

		if (qtrace)
			set_thread_tracing();

		/* When debugging wait until GDB has attached */
		if (debugger_enabled) {
			if (verbose)
				fprintf(stderr,
				    "Waiting for GDB to attach to %d\n",
				    getpid());
			raise(SIGSTOP);
		}

		/* Run the actual test. */
		ctp->ct_func(ctp);
		exit(0);
	}
	close(pipefd_stdin[0]);
	close(pipefd_stdout[1]);
	if (fcntl(pipefd_stdout[0], F_SETFL, O_NONBLOCK) < 0)
		err(EX_OSERR, "fcntl(F_SETFL, O_NONBLOCK) on test stdout");

	tests_run++;

	if (debugger_enabled) {
		char command[256];
		snprintf(
		    command, sizeof(command), "gdb --pid=%d", childpid);
		if (verbose)
			fprintf(stderr, "Running '%s' to debug %s\n", command,
			    ctp->ct_name);
		system(command);
	}

	(void)waitpid(childpid, &status, 0);

	/*
	 * If the test explicitly signalled failure for some reason, report
	 * this first rather than reporting an expected failure that has
	 * not yet been triggered.
	 */
	if (ccsp->ccs_testresult == TESTRESULT_FAILURE) {
		/*
		 * Ensure string is nul-terminated, as we will print
		 * it in due course, and a failed test might have left
		 * a corrupted string.
		 */
		ccsp->ccs_testresult_str[sizeof(ccsp->ccs_testresult_str) - 1] =
		    '\0';
		memcpy(reason, ccsp->ccs_testresult_str,
		    sizeof(ccsp->ccs_testresult_str));
		goto fail;
	}

	/*
	 * Check for errors from the test framework: successful process
	 * termination, signal disposition/exception codes/etc.  Analyse
	 * child's signal state returned via shared memory.
	 */
	if (ctp->ct_flags & CT_FLAG_SIGEXIT) {
		if (!WIFSIGNALED(status)) {
			snprintf(reason, sizeof(reason),
			    "Expected child termination with signal %d",
			    ctp->ct_signum);
			goto fail;
		}
		if (WTERMSIG(status) != ctp->ct_signum) {
			snprintf(reason, sizeof(reason),
			    "Expected child termination with signal %d; got %d",
			    ctp->ct_signum, WTERMSIG(status));
			goto fail;
		}

		/*
		 * Skip remaining checks as process has terminated as
		 * expected.
		 */
		goto pass;
	}
	if (!WIFEXITED(status)) {
		snprintf(reason, sizeof(reason), "Child exited abnormally");
		goto fail;
	}
	if (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != EX_SOFTWARE) {
		snprintf(reason, sizeof(reason), "Child status %d",
		    WEXITSTATUS(status));
		goto fail;
	}
	if (ccsp->ccs_signum < 0) {
		snprintf(reason, sizeof(reason),
		    "Child returned negative signal %d", ccsp->ccs_signum);
		goto fail;
	}
	if ((ctp->ct_flags & CT_FLAG_SIGNAL) &&
	    ccsp->ccs_signum != ctp->ct_signum) {
		snprintf(reason, sizeof(reason), "Expected signal %d, got %d",
		    ctp->ct_signum, ccsp->ccs_signum);
		goto fail;
	}
	if ((ctp->ct_flags & CT_FLAG_SI_CODE) &&
	    ccsp->ccs_si_code != ctp->ct_si_code) {
		snprintf(reason, sizeof(reason), "Expected si_code %d, got %d",
		    ctp->ct_si_code, ccsp->ccs_si_code);
		goto fail;
	}
	if ((ctp->ct_flags & CT_FLAG_SI_TRAPNO) &&
	    ccsp->ccs_si_trapno != ctp->ct_si_trapno) {
		snprintf(reason, sizeof(reason),
		    "Expected si_trapno %d, got %d", ctp->ct_si_trapno,
		    ccsp->ccs_si_trapno);
		goto fail;
	}
	if ((ctp->ct_flags & CT_FLAG_SI_ADDR) &&
	    !cheri_ptr_equal_exact(ccsp->ccs_si_addr_expected, ccsp->ccs_si_addr)) {
		snprintf(reason, sizeof(reason), "Expected si_addr %#p, got %#p",
		    ccsp->ccs_si_addr_expected, ccsp->ccs_si_addr);
		goto fail;
	}

	/*
	 * Next, we are concerned with whether the test itself reports a
	 * success.  This is based not on whether the test experiences a
	 * fault, but whether its semantics are correct -- e.g., did code in a
	 * sandbox run as expected.  Tests that have successfully experienced
	 * an expected/desired fault don't undergo these checks.
	 */
	if (!(ctp->ct_flags & CT_FLAG_SIGNAL)) {
		if (ccsp->ccs_testresult == TESTRESULT_UNKNOWN) {
			snprintf(reason, sizeof(reason),
			    "Test failed to set a success/failure status");
			goto fail;
		}
		if (ccsp->ccs_testresult != TESTRESULT_SUCCESS) {
			snprintf(reason, sizeof(reason),
			    "Test returned unexpected result (%d)",
			    ccsp->ccs_testresult);
			goto fail;
		}
	}

	/*
	 * Next, see whether any expected output was present.
	 */
	len = read(pipefd_stdout[0], buffer, sizeof(buffer) - 1);
	if (len < 0) {
		xo_attr("message", "%s", strerror(errno));
		xo_attr("type", "%d", errno);
		xo_emit("{e:error/%s}", "read() failed");
	} else {
		buffer[len] = '\0';
		if (len > 0) {
			if (ctp->ct_flags & CT_FLAG_STDOUT_IGNORE)
				xo_attr("ignored", "true");
			xo_emit("{e:system-out/%s}", buffer);
		}
	}
	if (ctp->ct_flags & CT_FLAG_STDOUT_STRING) {
		if (len < 0) {
			snprintf(reason, sizeof(reason),
			    "read() on test stdout failed with -1 (%d)",
			    errno);
			goto fail;
		}
		buffer[len] = '\0';
		if (strcmp(buffer, ctp->ct_stdout_string) != 0) {
			if (verbose)
				snprintf(reason, sizeof(reason),
				    "read() on test stdout expected '%s' "
				    "but got '%s'",
				    ctp->ct_stdout_string, buffer);
			else
				snprintf(reason, sizeof(reason),
				    "read() on test stdout did not match");
			goto fail;
		}
	} else if (!(ctp->ct_flags & CT_FLAG_STDOUT_IGNORE)) {
		if (len > 0) {
			if (verbose)
				snprintf(reason, sizeof(reason),
				    "read() on test stdout produced "
				    "unexpected output '%s'", buffer);
			else
				snprintf(reason, sizeof(reason),
				    "read() on test stdout produced "
				    "unexpected output");
			goto fail;
		}
	}

pass:
	if (xfail_reason != NULL) {
		/* Passed but we expected failure */
		xo_emit("XPASS: {d:name/%s} (Expected failure due to "
			"{d:reason/%s}) {e:failure/XPASS: %s}\n", ctp->ct_name,
		    xfail_reason, xfail_reason);
		asprintf(&failure_message, "%s: %s", ctp->ct_name, xfail_reason);
		tests_xpassed++;
		sl_add(cheri_xpassed_tests, failure_message);
	} else {
		xo_emit("{d:status/%s}: {d:name/%s}\n", "PASS", ctp->ct_name);
		tests_passed++;
	}
	close(pipefd_stdin[1]);
	close(pipefd_stdout[0]);
	xo_close_instance("testcase");
	xo_flush();
	if (sleep_after_test)
		sleep(1);
	return;

fail:
	/*
	 * Escape non-printing characters.
	 */
	strnvis(visreason, sizeof(visreason), reason, VIS_TAB);
	asprintf(&failure_message, "%s: %s", ctp->ct_name, visreason);
	if (xfail_reason == NULL && flaky_reason == NULL) {
		xo_emit("FAIL: {d:name/%s}: {:failure/%s}\n",
		    ctp->ct_name, visreason);
		tests_failed++;
		sl_add(cheri_failed_tests, failure_message);
	} else {
		/*
		 * xfail_reason != NULL was already handled earlier. If
		 * xfail_reason is NULL then we know that flaky_reason is not
		 * NULL, and so we pretend that the failure is expected.
		 */
		if (xfail_reason == NULL)
			expected_failures++;
		if (flaky_reason != NULL)
			xfail_reason = flaky_reason;
		if (xo_get_style(NULL) == XO_STYLE_XML) {
			xo_attr("message", "%s", xfail_reason);
			xo_emit("{e:skipped/%s}", "");
		} else {
			xo_emit(
			    "{d:status/%s}: {d:name/%s}: "
			    "{:failure-reason/%s} ({d:expected-failure-reason/%s})\n",
			    "XFAIL", ctp->ct_name, visreason, xfail_reason);
		}
		tests_xfailed++;
		sl_add(cheri_xfailed_tests, failure_message);
	}
	xo_close_instance("testcase");
	xo_flush();
	close(pipefd_stdin[1]);
	close(pipefd_stdout[0]);
	if (sleep_after_test)
		sleep(1);
}

static void
cheribsdtest_run_test_name(const char *name)
{
	struct cheri_test **ctp, *ct;

	SET_FOREACH(ctp, cheri_tests_set) {
		ct = *ctp;
		if (strcmp(name, ct->ct_name) == 0) {
			cheribsdtest_run_test(ct);
			return;
		}
	}
	errx(EX_USAGE, "unknown test: %s", name);
}

static void
cheribsdtest_run_child(struct cheri_test *ctp)
{
	if (ctp->ct_child_func == NULL)
		errx(EX_SOFTWARE, "%s has no child function", ctp->ct_name);
	ctp->ct_child_func(ctp);
	errx(EX_SOFTWARE, "%s child function returned", ctp->ct_name);
}

static void
cheribsdtest_run_child_name(const char *name)
{
	struct cheri_test **ctpp, *ctp;

	SET_FOREACH(ctpp, cheri_tests_set) {
		ctp = *ctpp;
		if (strcmp(name, ctp->ct_name) == 0) {
			cheribsdtest_run_child(ctp);
		}
	}
	errx(EX_USAGE, "unknown test: %s", name);
}

static char **
mk_exec_args(const struct cheri_test *ctp)
{
	char *execpath;
	char const **exec_args;
	int argc = 0, error;

	execpath = malloc(MAXPATHLEN);
	if (execpath == NULL)
		err(EX_OSERR, "malloc");
	exec_args = calloc(5, sizeof(*exec_args));
	if (exec_args == NULL)
		err(EX_OSERR, "calloc");

	/*
	 * XXXBD: it would be nice if there was a way to say "coexecve
	 * myself".
	 */
	error = elf_aux_info(AT_EXECPATH, execpath, MAXPATHLEN);
	if (error != 0)
		errx(EX_OSERR, "elf_aux_info: %s", strerror(error));
	exec_args[argc++] = execpath;
	exec_args[argc++] = "-E";
	if (coredump_enabled)
		exec_args[argc++] = "-c";
	exec_args[argc++] = ctp->ct_name;
	exec_args[argc++] = NULL;

	return (__DECONST(char **, exec_args));
}

void
cheribsdtest_coexec_child(const struct cheri_test *ctp)
{
	char **exec_args;

	exec_args = mk_exec_args(ctp);
	coexecve(getppid(), exec_args[0], exec_args, NULL);
	err(EX_OSERR, "%s: coexecve", __func__);
}

void
cheribsdtest_exec_child(const struct cheri_test *ctp)
{
	char **exec_args;

	exec_args = mk_exec_args(ctp);
	execve(exec_args[0], exec_args, NULL);
	err(EX_OSERR, "%s: execve", __func__);
}

__noinline void *
cheribsdtest_memcpy(void *dst, const void *src, size_t n)
{
	return memcpy(dst, src, n);
}

__noinline void *
cheribsdtest_memmove(void *dst, const void *src, size_t n)
{
	return memmove(dst, src, n);
}

int
main(int argc, char *argv[])
{
	struct rlimit rl;
	int opt;
	int glob = 0;
	stack_t stack;
	int i;
	uint qemu_trace_perthread;
	size_t len;
	const char *sep;
	struct cheri_test **ctp, *ct;

	argv0 = argv[0];
	argc = xo_parse_args(argc, argv);
	if (argc < 0)
		errx(1, "xo_parse_args failed\n");
	while ((opt = getopt(argc, argv, "acdEfglQqsuvx")) != -1) {
		switch (opt) {
		case 'a':
			run_all = 1;
			break;
		case 'c':
			coredump_enabled = 1;
			break;
		case 'd':
			debugger_enabled = 1;
			break;
		case 'E':
			execed = 1;
			break;
		case 'f':
			fast_tests_only = 1;
			break;
		case 'g':
			glob = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'Q':
			qtrace_user_mode_only = 1;
			/* FALLTHROUGH */
		case 'q':
			len = sizeof(qemu_trace_perthread);
			if (sysctlbyname("hw.qemu_trace_perthread",
			    &qemu_trace_perthread,
			    &len, NULL, 0) < 0)
				err(EX_OSERR,
				    "sysctlbyname(\"hw.qemu_trace_perthread\")");
			if (!qemu_trace_perthread)
				errx(EX_USAGE, "-%c requires sysctl "
				    "hw.qemu_trace_perthread=1", opt);
			qtrace = 1;
			break;
		case 's':
			sleep_after_test = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'x': /* JUnit XML output */
			/* XXX: allow an argument to specify output file? */
			xo_set_style(NULL, XO_STYLE_XML);
			xo_set_flags(NULL, XOF_PRETTY);
			break;
		default:
			warnx("unknown argument %c\n", opt);
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (execed) {
		if (run_all || glob || list) {
			warnx("-E is incompatbile with -a, -g, and -l");
			usage();
		}
		if (argc != 1) {
			warnx("-E requires exactly one test argument");
			usage();
		}
	}
	if (run_all && list) {
		warnx("-a and -l are incompatible");
		usage();
	}
	if (run_all && glob) {
		warnx("-a and -g are incompatible");
		usage();
	}
	if (list) {
		if (argc == 0)
			list_tests();
		/* XXXBD: should we allow this for test automation? */
		warnx("-l and a list of tests are incompatible");
		usage();
	}
	if (argc == 0 && !run_all)
		usage();
	if (argc > 0 && run_all) {
		warnx("-a and a list of test are incompatible");
		usage();
	}

	/*
	 * Allocate an alternative stack, required to safely process signals in
	 * sandboxes.
	 *
	 * XXX: Is this still needed now we no longer have libcheri sandboxes?
	 */
	stack.ss_size = MAX(getpagesize(), SIGSTKSZ);
	stack.ss_sp = mmap(NULL, stack.ss_size, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (stack.ss_sp == MAP_FAILED)
		err(EX_OSERR, "mmap");
	stack.ss_flags = 0;
	if (sigaltstack(&stack, NULL) < 0)
		err(EX_OSERR, "sigaltstack");

	/*
	 * We've been (co)execed so look up our child function and run it.
	 */
	if (execed)
		cheribsdtest_run_child_name(argv[0]);

	/*
	 * Allocate a page shared with children processes to return success/
	 * failure status.
	 */
	assert(sizeof(*ccsp) <= (size_t)getpagesize());
	ccsp = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_ANON, -1,
	    0);
	if (ccsp == MAP_FAILED)
		err(EX_OSERR, "mmap");
	if (minherit(ccsp, getpagesize(), INHERIT_SHARE) < 0)
		err(EX_OSERR, "minherit");

	/*
	 * Disable core dumps unless specifically enabled.
	 */
	if (!coredump_enabled) {
		bzero(&rl, sizeof(rl));
		if (setrlimit(RLIMIT_CORE, &rl) < 0)
			err(EX_OSERR, "setrlimit");
	}

	cheri_failed_tests = sl_init();
	cheri_xfailed_tests = sl_init();
	cheri_xpassed_tests = sl_init();
	/* Run the actual tests. */
	xo_open_container("testsuites");
	xo_attr("name", "%s", PROG);
	xo_open_container("testsuite");
	xo_open_list("test");
	if (run_all) {
		SET_FOREACH(ctp, cheri_tests_set) {
			ct = *ctp;
			cheribsdtest_run_test(ct);
		}
	} else if (glob) {
		for (i = 0; i < argc; i++) {
			SET_FOREACH(ctp, cheri_tests_set) {
				ct = *ctp;
				if (fnmatch(argv[i], ct->ct_name, 0) != 0)
					continue;
				cheribsdtest_run_test(ct);
			}
		}
	} else {
		for (i = 0; i < argc; i++) {
			cheribsdtest_run_test_name(argv[i]);
		}
	}
	xo_close_list("test");
	xo_close_container("testsuite");
	xo_close_container("testsuites");

	/* print a summary which tests failed */
	if (cheri_xfailed_tests->sl_cur != 0) {
		xo_emit("Expected failures:\n");
		for (i = 0; (size_t)i < cheri_xfailed_tests->sl_cur; i++)
			xo_emit("  {d:%s}\n", cheri_xfailed_tests->sl_str[i]);
	}
	if (cheri_failed_tests->sl_cur != 0) {
		xo_emit("Unexpected failures:\n");
		for (i = 0; (size_t)i < cheri_failed_tests->sl_cur; i++)
			xo_emit("  {d:%s}\n", cheri_failed_tests->sl_str[i]);
	}
	if (cheri_xpassed_tests->sl_cur != 0) {
		xo_emit("Unexpected passes:\n");
		for (i = 0; (size_t)i < cheri_xpassed_tests->sl_cur; i++)
			xo_emit("  {d:%s}\n", cheri_xpassed_tests->sl_str[i]);
	}
	sl_free(cheri_failed_tests, true);
	sl_free(cheri_xfailed_tests, true);
	sl_free(cheri_xpassed_tests, true);
	if (tests_run > 1) {
		xo_emit("{Lc:SUMMARY}");
		sep = " ";
#define	EMIT_SUMMARY_FIELD(label, value)				\
		do {							\
			if (value > 0) {				\
				xo_emit("{P:/%s}{Lw:" label "}{d:/%d}",	\
				    sep, value);			\
				sep = ", ";				\
			}						\
		} while (0)
		EMIT_SUMMARY_FIELD("passed", tests_passed);
		EMIT_SUMMARY_FIELD("failed", tests_failed);
		EMIT_SUMMARY_FIELD("expectedly failed", tests_xfailed);
		EMIT_SUMMARY_FIELD("unexpectedly passed", tests_xpassed);
#undef	EMIT_SUMMARY_FIELD
		xo_emit("\n");
	}
	xo_finish();

	if (tests_failed > 0)
		exit(-1);
	exit(EX_OK);
}
