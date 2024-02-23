/*-
 * Copyright (c) 2014, 2016 Robert N. M. Watson
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

/*
 * A few non-faulting CHERI-related virtual-memory tests.
 */

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <cheri/revoke.h>
#include <sys/event.h>

#include <machine/frame.h>
#include <machine/trap.h>
#include <machine/vmparam.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libprocstat.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

static const char *skip_need_writable_tmp(const char *name __unused);

/*
 * Tests to check that tags are ... or aren't ... preserved for various page
 * types.  'Anonymous' pages provided by the VM subsystem should always
 * preserve tags.  Pages from the filesystem should not -- unless they are
 * mapped MAP_PRIVATE, in which case they should, since they are effectively
 * anonymous pages.  Or so I claim.
 *
 * Most test cases only differ in the mmap flags and the file descriptor, this
 * function does all the shared checks
 */
static void
mmap_and_check_tag_stored(int fd, int protflags, int mapflags)
{
	void * __capability volatile *cp;
	void * __capability cp_value;
	int v;

	cp = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(), protflags,
	     mapflags, fd, 0));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;
	cp_value = *cp;
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp_value) != 0, "tag lost");
	CHERIBSDTEST_CHECK_SYSCALL(munmap(__DEVOLATILE(void *, cp), getpagesize()));
	if (fd != -1)
		CHERIBSDTEST_CHECK_SYSCALL(close(fd));
}

CHERIBSDTEST(vm_tag_mmap_anon,
    "check tags are stored for MAP_ANON pages")
{
	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE, MAP_ANON);
	cheribsdtest_success();
}

CHERIBSDTEST(vm_tag_shm_open_anon_shared,
    "check tags are stored for SHM_ANON MAP_SHARED pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED);
	cheribsdtest_success();
}

CHERIBSDTEST(vm_tag_shm_open_anon_private,
    "check tags are stored for SHM_ANON MAP_PRIVATE pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	cheribsdtest_success();
}

/*
 * Test aliasing of SHM_ANON objects
 */
CHERIBSDTEST(vm_tag_shm_open_anon_shared2x,
    "test multiply-mapped SHM_ANON objects")
{
	void * __capability volatile * map2;
	void * __capability c2;
	int fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	map2 = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
		PROT_READ, MAP_SHARED, fd, 0));

	/* Verify that no capability present */
	c2 = *map2;
	CHERIBSDTEST_VERIFY2(cheri_gettag(c2) == 0, "tag exists on first read");
	CHERIBSDTEST_VERIFY2(c2 == NULL, "Initial read NULL");

	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED);

	/* And now verify that it is, thanks to the aliased maps */
	c2 = *map2;
	CHERIBSDTEST_VERIFY2(cheri_gettag(c2) != 0, "tag lost on second read");
	CHERIBSDTEST_VERIFY2(c2 != NULL, "Second read not NULL");

	cheribsdtest_success();
}

CHERIBSDTEST(vm_shm_open_anon_unix_surprise,
    "test SHM_ANON vs SCM_RIGHTS",
    .ct_xfail_reason =
	"Tags currently survive cross-AS aliasing of SHM_ANON objects")
{
	int sv[2];
	int pid;

	CHERIBSDTEST_CHECK_SYSCALL(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0);

	pid = fork();
	if (pid == -1)
		cheribsdtest_failure_errx("Fork failed; errno=%d", errno);

	if (pid == 0) {
		void * __capability * map;
		void * __capability c;
		int fd, tag;
		struct msghdr msg = { 0 };
		struct cmsghdr * cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(fd))] = { 0 } ;
		char iovbuf[16];
		struct iovec iov = { .iov_base = iovbuf, .iov_len = sizeof(iovbuf) };

		close(sv[1]);

		/* Read from socket */
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		CHERIBSDTEST_CHECK_SYSCALL(recvmsg(sv[0], &msg, 0));

		/* Deconstruct cmsg */
		/* XXX Doesn't compile: cmsg = CMSG_FIRSTHDR(&msg); */
		cmsg = msg.msg_control;
		memmove(&fd, CMSG_DATA(cmsg), sizeof(fd));

		CHERIBSDTEST_VERIFY2(fd >= 0, "fd read OK");

		map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
						PROT_READ, MAP_SHARED, fd,
						0));
		c = *map;

		if (verbose)
			fprintf(stderr, "rx cap: %#lp\n", c);

		tag = cheri_gettag(c);
		CHERIBSDTEST_VERIFY2(tag == 0, "tag read");

		CHERIBSDTEST_CHECK_SYSCALL(munmap(map, getpagesize()));
		close(sv[0]);
		close(fd);

		exit(tag);
	} else {
		void * __capability * map;
		void * __capability c;
		int fd, res;
		struct msghdr msg = { 0 };
		struct cmsghdr * cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(fd))] = { 0 };
		char iovbuf[16] = { 0 };
		struct iovec iov = { .iov_base = iovbuf, .iov_len = sizeof(iovbuf) };

		close(sv[0]);

		fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
		CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

		map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
						PROT_READ | PROT_WRITE,
						MAP_SHARED, fd, 0));

		/* Just some pointer */
		*map = &fd;
		c = *map;
		CHERIBSDTEST_VERIFY2(cheri_gettag(c) != 0, "tag written");

		if (verbose)
			fprintf(stderr, "tx cap: %#lp\n", c);

		CHERIBSDTEST_CHECK_SYSCALL(munmap(map, getpagesize()));

		/* Construct control message */
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		/* XXX cmsg = CMSG_FIRSTHDR(&msg); */
		cmsg = msg.msg_control;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof fd);
		memmove(CMSG_DATA(cmsg), &fd, sizeof(fd));
		msg.msg_controllen = cmsg->cmsg_len;

		/* Send! */
		CHERIBSDTEST_CHECK_SYSCALL(sendmsg(sv[1], &msg, 0));

		close(sv[1]);
		close(fd);

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheribsdtest_success();
		} else {
			cheribsdtest_failure_errx("tag transfer succeeded");
		}
	}
}

CHERIBSDTEST(shm_open_read_nocaps,
    "check that read(2) of a shm_open fd does not return tags")
{
	void * __capability *map;
	void * __capability c;
	size_t rv;
	int fd;

	fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

	/* Just some pointer */
	*map = &fd;
	c = *map;
	CHERIBSDTEST_VERIFY2(cheri_gettag(c) != 0, "tag written");

	rv = CHERIBSDTEST_CHECK_SYSCALL(read(fd, &c, sizeof(c)));
	CHERIBSDTEST_CHECK_EQ_SIZE(rv, sizeof(c));

	CHERIBSDTEST_VERIFY2(cheri_gettag(c) == 0, "tag read");
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(cheri_cleartag(*map), c),
	    "untagged value not read");

	CHERIBSDTEST_CHECK_SYSCALL(close(fd));
	cheribsdtest_success();
}

CHERIBSDTEST(shm_open_write_nocaps,
    "check that write(2) of a shm_open fd does not set tags")
{
	void * __capability *map;
	void * __capability c;
	size_t rv;
	int fd;

	fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

	/* Just some pointer */
	c = &fd;
	CHERIBSDTEST_VERIFY2(cheri_gettag(c) != 0, "tag set on source");

	rv = CHERIBSDTEST_CHECK_SYSCALL(write(fd, &c, sizeof(c)));
	CHERIBSDTEST_CHECK_EQ_SIZE(rv, sizeof(c));

	CHERIBSDTEST_VERIFY2(cheri_gettag(*map) == 0, "tag written");
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(cheri_cleartag(c), *map),
	    "untagged value not written");

	CHERIBSDTEST_CHECK_SYSCALL(close(fd));
	cheribsdtest_success();
}

#ifdef __CHERI_PURE_CAPABILITY__

/*
 * We can fork processes with shared file descriptor tables, including
 * shared access to a kqueue, which can hoard capabilities for us, allowing
 * them to flow between address spaces.  It is difficult to know what to do
 * about this case, but it seems important to acknowledge.
 */
CHERIBSDTEST(vm_cap_share_fd_kqueue,
    "Demonstrate capability passing via shared FD table",
    .ct_xfail_reason = "Tags currently survive cross-AS shared FD tables")
{
	int kq, pid;

	kq = CHERIBSDTEST_CHECK_SYSCALL(kqueue());
	pid = rfork(RFPROC);
	if (pid == -1)
		cheribsdtest_failure_errx("Fork failed; errno=%d", errno);

	if (pid == 0) {
		struct kevent oke;
		/*
		 * Wait for receipt of the user event, and witness the
		 * capability received from the parent.
		 */
		oke.udata = NULL;
		CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, NULL, 0, &oke, 1, NULL));
		CHERIBSDTEST_VERIFY2(oke.ident == 0x2BAD, "Bad identifier from kqueue");
		CHERIBSDTEST_VERIFY2(oke.filter == EVFILT_USER, "Bad filter from kqueue");

		exit(cheri_gettag(oke.udata));
	} else {
		int res;
		struct kevent ike;
		void * __capability passme;

		/*
		 * Generate a capability to a new mapping to pass to the
		 * child, who will not have this region mapped.
		 */
		passme = CHERIBSDTEST_CHECK_SYSCALL(mmap(0, PAGE_SIZE,
				PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

		EV_SET(&ike, 0x2BAD, EVFILT_USER, EV_ADD|EV_ONESHOT,
			NOTE_FFNOP, 0, passme);
		CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));

		EV_SET(&ike, 0x2BAD, EVFILT_USER, EV_KEEPUDATA,
			NOTE_FFNOP|NOTE_TRIGGER, 0, NULL);
		CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheribsdtest_success();
		} else {
			cheribsdtest_failure_errx("tag transfer");
		}
	}
}

extern int __sys_sigaction(int, const struct sigaction *, struct sigaction *);

/*
 * We can rfork and share the sigaction table across parent and child, which
 * again allows for capability passing across address spaces.
 */
CHERIBSDTEST(vm_cap_share_sigaction,
    "Demonstrate capability passing via shared sigaction table",
    .ct_xfail_reason = "Tags currently survive cross-AS shared sigaction table")
{
	int pid;

	pid = rfork(RFPROC | RFSIGSHARE);
	if (pid == -1)
		cheribsdtest_failure_errx("Fork failed; errno=%d", errno);

	/*
	 * Note: we call __sys_sigaction directly here, since the libthr
	 * _thr_sigaction has a shadow list for the sigaction values
	 * (per-process) and therefore does not read the new value installed by
	 * the child process forked with RFSIGSHARE.
	 */
	if (pid == 0) {
		void *__capability passme;
		struct sigaction sa;

		bzero(&sa, sizeof(sa));

		/* This is a little abusive, but shows the point, I think */

		passme = CHERIBSDTEST_CHECK_SYSCALL(mmap(0, PAGE_SIZE,
		    PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON, -1, 0));
		sa.sa_handler = passme;

		CHERIBSDTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, &sa, NULL));

		/* Read it again and check that we get the same value back. */
		CHERIBSDTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, NULL, &sa));
		CHERIBSDTEST_CHECK_EQ_CAP(sa.sa_handler, passme);

		exit(0);
	} else {
		struct sigaction sa;

		waitpid(pid, NULL, 0);

		bzero(&sa, sizeof(sa));
		sa.sa_flags = 1;

		CHERIBSDTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, NULL, &sa));

		/* Flags should be zero on read */
		CHERIBSDTEST_CHECK_EQ_LONG(sa.sa_flags, 0);

		if (cheri_gettag(sa.sa_handler)) {
			cheribsdtest_failure_errx("tag transfer");
		} else {
			cheribsdtest_success();
		}
	}
}

#endif

CHERIBSDTEST(vm_tag_dev_zero_shared,
    "check tags are stored for /dev/zero MAP_SHARED pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(open("/dev/zero", O_RDWR));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED);
	cheribsdtest_success();
}

CHERIBSDTEST(vm_tag_dev_zero_private,
    "check tags are stored for /dev/zero MAP_PRIVATE pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(open("/dev/zero", O_RDWR));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	cheribsdtest_success();
}

static int
create_tempfile(void)
{
	char template[] = "/tmp/cheribsdtest.XXXXXXXX";
	int fd = CHERIBSDTEST_CHECK_SYSCALL2(mkstemp(template),
	    "mkstemp %s", template);
	CHERIBSDTEST_CHECK_SYSCALL(unlink(template));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	return fd;
}

/*
 * This case should fault.
 * XXXRW: I wonder if we also need some sort of load-related test?
 */
CHERIBSDTEST(vm_notag_tmpfile_shared,
    "check tags are not stored for tmpfile() MAP_SHARED pages",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO | CT_FLAG_SI_ADDR,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
    .ct_check_skip = skip_need_writable_tmp)
{
	void * __capability volatile *cp;
	void * __capability cp_value;
	int fd, v;

	fd = create_tempfile();
	cp = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
	cheribsdtest_set_expected_si_addr(NULL_DERIVED_VOIDP(cp));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;
	cheribsdtest_failure_errx("tagged store succeeded");
}

CHERIBSDTEST(vm_tag_tmpfile_private,
    "check tags are stored for tmpfile() MAP_PRIVATE pages",
    .ct_check_skip = skip_need_writable_tmp)
{
	int fd = create_tempfile();
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	cheribsdtest_success();
}

CHERIBSDTEST(vm_tag_tmpfile_private_prefault,
    "check tags are stored for tmpfile() MAP_PRIVATE, MAP_PREFAULT_READ pages",
    .ct_check_skip = skip_need_writable_tmp)
{
	int fd = create_tempfile();
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_PREFAULT_READ);
	cheribsdtest_success();
}

static const char *
skip_need_writable_tmp(const char *name __unused)
{
	static const char *reason = NULL;
	static int checked = 0;
	char template[] = "/tmp/cheribsdtest.XXXXXXXX";
	int fd;

	if (checked)
		return (reason);

	checked = 1;
	fd = mkstemp(template);
	if (fd >= 0) {
		close(fd);
		unlink(template);
		return (NULL);
	}
	reason = "/tmp is not writable";
	return (reason);
}

/*
 * Exercise copy-on-write:
 *
 * 1) Create a new anonymous shared memory object, extend to page size, map,
 * and write a tagged capability to it.
 *
 * 2) Create a second copy-on-write mapping; read back the tagged value via
 * the second mapping, and confirm that it still has a tag.
 * (cheribsdtest_vm_cow_read)
 *
 * 3) Write an adjacent word in the second mapping, which should cause a
 * copy-on-write, then read back the capability and confirm that it still has
 * a tag.  (cheribsdtest_vm_cow_write)
 */
CHERIBSDTEST(vm_cow_read,
    "read capabilities from a copy-on-write page")
{
	void * __capability volatile *cp_copy;
	void * __capability volatile *cp_real;
	void * __capability cp;
	int fd;

	/*
	 * Create anonymous shared memory object.
	 */
	fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	/*
	 * Create 'real' and copy-on-write mappings.
	 */
	cp_real = CHERIBSDTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0), "mmap cp_real");
	cp_copy = CHERIBSDTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), "mmap cp_copy");

	/*
	 * Write out a tagged capability to 'real' mapping -- doesn't really
	 * matter what it points at.  Confirm it has a tag.
	 */
	cp = cheri_ptr(&fd, sizeof(fd));
	cp_real[0] = cp;
	cp = cp_real[0];
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp) != 0, "pretest: tag missing");

	/*
	 * Read in tagged capability via copy-on-write mapping.  Confirm it
	 * has a tag.
	 */
	cp = cp_copy[0];
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp) != 0, "tag missing, cp_real");

	/*
	 * Clean up.
	 */
	CHERIBSDTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_real),
	    getpagesize()), "munmap cp_real");
	CHERIBSDTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_copy),
	    getpagesize()), "munmap cp_copy");
	CHERIBSDTEST_CHECK_SYSCALL(close(fd));
	cheribsdtest_success();
}

CHERIBSDTEST(vm_cow_write,
    "read capabilities from a faulted copy-on-write page")
{
	void * __capability volatile *cp_copy;
	void * __capability volatile *cp_real;
	void * __capability cp;
	int fd;

	/*
	 * Create anonymous shared memory object.
	 */
	fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	/*
	 * Create 'real' and copy-on-write mappings.
	 */
	cp_real = CHERIBSDTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0), "mmap cp_real");
	cp_copy = CHERIBSDTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), "mmap cp_copy");

	/*
	 * Write out a tagged capability to 'real' mapping -- doesn't really
	 * matter what it points at.  Confirm it has a tag.
	 */
	cp = cheri_ptr(&fd, sizeof(fd));
	cp_real[0] = cp;
	cp = cp_real[0];
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp) != 0, "pretest: tag missing");

	/*
	 * Read in tagged capability via copy-on-write mapping.  Confirm it
	 * has a tag.
	 */
	cp = cp_copy[0];
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp) != 0, "tag missing, cp_real");

	/*
	 * Diverge from cheribsdtest_vm_cow_read(): write via the second mapping
	 * to force a copy-on-write rather than continued sharing of the page.
	 */
	cp = cheri_ptr(&fd, sizeof(fd));
	cp_copy[1] = cp;

	/*
	 * Confirm that the tag is still present on the 'real' page.
	 */
	cp = cp_real[0];
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp) != 0, "tag missing after COW, cp_real");

	cp = cp_copy[0];
	CHERIBSDTEST_VERIFY2(cheri_gettag(cp) != 0, "tag missing after COW, cp_copy");

	/*
	 * Clean up.
	 */
	CHERIBSDTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_real),
	    getpagesize()), "munmap cp_real");
	CHERIBSDTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_copy),
	    getpagesize()), "munmap cp_copy");
	CHERIBSDTEST_CHECK_SYSCALL(close(fd));
	cheribsdtest_success();
}

#ifdef __CHERI_PURE_CAPABILITY__

static int __used sink;

static size_t
get_unrepresentable_length(void)
{
	int shift = 0;
	size_t len;

	/*
	 * Generate the shortest unrepresentable length, for which rounding
	 * up to PAGE_SIZE is still unrepresentable.
	 */
	do {
		len = (1 << (PAGE_SHIFT + shift)) + 1;
		shift++;
	} while (round_page(len) ==
	    __builtin_cheri_round_representable_length(round_page(len)));
	return (len);
}

/*
 * Check that globals do not have the SW_VMEM permission bit after
 * capability relocation.
 */
static char test_buffer[64];
static void *test_bufferp = (void *)&test_buffer;

CHERIBSDTEST(vm_sw_perm_on_capreloc,
	     "Check that the SW_VMEM permission is not present on globals.")
{
	CHERIBSDTEST_VERIFY(cheri_gettag(test_bufferp));
	CHERIBSDTEST_VERIFY((cheri_getperm(test_bufferp) & CHERI_PERM_SW_VMEM) == 0);

	cheribsdtest_success();
}

/*
 * Check that the padding of a reservation faults on access
 */
CHERIBSDTEST(vm_reservation_access_fault,
    "check that we fault when accessing padding of a reservation",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_ACCERR)
{
	size_t len = get_unrepresentable_length();
	size_t expected_len;
	void *map;
	int *padding;

	expected_len = __builtin_cheri_round_representable_length(len);
	CHERIBSDTEST_VERIFY2(expected_len > round_page(len),
	    "test precondition failed: padding for length (%lx) must "
	    "exceed one page, found %lx", len, expected_len);
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0, "mmap() failed to return "
	    "a pointer when given unrepresentable length (%zu)", len);
	CHERIBSDTEST_VERIFY2(cheri_getlen(map) == expected_len,
	    "mmap() returned a pointer with an unrepresentable length "
	    "(%zu vs %zu): %#p", cheri_getlen(map), expected_len, map);

	padding = (int *)((uintcap_t)map + expected_len - sizeof(int));
	sink = *padding;

	cheribsdtest_failure_errx("reservation padding access allowed");
}

/*
 * Check that a reserved range can not be reused for another mapping,
 * until the whole mapping is freed.
 */
CHERIBSDTEST(vm_reservation_reuse,
    "check that we can not remap over a partially-unmapped reservation")
{
	void *map;
	void *map2;

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, PAGE_SIZE * 2,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0, "mmap() failed to return "
	    "a pointer");

	CHERIBSDTEST_CHECK_SYSCALL(munmap((char *)map + PAGE_SIZE, PAGE_SIZE));
	/*
	 * XXX-AM: is this checking the right thing?
	 * We may be failing because the reservation length is not enough.
	 */
	map2 = mmap((void *)(uintptr_t)((ptraddr_t)map + PAGE_SIZE),
	    PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
	if (map2 == MAP_FAILED) {
		CHERIBSDTEST_VERIFY2(errno == ENOMEM,
		    "Unexpected errno %d instead of ENOMEM", errno);
		cheribsdtest_success();
	}

	cheribsdtest_failure_errx("mmap over reservation succeeded");
}

/*
 * Check that alignment is promoted automatically to the first
 * representable boundary.
 */
CHERIBSDTEST(vm_reservation_align,
    "check that mmap correctly align mappings")
{
	void *map;
	size_t len = get_unrepresentable_length();
	size_t align_shift = CHERI_ALIGN_SHIFT(len);
	size_t align_mask = CHERI_ALIGN_MASK(len);

	/* No alignment */
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align representable region for %p", map);

	/* Underaligned */
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_ALIGNED(align_shift - 1),
	    -1, 0));
	CHERIBSDTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align representable region with requested "
	    "alignment %lx for %p", align_shift - 1, map);

	/* Overaligned */
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_ALIGNED(align_shift + 1),
	    -1, 0));
	CHERIBSDTEST_VERIFY2(
	    ((ptraddr_t)(map) & ((1 << (align_shift + 1)) - 1)) == 0,
	    "mmap failed to align representable region with requested "
	    "alignment %lx for %p", align_shift + 1, map);

	/* Explicit cheri alignment */
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_ALIGNED_CHERI, -1, 0));
	CHERIBSDTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align representable region with requested "
	    "cheri alignment for %p", map);

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_ALIGNED_CHERI_SEAL, -1, 0));
	CHERIBSDTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align representable region with requested "
	    "cheri seal alignment for %p", map);

	cheribsdtest_success();
}

static bool
reservations_are_quarantined(void)
{
	uint8_t quarantine_unmapped_reservations;
	size_t quarantine_unmapped_reservations_sz =
	    sizeof(quarantine_unmapped_reservations);

	if (sysctlbyname("vm.cheri_revoke.quarantine_unmapped_reservations",
	    &quarantine_unmapped_reservations,
	    &quarantine_unmapped_reservations_sz, NULL, 0) != 0) {
		if (errno == ENOENT)
			return (false);
		cheribsdtest_failure_err(
		    "sysctlbyname(vm.cheri_revoke.quarantine_unmapped_reservations)");
	}

	return (quarantine_unmapped_reservations != 0);
}

/*
 * Check that after a reservation is unmapped, it is not possible to
 * reuse the old capability to create new fixed mappings.
 * This is an attempt to reuse a capability prior to a revocation pass.
 * As this capability may be revoked at some arbitrary point in the
 * future, we always disallow use.
 */
CHERIBSDTEST(vm_reservation_mmap_after_free_fixed,
    "check that an old capability can not be used to mmap with MAP_FIXED "
    "after the reservation has been deleted",
    .ct_check_skip = skip_need_cheri_revoke)
{
	void *map;
	const volatile struct cheri_revoke_info *cri;

	/* Make sure this process is revoking */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIBSDTEST_CHECK_SYSCALL(munmap((char *)map, PAGE_SIZE));

	map = mmap(map, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_FIXED, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED, "mmap after free succeeded");

	if (reservations_are_quarantined()) {
		/*
		 * There's nothing to cause the quarantined reservation to be
		 * revoked between the munmap and mmap calls so we'll get an
		 * ENOMEM here.
		 *
		 * XXX: ideally we'd trigger a revocation of this specific
		 * reservation before the mmap call to test the same case with
		 * and without revocation.
		 */
		CHERIBSDTEST_VERIFY2(errno == ENOMEM,
		    "mmap after free failed with %d instead of ENOMEM", errno);
	} else
		CHERIBSDTEST_VERIFY2(errno == EPROT,
		    "mmap after free failed with %d instead of EPROT", errno);

	cheribsdtest_success();
}

/*
 * Check that after a reservation is unmapped, it is not possible to
 * reuse the old capability to create new non-fixed mappings.
 * This is an attempt of reusing a capability before revocation, in
 * a proper temporal-safety implementation will lead to failures so
 * we catch these early.
 */
CHERIBSDTEST(vm_reservation_mmap_after_free,
    "check that an old capability can not be used to mmap after the "
    "reservation has been deleted",
    .ct_check_skip = skip_need_cheri_revoke)
{
	void *map;
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIBSDTEST_CHECK_SYSCALL(munmap((char *)map, PAGE_SIZE));

	map = mmap(map, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED, "mmap after free succeeded");
	CHERIBSDTEST_VERIFY2(errno == EPROT,
	    "mmap after free failed with %d instead of EPROT", errno);
	cheribsdtest_success();
}

/*
 * Check that reservations are aligned and padded correctly for shared mappings.
 */
CHERIBSDTEST(vm_reservation_mmap_shared,
    "check reservation alignment and bounds for shared mappings")
{
	void *map;
	size_t len = get_unrepresentable_length();
	size_t expected_len;
	size_t align_mask = CHERI_ALIGN_MASK(len);
	int fd;

	expected_len = __builtin_cheri_round_representable_length(len);
	fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, len));

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

	CHERIBSDTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align shared regiont for representability");
	CHERIBSDTEST_VERIFY2(cheri_getlen(map) == expected_len,
	    "mmap returned pointer with unrepresentable length");

	cheribsdtest_success();
}

/*
 * Check that we require NULL-derived capabilities when mmap().
 * Test mmap() with an invalid capability and no backing reservation.
 */
CHERIBSDTEST(vm_mmap_invalid_cap,
    "check that mmap with invalid capability hint fails")
{
	void *invalid = cheri_cleartag(cheri_setaddress(
	    cheri_getpcc(), 0x4300beef));
	void *map;

	map = mmap(invalid, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED,
	    "mmap with invalid capability succeeded");
	CHERIBSDTEST_VERIFY2(errno == EINVAL,
	    "mmap with invalid capability failed with %d instead "
	    "of EINVAL", errno);

	cheribsdtest_success();
}

/*
 * Check that we require NULL-derived capabilities when mmap().
 * Test mmap() MAP_FIXED with an invalid capability and no backing reservation.
 */
CHERIBSDTEST(vm_mmap_invalid_cap_fixed,
    "check that mmap MAP_FIXED with invalid capability hint fails")
{
	void *invalid = cheri_cleartag(cheri_setaddress(
	    cheri_getpcc(), 0x4300beef));
	void *map;

	map = mmap(invalid, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_FIXED, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED,
	    "mmap with invalid capability succeeded");
	CHERIBSDTEST_VERIFY2(errno == EINVAL,
	    "mmap with invalid capability failed with %d instead "
	    "of EINVAL", errno);

	cheribsdtest_success();
}

/*
 * Check that we require NULL-derived capabilities when mmap().
 * Test mmap() MAP_FIXED with an invalid capability and existing
 * backing reservation.
 */
CHERIBSDTEST(vm_reservation_mmap_invalid_cap,
    "check that mmap over existing reservation with invalid "
    "capability hint fails")
{
	void *invalid;
	void *map;

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	invalid = cheri_cleartag(map);

	map = mmap(invalid, PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED,
	    "mmap with invalid capability succeeded");
	CHERIBSDTEST_VERIFY2(errno == EINVAL,
	    "mmap with invalid capability failed with %d instead "
	    "of EINVAL", errno);

	cheribsdtest_success();
}

/*
 * Check that mmap() with a null-derived hint address succeeds.
 */
CHERIBSDTEST(vm_reservation_mmap,
    "check mmap with NULL-derived hint address")
{
	uintptr_t hint;
	void *map;

	hint = find_address_space_gap(PAGE_SIZE, 0);
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap((void *)hint, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0,
	    "mmap with null-derived hint failed to return valid capability");

	cheribsdtest_success();
}

/*
 * Check that mapping with a NULL-derived capability hint at a fixed
 * address, with no existing reservation at the target region, succeeds.
 * Check that this fails if a mapping already exists at the target address
 * as MAP_FIXED implies MAP_EXCL in this case.
 */
CHERIBSDTEST(vm_reservation_mmap_fixed_unreserved,
    "check mmap MAP_FIXED with NULL-derived hint address")
{
	uintptr_t hint;
	void *map;

	hint = find_address_space_gap(PAGE_SIZE * 2, 0);
	map = CHERIBSDTEST_CHECK_SYSCALL(mmap((void *)(hint + PAGE_SIZE),
	    PAGE_SIZE, PROT_MAX(PROT_READ | PROT_WRITE), MAP_ANON | MAP_FIXED,
	    -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0,
	    "mmap fixed with NULL-derived hint failed to return "
	    "valid capability");

	map = mmap((void *)hint, 2 * PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED,
	    "mmap fixed with NULL-derived hint does not imply MAP_EXCL");
	CHERIBSDTEST_VERIFY2(errno == ENOMEM,
	    "mmap fixed with NULL-derived hint failed with %d instead "
	    "of ENOMEM", errno);

	cheribsdtest_success();
}

/*
 * Check that mmap at fixed address with NULL-derived hint fails if
 * a reservation already exists at the target address.
 */
CHERIBSDTEST(vm_reservation_mmap_insert_null_derived,
    "check that mmap with NULL-derived hint address over existing "
    "reservation fails")
{
	void *map;

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, 3 * PAGE_SIZE,
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_GUARD, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0,
	    "mmap failed to return valid capability");

	map = mmap((void *)(uintptr_t)(ptraddr_t)map, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
	CHERIBSDTEST_VERIFY2(map == MAP_FAILED,
	    "mmap fixed with NULL-derived hint succeded");
	CHERIBSDTEST_VERIFY2(errno == ENOMEM,
	    "mmap fixed with NULL-derived hint failed with %d instead "
	    "of ENOMEM", errno);

	cheribsdtest_success();
}

CHERIBSDTEST(vm_reservation_mmap_fixed_insert,
    "check mmap MAP_FIXED into an existing reservation with a "
    "SW_VMEM perm capability")
{
	void *map;

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, 3 * PAGE_SIZE,
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_GUARD, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0,
	    "mmap failed to return valid capability");
	CHERIBSDTEST_VERIFY2(cheri_getperm(map) & CHERI_PERM_SW_VMEM,
	    "mmap failed to return capability with VMEM perm");

	CHERIBSDTEST_CHECK_SYSCALL(mmap((char *)(map) + PAGE_SIZE, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0,
	    "mmap fixed failed to return valid capability");

	cheribsdtest_success();
}

CHERIBSDTEST(vm_reservation_mmap_fixed_insert_noperm,
    "check that mmap MAP_FIXED into an existing reservation "
    "with a capability missing SW_VMEM permission fails")
{
	void *map;
	void *map2;
	void *not_enough_perm;

	map = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, 3 * PAGE_SIZE,
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_GUARD, -1, 0));
	CHERIBSDTEST_VERIFY2(cheri_gettag(map) != 0,
	    "mmap failed to return valid capability");
	CHERIBSDTEST_VERIFY2(cheri_getperm(map) & CHERI_PERM_SW_VMEM,
	    "mmap failed to return capability with VMEM perm");

	not_enough_perm = cheri_andperm(map, ~CHERI_PERM_SW_VMEM);
	map2 = mmap((char *)(not_enough_perm) + PAGE_SIZE, PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
	CHERIBSDTEST_VERIFY2(map2 == MAP_FAILED,
	    "mmap fixed with capability missing VMEM perm succeeds");
	CHERIBSDTEST_VERIFY2(errno == EACCES,
	    "mmap fixed with capability missing VMEM perm failed "
	    "with %d instead of EACCES", errno);

	cheribsdtest_success();
}

#if PMAP_HAS_LARGEPAGES
static int
get_pagesizes(size_t ps[static MAXPAGESIZES])
{
	int count;

	count = getpagesizes(ps, MAXPAGESIZES);
	CHERIBSDTEST_VERIFY2(count != -1, "failed to get pagesizes");
	CHERIBSDTEST_VERIFY2(ps[0] == PAGE_SIZE, "psind 0 is not PAGE_SIZE");
	return (count);
}

/*
 * Builds on FreeBSD testsuite posixshm_test:largepage_basic.
 */
CHERIBSDTEST(vm_shm_largepage_basic,
    "Test basic largepage SHM mapping setup and teardown")
{
	void *addr;
	size_t ps[MAXPAGESIZES];
	int psind, psmax;
	int fd;
	unsigned int perms = (CHERI_PERM_LOAD | CHERI_PERM_STORE);
	void * volatile *map_buffer;
	int v;

	psmax = get_pagesizes(ps);
	for (psind = 1; psind < psmax; psind++) {
		/* Skip very large pagesizes */
		if (ps[psind] >= (1 << 30))
			continue;

		fd = shm_create_largepage(SHM_ANON, O_CREAT | O_RDWR, psind,
		    SHM_LARGEPAGE_ALLOC_DEFAULT, /*mode*/0);
		CHERIBSDTEST_VERIFY2(fd >= 0, "Failed to create largepage SHM fd "
		    "psind=%d errno=%d", psind, errno);
		CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, ps[psind]));
		addr = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, ps[psind],
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

		/* Verify mmap output */
		CHERIBSDTEST_VERIFY2(cheri_gettag(addr) != 0,
		    "mmap invalid capability for psind=%d", psind);
		CHERIBSDTEST_VERIFY2(cheri_getlen(addr) == ps[psind],
		    "mmap wrong capability length for psind=%d "
		    "expected %jx found %jx",
		    psind, ps[psind], cheri_getlen(addr));
		CHERIBSDTEST_VERIFY2((cheri_getperm(addr) & perms) == perms,
		    "mmap missing permission expected %jx found %jx",
		    (uintmax_t)perms, (uintmax_t)cheri_getperm(addr));

		/* Try to store capabilities in the SHM region */
		map_buffer = (void * volatile *)addr;
		*map_buffer = &v;
		CHERIBSDTEST_VERIFY2(cheri_gettag(*map_buffer) != 0, "tag lost");

		map_buffer = (void * volatile *)((uintptr_t)addr +
		    ps[psind] / 2);
		*map_buffer = &v;
		CHERIBSDTEST_VERIFY2(cheri_gettag(*map_buffer) != 0, "tag lost");

		map_buffer = (void * volatile *)((uintptr_t)addr +
		    ps[psind] - PAGE_SIZE);
		*map_buffer = &v;
		CHERIBSDTEST_VERIFY2(cheri_gettag(*map_buffer) != 0, "tag lost");

		CHERIBSDTEST_CHECK_SYSCALL(munmap(addr, ps[psind]));
		CHERIBSDTEST_CHECK_SYSCALL(close(fd));
	}
	cheribsdtest_success();
}
#endif /* PMAP_HAS_LARGEPAGES */

/*
 * Store a cap to a page and check that mincore reports it CAPSTORE.
 *
 * Due to a shortage of bits in mincore()'s uint8_t reporting bit vector, this
 * particular test is not able to distinguish CAPSTORE and CAPDIRTY and so is
 * not sensitive to the vm.pmap.enter_capstore_as_capdirty sysctl.
 *
 * On the other hand, this test is sensitive to the vm.capstore_on_alloc sysctl:
 * if that is asserted, our cap-capable anonymous memory will be installed
 * CAPSTORE (and possibly even CAPDIRTY, in light of the above) whereas, if this
 * sysctl is clear, our initial view of said memory will be !CAPSTORE.
 */
CHERIBSDTEST(vm_capdirty, "verify capdirty marking and mincore")
{
#define CHERIBSDTEST_VM_CAPDIRTY_NPG	2
	size_t sz = CHERIBSDTEST_VM_CAPDIRTY_NPG * getpagesize();
	uint8_t capstore_on_alloc;
	size_t capstore_on_alloc_sz = sizeof(capstore_on_alloc);

	void * __capability *pg0;
	unsigned char mcv[CHERIBSDTEST_VM_CAPDIRTY_NPG] = { 0 };

	CHERIBSDTEST_CHECK_SYSCALL(
	    sysctlbyname("vm.capstore_on_alloc", &capstore_on_alloc,
	        &capstore_on_alloc_sz, NULL, 0));

	pg0 = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	void * __capability *pg1 = (void *)&((char *)pg0)[getpagesize()];

	/*
	 * Pages are ZFOD and so will not be CAPSTORE, or, really, anything
	 * else, either.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(mincore(pg0, sz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(mcv[0] == 0, "page 0 status 0");
	CHERIBSDTEST_VERIFY2(mcv[1] == 0, "page 1 status 0");

	/*
	 * Write data to page 0, causing it to become allocated and MODIFIED.
	 * If vm.capstore_on_alloc, then it should be CAPSTORE as well, despite
	 * having never been the target of a capability store.
	 */
	*(char *)pg0 = 0x42;

	CHERIBSDTEST_CHECK_SYSCALL(mincore(pg0, sz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_MODIFIED) != 0, "page 0 modified 1");
	CHERIBSDTEST_VERIFY2(
	    !(mcv[0] & MINCORE_CAPSTORE) == !capstore_on_alloc,
	    "page 0 capstore 1");

	/*
	 * Write a capability to page 1 and check that it is MODIFIED and
	 * CAPSTORE regardless of vm.capstore_on_alloc.
	 */
	*pg1 = (__cheri_tocap void * __capability)pg0;

	CHERIBSDTEST_CHECK_SYSCALL(mincore(pg0, sz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_MODIFIED) != 0, "page 1 modified 2");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2");

	CHERIBSDTEST_CHECK_SYSCALL(munmap(pg0, sz));
	cheribsdtest_success();
#undef CHERIBSDTEST_VM_CAPDIRTY_NPG
}

#ifdef CHERIBSDTEST_CHERI_REVOKE_TESTS
/*
 * Revocation tests
 */

static const char *
skip_need_quarantine_unmapped_reservations(const char *name __unused)
{
	if (!feature_present("cheri_revoke"))
		return ("Kernel does not support revocation");
	if (!reservations_are_quarantined())
		return ("unmapped reservations are not being quarantined");
	return (NULL);
}

static int
check_revoked(void *r)
{
	return (cheri_gettag(r) == 0) ||
	    ((cheri_gettype(r) == -1L) && (cheri_getperm(r) == 0));
}

/*
 * Install a couple of knotes into the queue, one identified by a file
 * descriptor and one not, to exercise different code paths in the kernel.
 * The knotes will contain a user capability which should be detected and
 * handled by the kernel's caprevoke machinery.
 */
static void
install_kqueue_cap(int kq, int pfd[2], void *revme)
{
	struct kevent ike;
	ssize_t rv;
	char b;

	EV_SET(&ike, (uintptr_t)&install_kqueue_cap,
	    EVFILT_USER, EV_ADD | EV_ONESHOT | EV_DISABLE, NOTE_FFNOP, 0,
	    revme);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	EV_SET(&ike, (uintptr_t)&install_kqueue_cap, EVFILT_USER, EV_KEEPUDATA,
	    NOTE_FFNOP | NOTE_TRIGGER, 0, NULL);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));

	EV_SET(&ike, (uintptr_t)pfd[0], EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0,
	    revme);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	b = 42;
	rv = CHERIBSDTEST_CHECK_SYSCALL(write(pfd[1], &b, sizeof(b)));
	CHERIBSDTEST_VERIFY(rv == 1);
}

static void
check_kqueue_cap(int kq, int pfd[2], unsigned int valid)
{
	struct kevent ike, oke = { 0 };
	ssize_t rv;
	char b;

	EV_SET(&ike, (uintptr_t)&install_kqueue_cap,
	    EVFILT_USER, EV_ENABLE|EV_KEEPUDATA, NOTE_FFNOP, 0, NULL);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, NULL, 0, &oke, 1, NULL));
	CHERIBSDTEST_VERIFY2(
	    __builtin_cheri_equal_exact(oke.ident, &install_kqueue_cap),
	    "Bad identifier from kqueue");
	CHERIBSDTEST_VERIFY2(oke.filter == EVFILT_USER,
	    "Bad filter from kqueue");
	CHERIBSDTEST_VERIFY2(check_revoked(oke.udata) == !valid,
	    "kqueue-held cap not as expected");

	memset(&oke, 0, sizeof(0));
	EV_SET(&ike, pfd[0], EVFILT_READ, EV_ENABLE | EV_KEEPUDATA, 0, 0, NULL);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, NULL, 0, &oke, 1, NULL));
	CHERIBSDTEST_VERIFY2(oke.ident == (uintptr_t)pfd[0],
	    "Bad identifier from kqueue");
	CHERIBSDTEST_VERIFY2(oke.filter == EVFILT_READ,
	    "Bad filter from kqueue");
	CHERIBSDTEST_VERIFY2(check_revoked(oke.udata) == !valid,
	    "kqueue-held cap not as expected");
	rv = CHERIBSDTEST_CHECK_SYSCALL(read(pfd[0], &b, sizeof(b)));
	CHERIBSDTEST_VERIFY(rv == 1);
	CHERIBSDTEST_VERIFY(b == 42);
}

CHERIBSDTEST(cheri_revoke_lightly, "A gentle test of capability revocation",
    .ct_check_skip = skip_need_cheri_revoke)
{
	void **mb;
	void *sh;
	const volatile struct cheri_revoke_info *cri;
	void *revme;
	struct cheri_revoke_syscall_info crsi;
	int ekq, kq, pfd[2];

	/*
	 * Set up our descriptors.  Keep an empty kqueue around to help exercise
	 * extra code paths in the kernel.
	 */
	ekq = CHERIBSDTEST_CHECK_SYSCALL(kqueue());
	kq = CHERIBSDTEST_CHECK_SYSCALL(kqueue());
	CHERIBSDTEST_CHECK_SYSCALL(pipe(pfd));

	mb = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));

	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	/*
	 * OK, armed with the shadow mapping... generate a capability to
	 * the 0th granule of the map, spill it to the 1st granule,
	 * stash it in the kqueue, and mark it as revoked in the shadow.
	 */
	revme = cheri_andperm(mb, ~CHERI_PERM_SW_VMEM);
	((void **)mb)[1] = revme;
	install_kqueue_cap(kq, pfd, revme);

	((uint8_t *)sh)[0] = 1;

	crsi.epochs.enqueue = 0xC0FFEE;
	crsi.epochs.dequeue = 0xB00;

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS , 0, &crsi));

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIBSDTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");
	check_kqueue_cap(kq, pfd, 0);

	/* Clear the revocation bit and do that again */
	((uint8_t *)sh)[0] = 0;

	/*
	 * We don't derive exactly the same thing, to prevent CSE from
	 * firing.  More specifically, we adjust the offset first, taking
	 * the path through the commutation diagram that doesn't share an
	 * edge with the derivation above.
	 */
	revme = cheri_andperm(mb + 1, ~CHERI_PERM_SW_VMEM);
	CHERIBSDTEST_VERIFY2(!check_revoked(revme), "Tag clear on 2nd revme?");
	((void **)mb)[1] = revme;
	install_kqueue_cap(kq, pfd, revme);

	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIBSDTEST_VERIFY2(
	    crsi.epochs.enqueue >= crsi.epochs.dequeue + 1,
	    "Bad epoch clock state");

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS,
	    crsi.epochs.enqueue, &crsi));

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIBSDTEST_VERIFY2(!check_revoked(mb[1]), "Memory tag cleared");

	check_kqueue_cap(kq, pfd, 1);

	munmap(mb, PAGE_SIZE);
	close(kq);
	close(ekq);
	close(pfd[0]);
	close(pfd[1]);

	cheribsdtest_success();
}

CHERIBSDTEST(cheri_revoke_loadside, "Test load-side revoker",
    .ct_check_skip = skip_need_cheri_revoke)
{
#define CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG	3

	void **mb;
	void *sh;
	const volatile struct cheri_revoke_info *cri;
	void *revme;
	struct cheri_revoke_syscall_info crsi;
	unsigned char mcv[CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG] = { 0 };
	const size_t asz = CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG *
	    PAGE_SIZE;

	mb = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, asz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));

	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY_CAP(void **, &cri)));

	revme = cheri_andperm(mb, ~CHERI_PERM_SW_VMEM);
	((void **)mb)[1] = revme;
	((uint8_t *)sh)[0] = 1;

	/* Write and clear a capability one page up */
	size_t capsperpage = PAGE_SIZE/sizeof(void *);
	((void * volatile *)mb)[capsperpage] = revme;
	((volatile uintptr_t *)mb)[capsperpage] = 0;

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 1");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 1");
	CHERIBSDTEST_VERIFY2(
	    (mcv[2] & MINCORE_CAPSTORE) == 0, "page 2 capstore 1");

	/*
	 * Begin load side.  This should be pretty speedy since we do no VM
	 * walks.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	/*
	 * Try to induce a read fault and check that the read result is revoked.
	 * Unfortunately, we can't check its capdirty status, but it should
	 * still be CAPSTORED, since not enough time has elapsed for the state
	 * machine to declare it clean.
	 */
	revme = ((void **)mb)[1];
	CHERIBSDTEST_VERIFY2(check_revoked(revme), "Fault didn't stop me!");

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.0");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.0");

	/*
	 * This might redirty the 0th page, if we're keeping tags around on
	 * revoked caps.  If it does, we expect the dirty bit to stay set
	 * through the revoker sweep (though that's not strictly essential)
	 */
	((void **)mb)[2] = revme;

	/*
	 * Now do the background sweep and wait for everything to finish
	 */
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
		CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.1");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.1");

	/* Re-dirty page 0 but not page 1 */
	revme = cheri_andperm(mb + 1, ~CHERI_PERM_SW_VMEM);
	CHERIBSDTEST_VERIFY2(!check_revoked(revme), "Tag clear on 2nd revme?");
	((void **)mb)[1] = revme;

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.2");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.2");

	/*
	 * Do another revocation, both parts at once this time.  This should
	 * transition page 0 from capdirty to capstore, since all capabilities
	 * on it are revoked.  Page 1, having previously been capstore, is now
	 * capclean.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
		CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIBSDTEST_VERIFY2(check_revoked(mb[1]),
	    "Revoker failure in full pass");

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 3");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) == 0, "page 1 capstore 3");

	/*
	 * Do that again so that we end with an odd CLG.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	        CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) == 0, "page 0 capstore 4");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) == 0, "page 1 capstore 4");
	/*
	 * TODO:
	 *
	 * - check that we can store to a page at any point in that transition.
	 */

	cheribsdtest_success();

#undef CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG
}

CHERIBSDTEST(cheri_revoke_async,
    "A gentle test of asynchronous capability revocation",
    .ct_check_skip = skip_need_cheri_revoke)
{
	struct cheri_revoke_syscall_info crsi;
	const volatile struct cheri_revoke_info *cri;
	cheri_revoke_epoch_t epoch;
	void **mb;
	void *sh;

	mb = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	mb[1] = cheri_andperm(mb, ~CHERI_PERM_SW_VMEM);
	((uint8_t *)sh)[0] = 1;
	epoch = cri->epochs.dequeue;

	memset(&crsi, 0, sizeof(crsi));
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START, 0,
	    &crsi));

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.enqueue == crsi.epochs.enqueue,
	    "Bad shared enqueue clock (%lu %lu)",
	    cri->epochs.enqueue, crsi.epochs.enqueue);
	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared dequeue clock (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);
	CHERIBSDTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue + 1,
	    "Bad shared clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);

	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, epoch)) {
		CHERIBSDTEST_CHECK_SYSCALL(
		    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START,
		    0, NULL));
		usleep(1000);
	}

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue,
	    "Bad shared post-revocation clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);
	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue + 2,
	    "Unexpected clock jump (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);

	CHERIBSDTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");

	cheribsdtest_success();
}

static void *
forker(void *arg)
{
	atomic_int *p = arg;

	while (*p == 0) {
		pid_t child = fork();
		CHERIBSDTEST_VERIFY2(child > 0, "fork failed");
		if (child == 0)
			_exit(0);
		(void)waitpid(child, NULL, 0);
	}

	return (NULL);
}

CHERIBSDTEST(cheri_revoke_async_fork,
    "A test of asynchronous capability revocation with concurrent forks",
    .ct_check_skip = skip_need_cheri_revoke)
{
	struct cheri_revoke_syscall_info crsi;
	const volatile struct cheri_revoke_info *cri;
	cheri_revoke_epoch_t epoch;
	pthread_t thr;
	void **mb;
	void *sh;
	atomic_int forker_res;
	int error;

	forker_res = 0;
	error = pthread_create(&thr, NULL, forker, &forker_res);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_create");

	mb = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	mb[1] = cheri_andperm(mb, ~CHERI_PERM_SW_VMEM);
	((uint8_t *)sh)[0] = 1;
	epoch = cri->epochs.dequeue;

	memset(&crsi, 0, sizeof(crsi));
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START, 0,
	    &crsi));

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.enqueue == crsi.epochs.enqueue,
	    "Bad shared enqueue clock (%lu %lu)",
	    cri->epochs.enqueue, crsi.epochs.enqueue);
	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared dequeue clock (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);
	CHERIBSDTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue + 1,
	    "Bad shared clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);

	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, epoch)) {
		CHERIBSDTEST_CHECK_SYSCALL(
		    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START,
		    0, NULL));
		usleep(1000);
	}

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue,
	    "Bad shared post-revocation clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);
	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue + 2,
	    "Unexpected clock jump (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);

	CHERIBSDTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");

	forker_res = 1;
	error = pthread_join(thr, NULL);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_join");

	cheribsdtest_success();
}

/*
 * Repeatedly invoke libcheri_caprevoke logic.
 * Using a bump the pointer allocator, repeatedly grab rand()-omly sized
 * objects and fill them with capabilities to themselves, mark them for
 * revocation, revoke, and validate.
 *
 */

#include <cheri/libcaprevoke.h>

static void
cheribsdtest_cheri_revoke_lib_init(size_t bigblock_caps, void *** obigblock,
    void ** oshadow, const volatile struct cheri_revoke_info ** ocri)
{
	void **bigblock;

	bigblock = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, bigblock_caps * sizeof(void *), PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0));

	for (size_t ix = 0; ix < bigblock_caps; ix++) {
		/* Create self-referential SW_VMEM-free capabilities */

		bigblock[ix] = cheri_andperm(cheri_setbounds(&bigblock[ix], 16),
		    ~CHERI_PERM_SW_VMEM);
	}
	*obigblock = bigblock;

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, bigblock,
	    oshadow));

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY(void **, ocri)));
}

enum {
	TCLR_MODE_NONE = 0,
	TCLR_MODE_LOAD_ONCE = 1,
	TCLR_MODE_LOAD_SPLIT = 2,
	TCLR_MODE_LOAD_SPLIT_INIT = 3,
	TCLR_MODE_LOAD_SPLIT_FINI = 4,
};

static void
cheribsdtest_cheri_revoke_lib_run(int paranoia, int mode, size_t bigblock_caps,
    void **bigblock, void *shadow, const volatile struct cheri_revoke_info *cri)
{
	size_t bigblock_offset = 0;
	const ptraddr_t sbase = cri->base_mem_nomap;

	if (verbose > 1)
		fprintf(stderr, "test_cheri_revoke_lib_run mode %d\n", mode);

	while (bigblock_offset < bigblock_caps) {
		struct cheri_revoke_syscall_info crsi;
		size_t csz;

		switch (mode) {
		case TCLR_MODE_LOAD_SPLIT_INIT:
		case TCLR_MODE_LOAD_SPLIT_FINI:
			/*
			 * Just do one big block so we can
			 * call this function once to open the
			 * epoch and once to close it.
			 */
			csz = bigblock_caps - bigblock_offset;
			break;
		default:
			csz = rand() % 1024 + 1;
			csz = MIN(csz, bigblock_caps - bigblock_offset);
			break;
		}

		if (verbose > 1) {
			fprintf(stderr, "left=%zd csz=%zd\n",
			    bigblock_caps - bigblock_offset, csz);
		}

		void **chunk = cheri_setbounds(bigblock + bigblock_offset,
		    csz * sizeof(void *));

		if (verbose > 1) {
			fprintf(stderr, "chunk: %#.16lp\n", chunk);
		}

		size_t chunk_offset = bigblock_offset;
		bigblock_offset += csz;

		if (mode == TCLR_MODE_LOAD_SPLIT_FINI)
			goto load_split_fini;

		if (verbose > 3) {
			ptrdiff_t fwo, lwo;
			uint64_t fwm, lwm;
			caprev_shadow_nomap_offsets((ptraddr_t)chunk,
			    csz * sizeof(void *), &fwo, &lwo);
			caprev_shadow_nomap_masks((ptraddr_t)chunk,
			    csz * sizeof(void *), &fwm, &lwm);

			fprintf(stderr,
			    "premrk fwo=%lx lwo=%lx fw=%p *fw=%016lx "
			    "(fwm=%016lx) *lw=%016lx (lwm=%016lx)\n",
			    fwo, lwo, cheri_setaddress(shadow, sbase + fwo),
			    *(uint64_t *)(cheri_setaddress(shadow,
			    sbase + fwo)), fwm,
			    *(uint64_t *)(cheri_setaddress(shadow,
			    sbase + lwo)), lwm);
		}

		/* Mark the chunk for revocation */
		CHERIBSDTEST_VERIFY2(caprev_shadow_nomap_set(
		    cri->base_mem_nomap, shadow, chunk, chunk) == 0,
		    "Shadow update collision");

		__atomic_thread_fence(__ATOMIC_RELEASE);

		if (verbose > 3) {
			ptrdiff_t fwo, lwo;
			caprev_shadow_nomap_offsets((ptraddr_t)chunk,
			    csz * sizeof(void *), &fwo, &lwo);

			fprintf(stderr,
			    "marked fwo=%lx lwo=%lx fw=%p *fw=%016lx "
			    "*lw=%016lx\n",
			    fwo, lwo, cheri_setaddress(shadow, sbase + fwo),
			    *(uint64_t *)(cheri_setaddress(shadow,
			    sbase + fwo)),
			    *(uint64_t *)(cheri_setaddress(shadow,
			    sbase + lwo)));
		}

		{
			int crflags = CHERI_REVOKE_IGNORE_START |
			    CHERI_REVOKE_TAKE_STATS;

			switch(mode) {
			case TCLR_MODE_LOAD_ONCE:
				crflags |= CHERI_REVOKE_LAST_PASS;
				break;
			}

			CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(crflags, 0,
			    &crsi));
			CHERIBSDTEST_VERIFY2(cri->epochs.dequeue ==
			    crsi.epochs.dequeue, "Bad shared clock");
		}

		/* Check the surroundings */
		if (paranoia > 1) {
			for (size_t ix = 0; ix < chunk_offset; ix++) {
				CHERIBSDTEST_VERIFY2(
				    !check_revoked(bigblock[ix]),
				    "Revoked cap incorrectly below object, "
				    "at ix=%zd", ix);
			}
			for (size_t ix = chunk_offset + csz; ix < bigblock_caps;
			    ix++) {
				CHERIBSDTEST_VERIFY2(
				    !check_revoked(bigblock[ix]),
				    "Revoked cap incorrectly above object, "
				    "at ix=%zd", ix);
			}
		}

		if (paranoia > 0) {
			for (size_t ix = 0; ix < csz; ix++) {
				if (!check_revoked(chunk[ix])) {
					fprintf(stderr, "c %#.16lp\n",
					    chunk[ix]);
					cheribsdtest_failure_errx(
					    "Unrevoked at ix=%zd after revoke",
					    ix);
				}
			}
		}
		if (mode == TCLR_MODE_LOAD_SPLIT_INIT)
			return;

		if (mode == TCLR_MODE_LOAD_SPLIT) {
load_split_fini:
			CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(
			    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
			    CHERI_REVOKE_TAKE_STATS, 0, &crsi));
			CHERIBSDTEST_VERIFY2(cri->epochs.dequeue ==
			    crsi.epochs.dequeue, "Bad shared clock");
		}

		caprev_shadow_nomap_clear(cri->base_mem_nomap, shadow, chunk);
		__atomic_thread_fence(__ATOMIC_RELEASE);

		for (size_t ix = 0; ix < csz; ix++) {
			/* Put everything back */
			chunk[ix] = cheri_andperm(
			    cheri_setbounds(&chunk[ix], 16),
			    ~CHERI_PERM_SW_VMEM);
		}
	}
}

CHERIBSDTEST(cheri_revoke_lib, "Test libcheri_caprevoke internals",
    .ct_check_skip = skip_need_cheri_revoke)
{
	/*
	 * Tweaking paranoia can turn this test into more of a
	 * benchmark than a correctness test.  At 0, no checks
	 * will be performed; at 1, only the revoked object is
	 * investigated, and at 2, the entire allocation arena
	 * is tested.
	 */
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	srand(1337);

	cheribsdtest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	cheribsdtest_cheri_revoke_lib_run(paranoia,
	    TCLR_MODE_LOAD_ONCE, bigblock_caps, bigblock, shadow, cri);

	cheribsdtest_cheri_revoke_lib_run(paranoia,
	    TCLR_MODE_LOAD_SPLIT, bigblock_caps, bigblock, shadow, cri);

	munmap(bigblock, bigblock_caps * sizeof(void *));

	cheribsdtest_success();
}

CHERIBSDTEST(cheri_revoke_lib_fork, "Test libcheri_caprevoke with fork",
    .ct_check_skip = skip_need_cheri_revoke)
{
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	int pid;

	srand(1337);

	cheribsdtest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	pid = fork();
	if (pid == 0) {
		cheribsdtest_cheri_revoke_lib_run(paranoia,
		    TCLR_MODE_LOAD_ONCE, bigblock_caps, bigblock, shadow, cri);

		cheribsdtest_cheri_revoke_lib_run(paranoia,
		    TCLR_MODE_LOAD_SPLIT, bigblock_caps, bigblock, shadow, cri);
	} else {
		int res;

		CHERIBSDTEST_VERIFY2(pid > 0, "fork failed");
		waitpid(pid, &res, 0);
		if (res == 0) {
			cheribsdtest_success();
		} else {
			cheribsdtest_failure_errx("Bad child process exit");
		}
	}

	munmap(bigblock, bigblock_caps * sizeof(void *));

	cheribsdtest_success();
}

CHERIBSDTEST(cheri_revoke_lib_fork_split,
    "Test libcheri_caprevoke split across fork",
    .ct_check_skip = skip_need_cheri_revoke)
{
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	int pid;

	srand(1337);

	cheribsdtest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	/* Open the epoch and begin revocation */
	cheribsdtest_cheri_revoke_lib_run(paranoia,
	    TCLR_MODE_LOAD_SPLIT_INIT, bigblock_caps, bigblock, shadow, cri);

	pid = fork();
	if (pid == 0) {
		/* Finish revocation */
		cheribsdtest_cheri_revoke_lib_run(paranoia,
		    TCLR_MODE_LOAD_SPLIT_FINI, bigblock_caps, bigblock,
		    shadow, cri);
	} else {
		int res;

		CHERIBSDTEST_VERIFY2(pid > 0, "fork failed");
		waitpid(pid, &res, 0);
		if (res == 0) {
			cheribsdtest_success();
		} else {
			cheribsdtest_failure_errx("Bad child process exit");
		}
	}

	munmap(bigblock, bigblock_caps * sizeof(void *));

	cheribsdtest_success();
}

/*
 * cheri_revoke_lib_child_* - test that execed children can revoke
 *
 * We selectively test along three axes:
 *   spawn method: fork+execve, rfork+execve, vfork+execve, posix_spawn
 *   pre-fork revoke: none, once, opened
 *   revoke type: once, split
 *
 * Testing all 24 cases is seems excessive so we limit rfork+execve to a
 * single test (posix_spawn being built on rfork) and alternate between
 * once and split as the difference has not previously resulted in bugs.
 */

static void
cheri_revoke_lib_child_spawn_common(enum spawn_child_mode sc_mode,
    int pre_fork_tclr_mode)
{
	static const int paranoia = 2;
	static const size_t bigblock_caps = 4096;
	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;
	int res;
	pid_t pid;

	/*
	 * Optionally exercise the revocation machinery before spawing a
	 * child process.
	 */
	if (pre_fork_tclr_mode != TCLR_MODE_NONE) {
		srand(1337);

		cheribsdtest_cheri_revoke_lib_init(bigblock_caps, &bigblock,
		    &shadow, &cri);
		cheribsdtest_cheri_revoke_lib_run(paranoia, pre_fork_tclr_mode,
		    bigblock_caps, bigblock, shadow, cri);
	}

	pid = cheribsdtest_spawn_child(sc_mode);

	CHERIBSDTEST_VERIFY2(pid > 0, "spawning child process failed");
	waitpid(pid, &res, 0);
	if (res != 0)
		cheribsdtest_failure_errx("Bad child process exit");

	cheribsdtest_success();
}


static void
cheri_revoke_lib_child_common(int tclr_mode)
{
	static const int paranoia = 2;
	static const size_t bigblock_caps = 4096;
	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	srand(1337);

	cheribsdtest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	/*
	 * Technically the epoch doesn't have to be 0 when a new vmspace is
	 * created, but that's the most logical init value so assert it.
	 *
	 * XXX: check the state
	 */
	CHERIBSDTEST_VERIFY(cri->epochs.enqueue == 0);
	CHERIBSDTEST_VERIFY(cri->epochs.dequeue == 0);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	cheribsdtest_cheri_revoke_lib_run(paranoia, tclr_mode, bigblock_caps,
	    bigblock, shadow, cri);

	munmap(bigblock, bigblock_caps * sizeof(void *));

	exit(0);
}

static void
cheri_revoke_lib_child_once(void)
{
	cheri_revoke_lib_child_common(TCLR_MODE_LOAD_ONCE);
}

static void
cheri_revoke_lib_child_split(void)
{
	cheri_revoke_lib_child_common(TCLR_MODE_LOAD_SPLIT);
}

CHERIBSDTEST(cheri_revoke_lib_child_fork_exec_once,
    "revoke in a fork+exec'd child",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_FORK,
	    TCLR_MODE_NONE);
}

CHERIBSDTEST(cheri_revoke_lib_child_fork_exec_split_prior,
    "split revoke in a fork+exec'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_FORK,
	    TCLR_MODE_LOAD_ONCE);
}

CHERIBSDTEST(cheri_revoke_lib_child_fork_exec_once_opened,
    "revoke in a fork+exec'd child after opening epoch",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_FORK,
	    TCLR_MODE_LOAD_SPLIT_INIT);
}

CHERIBSDTEST(cheri_revoke_lib_child_rfork_exec_split,
    "split revoke in a rfork+exec'd child",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_RFORK,
	    TCLR_MODE_NONE);
}

CHERIBSDTEST(cheri_revoke_lib_child_vfork_exec_once,
    "revoke in a vfork+exec'd child",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_VFORK,
	    TCLR_MODE_NONE);
}

CHERIBSDTEST(cheri_revoke_lib_child_vfork_exec_split_prior,
    "split revoke in a vfork+exec'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_VFORK,
	    TCLR_MODE_LOAD_ONCE);
}

CHERIBSDTEST(cheri_revoke_lib_child_vfork_exec_once_opened,
    "revoke in a vfork+exec'd child after opening epoch",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_VFORK,
	    TCLR_MODE_LOAD_SPLIT_INIT);
}

CHERIBSDTEST(cheri_revoke_lib_child_posix_spawn_split,
    "split revoke in a posix_spawn'd child",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_POSIX_SPAWN,
	    TCLR_MODE_NONE);
}

CHERIBSDTEST(cheri_revoke_lib_child_posix_spawn_once_prior,
    "revoke in a posix_spawn'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_POSIX_SPAWN,
	    TCLR_MODE_LOAD_ONCE);
}

CHERIBSDTEST(cheri_revoke_lib_child_posix_spawn_split_opened,
    "split revoke in a posix_spawn'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_POSIX_SPAWN,
	    TCLR_MODE_LOAD_SPLIT_INIT);
}

CHERIBSDTEST(revoke_largest_quarantined_reservation,
    "Verify that the largest quarantined reservation is revoked",
    .ct_check_skip = skip_need_quarantine_unmapped_reservations)
{
	const size_t res_size = 0x100000000;
	void *res;
	ptraddr_t res_addr;
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	const volatile struct cheri_revoke_info *cri;
	uint pcnt, vmcnt;
	bool found_res;

	/* Make sure this process is revoking */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	res = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, res_size, PROT_READ,
	    MAP_ANON, -1, 0));
	res_addr = (ptraddr_t)res;
	CHERIBSDTEST_CHECK_SYSCALL(munmap(res, res_size));

	psp = procstat_open_sysctl();
	CHERIBSDTEST_VERIFY(psp != NULL);
	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	CHERIBSDTEST_VERIFY(kipp != NULL);
	CHERIBSDTEST_VERIFY(pcnt == 1);
	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIBSDTEST_VERIFY(kivp != NULL);

	found_res = false;
	for (u_int i = 0; i < vmcnt; i++) {
		/*
		 * Look for an entry containing our reservation.  It
		 * may have been merged with a previously quarantined
		 * region so don't expect an exact match.
		 */
		if (kivp[i].kve_start <= res_addr &&
		    kivp[i].kve_end >= res_addr + res_size) {
			found_res = true;
			CHERIBSDTEST_VERIFY(kivp[i].kve_type ==
			    KVME_TYPE_QUARANTINED);
		}
	}
	CHERIBSDTEST_VERIFY2(found_res, "reservation not found in vmmap");

	procstat_freevmmap(psp, kivp);

	/*
	 * XXX: Assume that the revoker will revoke the largest
	 * quarantined reservation.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(
	    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START, 0, NULL));

	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIBSDTEST_VERIFY(kivp != NULL);

	for (u_int i = 0; i < vmcnt; i++) {
		/*
		 * Look for an entry containing our reservation.  We
		 * assuming res_size is large enough that it's the
		 * reservation we revoke, we shouldn't find it.
		 *
		 * XXX: It's possible procstat_getvmmap() could trigger
		 * reuse of this space, but probably not since we'll
		 * have just flushed malloc()'s quarantine list so
		 * there should be plenty of objects on the free list(s).
		 */
		if (kivp[i].kve_start <= res_addr &&
		    kivp[i].kve_end >= res_addr + res_size) {
			cheribsdtest_failure_errx(
			    "reservation still in memory map");
		}
	}

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	cheribsdtest_success();
}

#define	NRES	3
CHERIBSDTEST(revoke_merge_quarantined,
    "Verify that adjacent non-neighbor reservations are revoked",
    .ct_check_skip = skip_need_quarantine_unmapped_reservations)
{
	const size_t big_res_size = 0x100000000;
	const size_t res_sizes[NRES] =
	    { PAGE_SIZE, big_res_size, PAGE_SIZE };
	const size_t res_offsets[NRES] =
	    { PAGE_SIZE, big_res_size, 3 * big_res_size };
	void *res;
	ptraddr_t res_addrs[NRES], working_space;
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	const volatile struct cheri_revoke_info *cri;
	uint pcnt, vmcnt;
	bool found_res[NRES] = {};

	/* Make sure this process is revoking */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	/*
	 * Create a single large quarantined reservation with three
	 * non-adjacent, quarantined neighbors inside it (the edges are
	 * padded to prevent merging with neighbors are creation time).
	 *
	 * The three quarantined regions are:
	 *  - A PAGE_SIZE entry at offset PAGE_SIZE.
	 *  - A large (big_res_size) allocation at offset big_res_size.
	 *  - A PAGE_SIZE reservation at offset 3*big_res_size.
	 */
	working_space = find_address_space_gap(big_res_size * 4, 0);
	for (int r = 0; r < NRES; r++) {
		res = CHERIBSDTEST_CHECK_SYSCALL(mmap(
		    (void *)(uintptr_t)(working_space + res_offsets[r]),
		    res_sizes[r], PROT_READ, MAP_ANON, -1, 0));
		res_addrs[r] = (ptraddr_t)res;
		CHERIBSDTEST_CHECK_SYSCALL(munmap(res, res_sizes[r]));
	}

	psp = procstat_open_sysctl();
	CHERIBSDTEST_VERIFY(psp != NULL);
	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	CHERIBSDTEST_VERIFY(kipp != NULL);
	CHERIBSDTEST_VERIFY(pcnt == 1);
	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIBSDTEST_VERIFY(kivp != NULL);

	/*
	 * Check that there are quarantines resevations at each expected
	 * location.
	 */
	for (u_int i = 0; i < vmcnt; i++) {
		for (int r = 0; r < NRES; r++) {
			if (kivp[i].kve_start == res_addrs[r]) {
				found_res[r] = true;
				CHERIBSDTEST_VERIFY(kivp[i].kve_type ==
				    KVME_TYPE_QUARANTINED);
			}
		}
	}
	for (int r = 0; r < NRES; r++)
		CHERIBSDTEST_VERIFY2(found_res[r],
		    "reservation not found in vmmap");

	procstat_freevmmap(psp, kivp);

	/*
	 * XXX: Assume that the revoker will revoke the largest
	 * quarantined reservation and merge it with it's neighbors.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(
	    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START, 0, NULL));

	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIBSDTEST_VERIFY(kivp != NULL);

	for (u_int i = 0; i < vmcnt; i++) {
		/*
		 * Check that no entries overlap our working space.
		 */
		if ((kivp[i].kve_start >= working_space &&
		    kivp[i].kve_start < working_space + (4 * big_res_size)) ||
		    (kivp[i].kve_end - 1 >= working_space &&
		    kivp[i].kve_end - 1 < working_space + (4 * big_res_size))) {
			cheribsdtest_failure_errx(
			    "reservation(s) still in memory map");
		}
	}

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	cheribsdtest_success();
}
#undef NRES

/*
 * A simple test to confirm that revocation of a capability in a COW mapping
 * affects only the caller's mapping.
 */
CHERIBSDTEST(cheri_revoke_cow_mapping,
    "verify that revocation of a COW page triggers a copy",
    .ct_check_skip = skip_need_cheri_revoke)
{
	void **block, **cap1, **cap2;
	void *shadow, *torev;
	ssize_t n;
	size_t blocksz;
	pid_t child;
	int pd[2], res;
	char ch, st[2];

	/*
	 * Use three pages for our heap.  The last page will be revoked.  The
	 * first two pages contain a pointer into the third page; the first
	 * page will be unmapped before revocation, while the second will remain
	 * mapped.  This difference exercises different code paths in the
	 * revoker.
	 */
	blocksz = 3 * PAGE_SIZE;
	block = mmap(NULL, blocksz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY(block != MAP_FAILED);

	torev = cheri_setbounds(block + 2 * PAGE_SIZE / sizeof(void *),
	    PAGE_SIZE);
	cap1 = cheri_setbounds(&block[0], PAGE_SIZE);
	cap2 = cheri_setbounds(&block[PAGE_SIZE / sizeof(void *)], PAGE_SIZE);
	*cap1 = *cap2 = cheri_andperm(torev, ~CHERI_PERM_SW_VMEM);

	child = fork();
	if (child == -1)
		cheribsdtest_failure_errx("Fork failed; errno=%d", errno);
	if (child == 0) {
		/*
		 * Quarantine the third page.
		 */
		if (cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM,
		    torev, &shadow) != 0)
			_exit(1);
		memset(shadow, 0xff, cheri_getlen(shadow));

		/*
		 * Remove the first page from our page tables without modifying
		 * the logical mapping (i.e., without using munmap(2)).  This
		 * means that the revoker will visit the page, but cannot use
		 * the page tables to find it, so helps exercise different code
		 * paths.
		 */
		if (msync(cap1, PAGE_SIZE, MS_INVALIDATE) != 0)
			_exit(2);
		if (mincore(block, 2 * PAGE_SIZE, st) != 0)
			_exit(3);
		if ((st[0] & MINCORE_INCORE) != 0)
			_exit(4);

		/*
		 * Revoke the third page of our heap.
		 */
		if (cheri_revoke(CHERI_REVOKE_IGNORE_START |
		    CHERI_REVOKE_LAST_PASS, 0, NULL) != 0)
			_exit(6);

		if (!check_revoked(*cap1))
			_exit(7);
		if (!check_revoked(*cap2))
			_exit(8);
		_exit(0);
	}

	waitpid(child, &res, 0);
	if (!WIFEXITED(res) || WEXITSTATUS(res) != 0) {
		cheribsdtest_failure_errx("Bad child process exit: %d",
		    WEXITSTATUS(res));
	}

	/*
	 * Make sure our copies of the capability were preserved.
	 */
	CHERIBSDTEST_VERIFY(!check_revoked(*cap1));
	CHERIBSDTEST_VERIFY(!check_revoked(*cap2));

	/*
	 * Repeat the test, this time revoking in the parent.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(pipe(pd));
	child = fork();
	if (child == -1)
		cheribsdtest_failure_errx("Fork failed; errno=%d", errno);
	if (child == 0) {
		/*
		 * Block until the parent revokes the capability.
		 */
		n = read(pd[0], &ch, 1);
		if (n != 1)
			_exit(1);

		/*
		 * Make sure the child's copies of the capability were
		 * preserved.
		 */
		if (check_revoked(*cap1))
			_exit(5);
		if (check_revoked(*cap2))
			_exit(6);
		_exit(0);
	}

	/*
	 * Quarantine the third page.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_NOVMEM, torev, &shadow));
	memset(shadow, 0xff, cheri_getlen(shadow));

	/*
	 * Remove the first page from our page tables without modifying the
	 * logical mapping (i.e., without using munmap(2)).  This means that the
	 * revoker will visit the page, but cannot use the page tables to find
	 * it, so helps exercise different code paths.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(msync(cap1, PAGE_SIZE, MS_INVALIDATE));
	CHERIBSDTEST_CHECK_SYSCALL(mincore(block, 2 * PAGE_SIZE, st));
	CHERIBSDTEST_VERIFY((st[0] & MINCORE_INCORE) == 0);
	CHERIBSDTEST_VERIFY((st[1] & MINCORE_INCORE) != 0);

	/*
	 * Revoke the third page of our heap.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(
	    CHERI_REVOKE_IGNORE_START | CHERI_REVOKE_LAST_PASS, 0, NULL));

	CHERIBSDTEST_VERIFY(check_revoked(*cap1));
	CHERIBSDTEST_VERIFY(check_revoked(*cap2));

	/*
	 * Wake up our child and wait for it to verify its copy of the
	 * capability.
	 */
	n = write(pd[1], &ch, 1);
	CHERIBSDTEST_VERIFY(n == 1);

	waitpid(child, &res, 0);
	if (!WIFEXITED(res) || WEXITSTATUS(res) != 0) {
		cheribsdtest_failure_errx("Bad child 2 process exit: %d",
		    WEXITSTATUS(res));
	}

	CHERIBSDTEST_CHECK_SYSCALL(munmap(block, blocksz));
	CHERIBSDTEST_CHECK_SYSCALL(close(pd[0]));
	CHERIBSDTEST_CHECK_SYSCALL(close(pd[1]));

	cheribsdtest_success();
}
#endif /* CHERIBSDTEST_CHERI_REVOKE_TESTS */

#endif /* __CHERI_PURE_CAPABILITY__ */
