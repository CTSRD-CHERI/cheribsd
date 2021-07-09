/*-
 * Copyright (c) 2014, 2016 Robert N. M. Watson
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
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/wait.h>

#include <cheri/revoke.h>
#include <sys/event.h>

#include <machine/frame.h>
#include <machine/trap.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

static const char * xfail_need_writable_tmp(const char *name __unused);

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

CHERIBSDTEST(cheribsdtest_vm_tag_mmap_anon,
    "check tags are stored for MAP_ANON pages")
{
	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE, MAP_ANON);
	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_vm_tag_shm_open_anon_shared,
    "check tags are stored for SHM_ANON MAP_SHARED pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED);
	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_vm_tag_shm_open_anon_private,
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
CHERIBSDTEST(cheribsdtest_vm_tag_shm_open_anon_shared2x,
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

CHERIBSDTEST(cheribsdtest_vm_shm_open_anon_unix_surprise,
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

		fprintf(stderr, "rx cap: v:%lu b:%016jx l:%016zx o:%jx\n",
			(unsigned long)cheri_gettag(c), cheri_getbase(c),
			cheri_getlen(c), cheri_getoffset(c));

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

		fprintf(stderr, "tx cap: v:%lu b:%016jx l:%016zx o:%jx\n",
			(unsigned long)cheri_gettag(c), cheri_getbase(c),
			cheri_getlen(c), cheri_getoffset(c));

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

#ifdef __CHERI_PURE_CAPABILITY__

/*
 * We can fork processes with shared file descriptor tables, including
 * shared access to a kqueue, which can hoard capabilities for us, allowing
 * them to flow between address spaces.  It is difficult to know what to do
 * about this case, but it seems important to acknowledge.
 */
CHERIBSDTEST(cheribsdtest_vm_cap_share_fd_kqueue,
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

		fprintf(stderr, "oke.udata %#lp\n", oke.udata);

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
CHERIBSDTEST(cheribsdtest_vm_cap_share_sigaction,
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
		fprintf(stderr, "child value read from sigaction(): ");
		fprintf(stderr, "sa.sa_handler %#lp\n", sa.sa_handler);
		CHERIBSDTEST_CHECK_EQ_CAP(sa.sa_handler, passme);

		exit(0);
	} else {
		struct sigaction sa;

		waitpid(pid, NULL, 0);

		bzero(&sa, sizeof(sa));
		sa.sa_flags = 1;

		CHERIBSDTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, NULL, &sa));
		fprintf(stderr, "parent sa read from sigaction(): ");
		fprintf(stderr, "sa.sa_handler %#lp\n", sa.sa_handler);

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

CHERIBSDTEST(cheribsdtest_vm_tag_dev_zero_shared,
    "check tags are stored for /dev/zero MAP_SHARED pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(open("/dev/zero", O_RDWR));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED);
	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_vm_tag_dev_zero_private,
    "check tags are stored for /dev/zero MAP_PRIVATE pages")
{
	int fd = CHERIBSDTEST_CHECK_SYSCALL(open("/dev/zero", O_RDWR));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	cheribsdtest_success();
}

static int
create_tempfile()
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
CHERIBSDTEST(cheribsdtest_vm_notag_tmpfile_shared,
    "check tags are not stored for tmpfile() MAP_SHARED pages",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
    .ct_check_xfail = xfail_need_writable_tmp)
{
	void * __capability volatile *cp;
	void * __capability cp_value;
	int fd, v;

	fd = create_tempfile();
	cp = CHERIBSDTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;
	cheribsdtest_failure_errx("tagged store succeeded");
}

CHERIBSDTEST(cheribsdtest_vm_tag_tmpfile_private,
    "check tags are stored for tmpfile() MAP_PRIVATE pages",
    .ct_check_xfail = xfail_need_writable_tmp)
{
	int fd = create_tempfile();
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_vm_tag_tmpfile_private_prefault,
    "check tags are stored for tmpfile() MAP_PRIVATE, MAP_PREFAULT_READ pages",
    .ct_check_xfail = xfail_need_writable_tmp)
{
	int fd = create_tempfile();
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_PREFAULT_READ);
	cheribsdtest_success();
}

static const char *
xfail_need_writable_tmp(const char *name __unused)
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
CHERIBSDTEST(cheribsdtest_vm_cow_read,
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

CHERIBSDTEST(cheribsdtest_vm_cow_write,
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
CHERIBSDTEST(cheribsdtest_vm_capdirty, "verify capdirty marking and mincore")
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

/*
 * Revocation tests
 */

#ifdef CHERI_REVOKE

/* Ick */
static inline uint64_t
get_cyclecount()
{
#if defined(__mips__)
	return cheri_get_cyclecount();
#elif defined(__riscv)
	return __builtin_readcyclecounter();
#else
	return 0;
#endif
}

static int
check_revoked(void * __capability r)
{
	return (cheri_gettag(r) == 0) ||
	    ((cheri_gettype(r) == -1L) && (cheri_getperm(r) == 0));
}

static void
install_kqueue_cap(int kq, void * __capability revme)
{
	struct kevent ike;

	EV_SET(&ike, (uintptr_t)&install_kqueue_cap,
	    EVFILT_USER, EV_ADD | EV_ONESHOT | EV_DISABLE, NOTE_FFNOP, 0,
	    revme);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	EV_SET(&ike, (uintptr_t)&install_kqueue_cap, EVFILT_USER, EV_KEEPUDATA,
	    NOTE_FFNOP | NOTE_TRIGGER, 0, NULL);
	CHERIBSDTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
}

static void
check_kqueue_cap(int kq, unsigned int valid)
{
	struct kevent ike, oke = { 0 };

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
}

static void
fprintf_cheri_revoke_stats(FILE *f, struct cheri_revoke_syscall_info crsi,
    uint32_t cycsum)
{
	fprintf(f, "revoke:"
		" edeq=%" PRIu64
		" eenq=%" PRIu64

		" psro=%" PRIu32
		" psrw=%" PRIu32

		" pfro=%" PRIu32
		" pfrw=%" PRIu32

		" pclg=%" PRIu32

		" pskf=%" PRIu32
		" pskn=%" PRIu32
		" psks=%" PRIu32

		" cfnd=%" PRIu32
		" cfrv=%" PRIu32
		" cnuk=%" PRIu32

		" lscn=%" PRIu32
		" pmkc=%" PRIu32

		" pcyc=%" PRIu64
		" fcyc=%" PRIu64
		" tcyc=%" PRIu32
		"\n",

		crsi.epochs.dequeue,
		crsi.epochs.enqueue,

		crsi.stats.pages_scan_ro,
		crsi.stats.pages_scan_rw,

		crsi.stats.pages_faulted_ro,
		crsi.stats.pages_faulted_rw,

		crsi.stats.fault_visits,

		crsi.stats.pages_skip_fast,
		crsi.stats.pages_skip_nofill,
		crsi.stats.pages_skip,

		crsi.stats.caps_found,
		crsi.stats.caps_found_revoked,
		crsi.stats.caps_cleared,

		crsi.stats.lines_scan,
		crsi.stats.pages_mark_clean,

		crsi.stats.page_scan_cycles,
		crsi.stats.fault_cycles,
		cycsum);
}

CHERIBSDTEST(cheribsdtest_cheri_revoke_lightly,
    "A gentle test of capability revocation")
{
	void * __capability * __capability mb;
	void * __capability sh;
	const volatile struct cheri_revoke_info * __capability cri;
	void * __capability revme;
	struct cheri_revoke_syscall_info crsi;
	int kq;
	uint32_t cyc_start, cyc_end;

	kq = CHERIBSDTEST_CHECK_SYSCALL(kqueue());
	mb = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_shadow(CHERI_REVOKE_SHADOW_NOVMMAP, mb, &sh));

	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY_CAP(void * __capability *, &cri)));

	/*
	 * OK, armed with the shadow mapping... generate a capability to
	 * the 0th granule of the map, spill it to the 1st granule,
	 * stash it in the kqueue, and mark it as revoked in the shadow.
	 */
	revme = cheri_andperm(mb, ~CHERI_PERM_CHERIABI_VMMAP);
	((void * __capability *)mb)[1] = revme;
	install_kqueue_cap(kq, revme);

	((uint8_t * __capability)sh)[0] = 1;

	crsi.epochs.enqueue = 0xC0FFEE;
	crsi.epochs.dequeue = 0xB00;

	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS , 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIBSDTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");
	check_kqueue_cap(kq, 0);

	/* Clear the revocation bit and do that again */
	((uint8_t * __capability)sh)[0] = 0;

	/*
	 * We don't derive exactly the same thing, to prevent CSE from
	 * firing.  More specifically, we adjust the offset first, taking
	 * the path through the commutation diagram that doesn't share an
	 * edge with the derivation above.
	 */
	revme = cheri_andperm(mb + 1, ~CHERI_PERM_CHERIABI_VMMAP);
	CHERIBSDTEST_VERIFY2(!check_revoked(revme), "Tag clear on 2nd revme?");
	((void * __capability *)mb)[1] = revme;
	install_kqueue_cap(kq, revme);

	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_VERIFY2(
	    crsi.epochs.enqueue >= crsi.epochs.dequeue + 1,
	    "Bad epoch clock state");

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS,
	    crsi.epochs.enqueue, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIBSDTEST_VERIFY2(!check_revoked(mb[1]), "Memory tag cleared");

	check_kqueue_cap(kq, 1);

	munmap(mb, PAGE_SIZE);
	close(kq);

	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_cheri_revoke_capdirty,
    "Probe the interaction of revocation and capdirty")
{
	void * __capability * __capability mb;
	void * __capability sh;
	const volatile struct cheri_revoke_info * __capability cri;
	void * __capability revme;
	struct cheri_revoke_syscall_info crsi;
	uint32_t cyc_start, cyc_end;

	mb = CHERIBSDTEST_CHECK_SYSCALL(mmap(0, PAGE_SIZE, PROT_READ |
	    PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_shadow(CHERI_REVOKE_SHADOW_NOVMMAP,
	    mb, &sh));

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY_CAP(void * __capability *,&cri)));

	revme = cheri_andperm(cheri_setbounds(mb, 0x10),
			      ~CHERI_PERM_CHERIABI_VMMAP);
	mb[0] = revme;

	/* Mark the start of the arena as subject to revocation */
	((uint8_t * __capability) sh)[0] = 1;

	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_VERIFY2(cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	fprintf(stderr, "revme: %#.16lp\n", revme);
	fprintf(stderr, "mb[0]: %#.16lp\n", mb[0]);

	/* Between revocation sweeps, derive another cap and store */
	revme = cheri_andperm(cheri_setbounds(mb, 0x11),
	    ~CHERI_PERM_CHERIABI_VMMAP);
	mb[1] = revme;

	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_VERIFY2(cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	fprintf(stderr, "revme: %#.16lp\n", revme);
	fprintf(stderr, "mb[0]: %#.16lp\n", mb[0]);
	fprintf(stderr, "mb[1]: %#.16lp\n", mb[1]);

	/* Between revocation sweeps, derive another cap and store */
	revme = cheri_andperm(cheri_setbounds(mb, 0x12),
	    ~CHERI_PERM_CHERIABI_VMMAP);
	mb[2] = revme;

	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_LAST_PASS |
	    CHERI_REVOKE_IGNORE_START | CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_VERIFY2(cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	fprintf(stderr, "revme: %#.16lp\n", revme);
	fprintf(stderr, "mb[0]: %#.16lp\n", mb[0]);
	fprintf(stderr, "mb[1]: %#.16lp\n", mb[1]);
	fprintf(stderr, "mb[2]: %#.16lp\n", mb[2]);

	CHERIBSDTEST_VERIFY2(!check_revoked(mb), "Arena revoked");
	CHERIBSDTEST_VERIFY2(check_revoked(revme), "Register tag cleared");
	CHERIBSDTEST_VERIFY2(check_revoked(mb[0]), "Memory tag 0 cleared");
	CHERIBSDTEST_VERIFY2(check_revoked(mb[1]), "Memory tag 1 cleared");
	CHERIBSDTEST_VERIFY2(check_revoked(mb[2]), "Memory tag 2 cleared");

	munmap(mb, PAGE_SIZE);

	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_cheri_revoke_loadside, "Test load-side revoker")
{
#define CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG	3

	void * __capability * __capability mb;
	void * __capability sh;
	const volatile struct cheri_revoke_info * __capability cri;
	void * __capability revme;
	struct cheri_revoke_syscall_info crsi;
	uint32_t cyc_start, cyc_end;
	unsigned char mcv[CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG] = { 0 };
	const size_t asz = CHERIBSDTEST_VM_CHERI_REVOKE_LOADSIDE_NPG *
	    PAGE_SIZE;

	mb = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, asz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_shadow(CHERI_REVOKE_SHADOW_NOVMMAP, mb, &sh));

	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY_CAP(void * __capability *, &cri)));

	revme = cheri_andperm(mb, ~CHERI_PERM_CHERIABI_VMMAP);
	((void * __capability *)mb)[1] = revme;
	((uint8_t * __capability)sh)[0] = 1;

	/* Write and clear a capability one page up */
	size_t capsperpage = PAGE_SIZE/sizeof(void * __capability);
	((void * __capability volatile *)mb)[capsperpage] = revme;
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
	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_LOAD_SIDE |
	    CHERI_REVOKE_IGNORE_START | CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	/*
	 * Try to induce a read fault and check that the read result is revoked.
	 * Unfortunately, we can't check its capdirty status, but it should
	 * still be CAPSTORED, since not enough time has elapsed for the state
	 * machine to declare it clean.
	 */
	revme = ((void * __capability *)mb)[1];
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
	((void * __capability *)mb)[2] = revme;

	/*
	 * Now do the background sweep and wait for everything to finish
	 */
	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
		CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

	CHERIBSDTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIBSDTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.1");
	CHERIBSDTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.1");

	/* Re-dirty page 0 but not page 1 */
	revme = cheri_andperm(mb + 1, ~CHERI_PERM_CHERIABI_VMMAP);
	CHERIBSDTEST_VERIFY2(!check_revoked(revme), "Tag clear on 2nd revme?");
	((void * __capability *)mb)[1] = revme;

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
	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LOAD_SIDE | CHERI_REVOKE_LAST_PASS |
	        CHERI_REVOKE_IGNORE_START | CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

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
	cyc_start = get_cyclecount();
	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LOAD_SIDE | CHERI_REVOKE_LAST_PASS |
	        CHERI_REVOKE_IGNORE_START | CHERI_REVOKE_TAKE_STATS, 0, &crsi));
	cyc_end = get_cyclecount();
	fprintf_cheri_revoke_stats(stderr, crsi, cyc_end - cyc_start);

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

/*
 * Repeatedly invoke libcheri_cheri_revoke logic.
 * Using a bump the pointer allocator, repeatedly grab rand()-omly sized
 * objects and fill them with capabilities to themselves, mark them for
 * revocation, revoke, and validate.
 *
 */

#include <cheri/libcaprevoke.h>

/* Just for debugging printouts */
#ifndef CPU_CHERI
#define CPU_CHERI
#include <machine/pte.h>
#include <machine/vmparam.h>
#undef CPU_CHERI
#else
#include <machine/pte.h>
#include <machine/vmparam.h>
#endif

static void
cheribsdtest_cheri_revoke_lib_init(
	size_t bigblock_caps,
	void * __capability * __capability * obigblock,
	void * __capability * oshadow,
	const volatile struct cheri_revoke_info * __capability * ocri
)
{
	void * __capability * __capability bigblock;

	bigblock = CHERIBSDTEST_CHECK_SYSCALL(
			mmap(0, bigblock_caps * sizeof(void * __capability),
				PROT_READ | PROT_WRITE,
				MAP_ANON, -1, 0));

	for (size_t ix = 0; ix < bigblock_caps; ix++) {
		/* Create self-referential VMMAP-free capabilities */

		bigblock[ix] = cheri_andperm(
				cheri_setbounds(&bigblock[ix], 16),
				~CHERI_PERM_CHERIABI_VMMAP);
	}
	*obigblock = bigblock;

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke_shadow(CHERI_REVOKE_SHADOW_NOVMMAP, bigblock,
	    oshadow));

	CHERIBSDTEST_CHECK_SYSCALL(
		cheri_revoke_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
			__DEQUALIFY_CAP(void * __capability *,ocri)));
}

enum {
	TCLR_MODE_STORE = 0,
	TCLR_MODE_LOAD_ONCE = 1,
	TCLR_MODE_LOAD_SPLIT = 2,
};

static void
cheribsdtest_cheri_revoke_lib_run(
	int verbose,
	int paranoia,
	int mode,
	size_t bigblock_caps,
	void * __capability * __capability bigblock,
	void * __capability shadow,
	const volatile struct cheri_revoke_info * __capability cri
)
{
	size_t bigblock_offset = 0;
	const vaddr_t sbase = cri->base_mem_nomap;

	fprintf(stderr, "test_cheri_revoke_lib_run mode %d\n", mode);

	while (bigblock_offset < bigblock_caps) {
		struct cheri_revoke_syscall_info crsi;
		uint32_t cyc_start, cyc_end;

		size_t csz = rand() % 1024 + 1;
		csz = MIN(csz, bigblock_caps - bigblock_offset);

		if (verbose > 1) {
			fprintf(stderr, "left=%zd csz=%zd\n",
					bigblock_caps - bigblock_offset,
					csz);
		}

		void * __capability * __capability chunk =
			cheri_setbounds(bigblock + bigblock_offset,
					 csz * sizeof(void * __capability));

		if (verbose > 1) {
			fprintf(stderr, "chunk: %#.16lp\n", chunk);
		}

		size_t chunk_offset = bigblock_offset;
		bigblock_offset += csz;

		if (verbose > 3) {
			ptrdiff_t fwo, lwo;
			uint64_t fwm, lwm;
			caprev_shadow_nomap_offsets((vaddr_t)chunk,
				csz * sizeof(void * __capability), &fwo, &lwo);
			caprev_shadow_nomap_masks((vaddr_t)chunk,
				csz * sizeof(void * __capability), &fwm, &lwm);

			fprintf(stderr,
				"premrk fwo=%lx lwo=%lx fw=%p "
				"*fw=%016lx (fwm=%016lx) *lw=%016lx "
				"(lwm=%016lx)\n",
				fwo, lwo,
				cheri_setaddress(shadow, sbase + fwo),
				*(uint64_t *)(cheri_setaddress(shadow,
					sbase + fwo)),
				fwm,
				*(uint64_t *)(cheri_setaddress(shadow,
					sbase + lwo)),
				lwm);
		}

		/* Mark the chunk for revocation */
		CHERIBSDTEST_VERIFY2(caprev_shadow_nomap_set(
		    cri->base_mem_nomap, shadow, chunk, chunk) == 0,
		    "Shadow update collision");

		__atomic_thread_fence(__ATOMIC_RELEASE);

		if (verbose > 3) {
			ptrdiff_t fwo, lwo;
			caprev_shadow_nomap_offsets((vaddr_t)chunk,
				csz * sizeof(void * __capability), &fwo, &lwo);

			fprintf(stderr,
				"marked fwo=%lx lwo=%lx fw=%p "
				"*fw=%016lx *lw=%016lx\n",
				fwo, lwo,
				cheri_setaddress(shadow, sbase + fwo),
				*(uint64_t *)(cheri_setaddress(shadow,
					sbase + fwo)),
				*(uint64_t *)(cheri_setaddress(shadow,
					sbase + lwo)));
		}

		{
			int crflags = CHERI_REVOKE_IGNORE_START |
			    CHERI_REVOKE_TAKE_STATS;

			switch(mode) {
			case TCLR_MODE_STORE:
				crflags |= CHERI_REVOKE_LAST_PASS;
				break;
			case TCLR_MODE_LOAD_ONCE:
				crflags |= CHERI_REVOKE_LAST_PASS |
				    CHERI_REVOKE_LOAD_SIDE;
				break;
			case TCLR_MODE_LOAD_SPLIT:
				crflags |= CHERI_REVOKE_LOAD_SIDE;
				break;
			}

			cyc_start = get_cyclecount();
			CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(crflags, 0,
			    &crsi));
			cyc_end = get_cyclecount();
			if (verbose > 2) {
				fprintf_cheri_revoke_stats(stderr, crsi,
				    cyc_end - cyc_start);
			}
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

		if (mode == TCLR_MODE_LOAD_SPLIT) {
			cyc_start = get_cyclecount();
			CHERIBSDTEST_CHECK_SYSCALL(cheri_revoke(
			    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
			    CHERI_REVOKE_TAKE_STATS, 0, &crsi));
			cyc_end = get_cyclecount();
			if (verbose > 2) {
				fprintf_cheri_revoke_stats(stderr, crsi,
				    cyc_end - cyc_start);
			}
			CHERIBSDTEST_VERIFY2(cri->epochs.dequeue ==
			    crsi.epochs.dequeue, "Bad shared clock");
		}

		caprev_shadow_nomap_clear(cri->base_mem_nomap, shadow, chunk);
		__atomic_thread_fence(__ATOMIC_RELEASE);

		for (size_t ix = 0; ix < csz; ix++) {
			/* Put everything back */
			chunk[ix] = cheri_andperm(
					cheri_setbounds(&chunk[ix], 16),
					~CHERI_PERM_CHERIABI_VMMAP);
		}
	}
}

CHERIBSDTEST(cheribsdtest_cheri_revoke_lib, "Test libcheri_caprevoke internals")
{
		/* If debugging the revoker, some verbosity can help. 0 - 4. */
	static const int verbose = 0;

		/*
		 * Tweaking paranoia can turn this test into more of a
		 * benchmark than a correctness test.  At 0, no checks
		 * will be performed; at 1, only the revoked object is
		 * investigated, and at 2, the entire allocation arena
		 * is tested.
		 */
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void * __capability * __capability bigblock;
	void * __capability shadow;
	const volatile struct cheri_revoke_info * __capability cri;

	srand(1337);

	cheribsdtest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	cheribsdtest_cheri_revoke_lib_run(verbose, paranoia, TCLR_MODE_STORE,
	    bigblock_caps, bigblock, shadow, cri);

	cheribsdtest_cheri_revoke_lib_run(verbose, paranoia,
	    TCLR_MODE_LOAD_ONCE, bigblock_caps, bigblock, shadow, cri);

	cheribsdtest_cheri_revoke_lib_run(verbose, paranoia,
	    TCLR_MODE_LOAD_SPLIT, bigblock_caps, bigblock, shadow, cri);

	munmap(bigblock, bigblock_caps * sizeof(void * __capability));

	cheribsdtest_success();
}

CHERIBSDTEST(cheribsdtest_cheri_revoke_lib_fork,
    "Test libcheri_caprevoke with fork")
{
	static const int verbose = 0;
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void * __capability * __capability bigblock;
	void * __capability shadow;
	const volatile struct cheri_revoke_info * __capability cri;

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
		cheribsdtest_cheri_revoke_lib_run(verbose, paranoia,
		    TCLR_MODE_STORE, bigblock_caps, bigblock, shadow, cri);

		cheribsdtest_cheri_revoke_lib_run(verbose, paranoia,
		    TCLR_MODE_LOAD_ONCE, bigblock_caps, bigblock, shadow, cri);

		cheribsdtest_cheri_revoke_lib_run(verbose, paranoia,
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

	munmap(bigblock, bigblock_caps * sizeof(void * __capability));

	cheribsdtest_success();
}

#endif
