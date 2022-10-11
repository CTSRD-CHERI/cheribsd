/*-
 * Copyright (c) 2003-2004, 2010 Robert N. M. Watson
 * All rights reserved.
 *
 * Portions of this software were developed at the University of Cambridge
 * Computer Laboratory with support from a grant from Google, Inc.
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
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#ifdef __CHERI__
#include <cheri/cheri.h>
#endif

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#ifdef WITH_PTHREAD
#include <pthread.h>
#endif
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_LIBSTATCOUNTERS
#include <statcounters.h>
#endif

/*
 * Enable by default; comment out to measure the overhead.
 */
#define RAW

static struct timespec ts_start, ts_end;
static int alarm_timeout;
#ifdef RAW
#define	RAW_LEN_MAX	10
static int raw_len = 1; /* 1, the time is always measured */
#ifdef WITH_LIBSTATCOUNTERS
static int raw_ids[RAW_LEN_MAX]; /* Array of counter ids */
static uint64_t raw_prevs[RAW_LEN_MAX]; /* Array of last values for each counter */
#endif
static int *raw_numbers = NULL; /* Array of deltas between last and current */
#define	RAW_NUMBER(iteration, counter)	raw_numbers[iteration * raw_len + counter]
#define	RAW_PREV(counter)		raw_prevs[counter]
#endif
#ifdef CHERI_START_TRACE
static volatile int trace;
#endif
static volatile int alarm_fired;

static void
alarm_handler(int signum __unused)
{

	alarm_fired = 1;
}

static void
benchmark_start(void)
{
	int error;

	alarm_fired = 0;
	if (alarm_timeout) {
		signal(SIGALRM, alarm_handler);
		alarm(alarm_timeout);
	}
	error = clock_gettime(CLOCK_REALTIME, &ts_start);
	assert(error == 0);

#ifdef CHERI_START_TRACE
	if (trace)
		CHERI_START_TRACE;
#endif
}

static void
benchmark_stop(void)
{
	int error;

#ifdef CHERI_STOP_TRACE
	if (trace)
		CHERI_STOP_TRACE;
#endif

	error = clock_gettime(CLOCK_REALTIME, &ts_end);
	assert(error == 0);
}

#ifdef RAW
static void
benchmark_iteration(int i)
{
	static struct timespec ts_prev;
	struct timespec ts_diff, ts_now;
#ifdef WITH_LIBSTATCOUNTERS
	uint64_t val;
	int j;
#endif
	int error;

	if (raw_numbers == NULL)
		return;

	/*
	 * Note that this function gets called iterations + 1 times.
	 */

	error = clock_gettime(CLOCK_REALTIME, &ts_now);
	assert(error == 0);

	if (i == 0) {
		ts_prev = ts_now;
#ifdef WITH_LIBSTATCOUNTERS
		for (j = 1; j < raw_len; j++)
			RAW_PREV(j) = statcounters_sample_by_id(raw_ids[j]);
#endif
		return;
	}

	/*
	 * 0 is a special case, it's always the time.
	 */
	ts_diff = ts_now;
	timespecsub(&ts_diff, &ts_prev, &ts_diff);
	assert(ts_diff.tv_sec == 0);
	RAW_NUMBER(i, 0) = ts_diff.tv_nsec;
	ts_prev = ts_now;

#ifdef WITH_LIBSTATCOUNTERS
	for (j = 1; j < raw_len; j++) {
		val = statcounters_sample_by_id(raw_ids[j]);
		assert(val >= RAW_PREV(j));
		RAW_NUMBER(i, j) = val - RAW_PREV(j);
		RAW_PREV(j) = val;
	}
#endif
}
#else /* !RAW */
#define benchmark_iteration(X)	42
#endif
  
#define	BENCHMARK_FOREACH(I, NUM) for (I = 0; benchmark_iteration(I), \
	I < NUM && alarm_fired == 0; I++)

static uintmax_t
test_access(uintmax_t num, uintmax_t int_arg __unused, const char *path)
{
	uintmax_t i;
	int fd;

	fd = access(path, O_RDONLY);
	if (fd < 0)
		err(-1, "test_access: %s", path);
	close(fd);

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		access(path, O_RDONLY);
		close(fd);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_bad_open(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		open("", O_RDONLY);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_chroot(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;

	if (chroot("/") < 0)
		err(-1, "test_chroot: chroot");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		if (chroot("/") < 0)
			err(-1, "test_chroot: chroot");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_clock_gettime(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	struct timespec ts;
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)clock_gettime(CLOCK_REALTIME, &ts);
	}
	benchmark_stop();
	return (i);
}

#ifdef __CHERI_PURE_CAPABILITY__
static uintmax_t
test_coping(uintmax_t num, uintmax_t int_arg, const char *path)
{
	char buf[int_arg];
	void * __capability lookedup;
	uintmax_t i;
	int error;

	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "cosetup");

	error = colookup(path, &lookedup);
	if (error != 0) {
		if (errno == ESRCH) {
			warnx("received ESRCH; this usually means there's nothing coregistered for \"%s\"", path);
			warnx("use coexec(1) to colocate; you might also find \"ps aux -o vmaddr\" useful");
		}
		err(1, "colookup");
	}

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		error = cocall(lookedup, buf, int_arg, buf, int_arg);
		if (error != 0)
			err(1, "cocall");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_coping_slow(uintmax_t num, uintmax_t int_arg, const char *path)
{
	char buf[int_arg];
	void * __capability lookedup;
	uintmax_t i;
	int error;

	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "cosetup");

	error = colookup(path, &lookedup);
	if (error != 0) {
		if (errno == ESRCH) {
			warnx("received ESRCH; this usually means there's nothing coregistered for \"%s\"", path);
			warnx("use coexec(1) to colocate; you might also find \"ps aux -o vmaddr\" useful");
		}
		err(1, "colookup");
	}

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		error = cocall_slow(lookedup, buf, int_arg, buf, int_arg);
		if (error != 0)
			err(1, "cocall");
	}
	benchmark_stop();
	return (i);
}
#endif

static uintmax_t
test_create_unlink(uintmax_t num, uintmax_t int_arg __unused, const char *path)
{
	uintmax_t i;
	int fd;

	(void)unlink(path);
	fd = open(path, O_RDWR | O_CREAT, 0600);
	if (fd < 0)
		err(-1, "test_create_unlink: create: %s", path);
	close(fd);
	if (unlink(path) < 0)
		err(-1, "test_create_unlink: unlink: %s", path);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		fd = open(path, O_RDWR | O_CREAT, 0600);
		if (fd < 0)
			err(-1, "test_create_unlink: create: %s", path);
		close(fd);
		if (unlink(path) < 0)
			err(-1, "test_create_unlink: unlink: %s", path);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_dup(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;
	int fd, shmfd;

	shmfd = shm_open(SHM_ANON, O_CREAT | O_RDWR, 0600);
	if (shmfd < 0)
		err(-1, "test_dup: shm_open");
	fd = dup(shmfd);
	if (fd >= 0)
		close(fd);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		fd = dup(shmfd);
		if (fd >= 0)
			close(fd);
	}
	benchmark_stop();
	close(shmfd);
	return (i);
}

static uintmax_t
test_fork(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	pid_t pid;
	uintmax_t i;

	pid = fork();
	if (pid < 0)
		err(-1, "test_fork: fork");
	if (pid == 0)
		_exit(0);
	if (waitpid(pid, NULL, 0) < 0)
		err(-1, "test_fork: waitpid");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		pid = fork();
		if (pid < 0)
			err(-1, "test_fork: fork");
		if (pid == 0)
			_exit(0);
		if (waitpid(pid, NULL, 0) < 0)
			err(-1, "test_fork: waitpid");
	}
	benchmark_stop();
	return (i);
}

#define	USR_BIN_TRUE	"/usr/bin/true"
static char *execve_args[] = { __DECONST(char *, USR_BIN_TRUE), NULL};
extern char **environ;

static uintmax_t
test_fork_exec(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	pid_t pid;
	uintmax_t i;

	pid = fork();
	if (pid < 0)
		err(-1, "test_fork_exec: fork");
	if (pid == 0) {
		(void)execve(USR_BIN_TRUE, execve_args, environ);
		err(-1, "execve");
	}
	if (waitpid(pid, NULL, 0) < 0)
		err(-1, "test_fork: waitpid");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		pid = fork();
		if (pid < 0)
			err(-1, "test_fork_exec: fork");
		if (pid == 0) {
			(void)execve(USR_BIN_TRUE, execve_args, environ);
			err(-1, "test_fork_exec: execve");
		}
		if (waitpid(pid, NULL, 0) < 0)
			err(-1, "test_fork_exec: waitpid");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_fstat_shmfd(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	struct stat sb;
	uintmax_t i;
	int shmfd;

	shmfd = shm_open(SHM_ANON, O_CREAT | O_RDWR, 0600);
	if (shmfd < 0)
		err(-1, "test_fstat_shmfd: shm_open");
	if (fstat(shmfd, &sb) < 0)
		err(-1, "test_fstat_shmfd: fstat");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)fstat(shmfd, &sb);
	}
	benchmark_stop();
	close(shmfd);
	return (i);
}

static uintmax_t
test_getppid(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;

	/*
	 * This is process-local, but can change, so will require a
	 * lock.
	 */
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		getppid();
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_getpriority(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)getpriority(PRIO_PROCESS, 0);
	}
	benchmark_stop();
	return (i);
}

/*
 * The point of this one is to figure out the cost of a call into libc,
 * through PLT, and back.
 */
static uintmax_t
test_getprogname(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)getprogname();
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_getresuid(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uid_t ruid, euid, suid;
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)getresuid(&ruid, &euid, &suid);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_gettimeofday(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	struct timeval tv;
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)gettimeofday(&tv, NULL);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_getuid(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;

	/*
	 * Thread-local data should require no locking if system
	 * call is MPSAFE.
	 */
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		getuid();
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_lstat(uintmax_t num, uintmax_t int_arg __unused, const char *path)
{
	struct stat sb;
	uintmax_t i;
	int error;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		error = lstat(path, &sb);
		if (error != 0)
			err(-1, "lstat");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_memcpy(uintmax_t num, uintmax_t int_arg, const char *path __unused)
{
	char buf[int_arg], buf2[int_arg];
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		memcpy(buf2, buf, int_arg);
		memcpy(buf, buf2, int_arg);
	}
	benchmark_stop();

	return (i);
}

static uintmax_t
test_open_close(uintmax_t num, uintmax_t int_arg __unused, const char *path)
{
	uintmax_t i;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(-1, "test_open_close: %s", path);
	close(fd);

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		fd = open(path, O_RDONLY);
		if (fd < 0)
			err(-1, "test_open_close: %s", path);
		close(fd);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_open_read_close(uintmax_t num, uintmax_t int_arg, const char *path)
{
	char buf[int_arg];
	uintmax_t i;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(-1, "test_open_read_close: %s", path);
	(void)read(fd, buf, int_arg);
	close(fd);

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		fd = open(path, O_RDONLY);
		if (fd < 0)
			err(-1, "test_open_read_close: %s", path);
		(void)read(fd, buf, int_arg);
		close(fd);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_pipe(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	int fd[2];
	uintmax_t i;

	/*
	 * pipe creation is expensive, as it will allocate a new file
	 * descriptor, allocate a new pipe, hook it all up, and return.
	 * Destroying is also expensive, as we now have to free up
	 * the file descriptors and return the pipe.
	 */
	if (pipe(fd) < 0)
		err(-1, "test_pipe: pipe");
	close(fd[0]);
	close(fd[1]);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		if (pipe(fd) == -1)
			err(-1, "test_pipe: pipe");
		close(fd[0]);
		close(fd[1]);
	}
	benchmark_stop();
	return (i);
}

static void
readx(int fd, char *buf, size_t size)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, size);
		if (ret == -1)
			err(1, "read");
		assert((size_t)ret <= size);
		size -= ret;
		buf += ret;
	} while (size > 0);
}

static void
writex(int fd, const char *buf, size_t size)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, size);
		if (ret == -1)
			err(1, "write");
		assert((size_t)ret <= size);
		size -= ret;
		buf += ret;
	} while (size > 0);
}

static uintmax_t
test_pipeping(uintmax_t num, uintmax_t int_arg, const char *path __unused)
{
	char buf[int_arg];
	uintmax_t i;
	pid_t pid;
	int fd[2], procfd;

	if (pipe(fd) < 0)
		err(-1, "pipe");

	pid = pdfork(&procfd, 0);
	if (pid < 0)
		err(1, "pdfork");

	if (pid == 0) {
		close(fd[0]);

		for (;;) {
			readx(fd[1], buf, int_arg);
			writex(fd[1], buf, int_arg);
		}
	}

	close(fd[1]);

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		writex(fd[0], buf, int_arg);
		readx(fd[0], buf, int_arg);
	}
	benchmark_stop();

	close(procfd);
	return (i);
}

#ifdef WITH_PTHREAD
struct pipepingtd_ctx {
	int		fd;
	uintmax_t	int_arg;
};

static void *
pipepingtd_proc(void *arg)
{
	struct pipepingtd_ctx *ctxp;
	int fd;
	void *buf;
	uintmax_t int_arg;

	ctxp = arg;
	fd = ctxp->fd;
	int_arg = ctxp->int_arg;

	buf = malloc(int_arg);
	if (buf == NULL)
		err(1, "malloc");

	for (;;) {
		readx(fd, buf, int_arg);
		writex(fd, buf, int_arg);
	}
}

static uintmax_t
test_pipepingtd(uintmax_t num, uintmax_t int_arg, const char *path __unused)
{
	struct pipepingtd_ctx ctx;
	char buf[int_arg];
	pthread_t td;
	uintmax_t i;
	int error, fd[2];

	if (pipe(fd) < 0)
		err(-1, "pipe");

	ctx.fd = fd[1];
	ctx.int_arg = int_arg;

	error = pthread_create(&td, NULL, pipepingtd_proc, &ctx);
	if (error != 0)
		err(1, "pthread_create");

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		writex(fd[0], buf, int_arg);
		readx(fd[0], buf, int_arg);
	}
	benchmark_stop();
	pthread_cancel(td);

	return (i);
}
#endif

static uintmax_t
test_read(uintmax_t num, uintmax_t int_arg, const char *path)
{
	char buf[int_arg];
	uintmax_t i;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(-1, "test_open_read: %s", path);
	(void)pread(fd, buf, int_arg, 0);

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)pread(fd, buf, int_arg, 0);
	}
	benchmark_stop();
	close(fd);
	return (i);
}

static uintmax_t
test_select(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	fd_set readfds, writefds, exceptfds;
	struct timeval tv;
	uintmax_t i;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		(void)select(0, &readfds, &writefds, &exceptfds, &tv);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_semaping(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;
	pid_t pid;
	sem_t *buf;
	int error, j, procfd;

	buf = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (buf == MAP_FAILED)
		err(1, "mmap");

	for (j = 0; j < 2; j++) {
		error = sem_init(&buf[j], 1, 0);
		if (error != 0)
			err(1, "sem_init");
	}

	pid = pdfork(&procfd, 0);
	if (pid < 0)
		err(1, "pdfork");

	if (pid == 0) {
		for (;;) {
			error = sem_wait(&buf[0]);
			if (error != 0)
				err(1, "sem_wait");
			error = sem_post(&buf[1]);
			if (error != 0)
				err(1, "sem_post");
		}
	}

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		error = sem_post(&buf[0]);
		if (error != 0)
			err(1, "sem_post");
		error = sem_wait(&buf[1]);
		if (error != 0)
			err(1, "sem_wait");
	}
	benchmark_stop();

	close(procfd);

	for (j = 0; j < 2; j++) {
		error = sem_destroy(&buf[j]);
		if (error != 0)
			err(1, "sem_destroy");
	}

	error = munmap(buf, PAGE_SIZE);
	if (error != 0)
		err(1, "munmap");

	return (i);
}

static uintmax_t
test_setuid(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uid_t uid;
	uintmax_t i;

	uid = getuid();
	if (setuid(uid) < 0)
		err(-1, "test_setuid: setuid");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		if (setuid(uid) < 0)
			err(-1, "test_setuid: setuid");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_shmfd(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;
	int shmfd;

	shmfd = shm_open(SHM_ANON, O_CREAT | O_RDWR, 0600);
	if (shmfd < 0)
		err(-1, "test_shmfd: shm_open");
	close(shmfd);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		shmfd = shm_open(SHM_ANON, O_CREAT | O_RDWR, 0600);
		if (shmfd < 0)
			err(-1, "test_shmfd: shm_open");
		close(shmfd);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_socket_stream(uintmax_t num, uintmax_t int_arg, const char *path __unused)
{
	uintmax_t i;
	int so;

	so = socket(int_arg, SOCK_STREAM, 0);
	if (so < 0)
		err(-1, "test_socket_stream: socket");
	close(so);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		so = socket(int_arg, SOCK_STREAM, 0);
		if (so == -1)
			err(-1, "test_socket_stream: socket");
		close(so);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_socket_dgram(uintmax_t num, uintmax_t int_arg, const char *path __unused)
{
	uintmax_t i;
	int so;

	so = socket(int_arg, SOCK_DGRAM, 0);
	if (so < 0)
		err(-1, "test_socket_dgram: socket");
	close(so);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		so = socket(int_arg, SOCK_DGRAM, 0);
		if (so == -1)
			err(-1, "test_socket_dgram: socket");
		close(so);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_socketpair_stream(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;
	int so[2];

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, so) == -1)
		err(-1, "test_socketpair_stream: socketpair");
	close(so[0]);
	close(so[1]);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		if (socketpair(PF_LOCAL, SOCK_STREAM, 0, so) == -1)
			err(-1, "test_socketpair_stream: socketpair");
		close(so[0]);
		close(so[1]);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_socketpair_dgram(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	uintmax_t i;
	int so[2];

	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, so) == -1)
		err(-1, "test_socketpair_dgram: socketpair");
	close(so[0]);
	close(so[1]);
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, so) == -1)
			err(-1, "test_socketpair_dgram: socketpair");
		close(so[0]);
		close(so[1]);
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_readlink(uintmax_t num, uintmax_t int_arg __unused, const char *path)
{
	char buf[PATH_MAX];
	ssize_t rv;
	uintmax_t i;

	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		rv = readlink(path, buf, sizeof(buf));
		if (rv < 0 && errno != EINVAL)
			err(-1, "readlink");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_vfork(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	pid_t pid;
	uintmax_t i;

	pid = vfork();
	if (pid < 0)
		err(-1, "test_vfork: vfork");
	if (pid == 0)
		_exit(0);
	if (waitpid(pid, NULL, 0) < 0)
		err(-1, "test_vfork: waitpid");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		pid = vfork();
		if (pid < 0)
			err(-1, "test_vfork: vfork");
		if (pid == 0)
			_exit(0);
		if (waitpid(pid, NULL, 0) < 0)
			err(-1, "test_vfork: waitpid");
	}
	benchmark_stop();
	return (i);
}

static uintmax_t
test_vfork_exec(uintmax_t num, uintmax_t int_arg __unused, const char *path __unused)
{
	pid_t pid;
	uintmax_t i;

	pid = vfork();
	if (pid < 0)
		err(-1, "test_vfork_exec: vfork");
	if (pid == 0) {
		(void)execve(USR_BIN_TRUE, execve_args, environ);
		err(-1, "test_vfork_exec: execve");
	}
	if (waitpid(pid, NULL, 0) < 0)
		err(-1, "test_vfork_exec: waitpid");
	benchmark_start();
	BENCHMARK_FOREACH(i, num) {
		pid = vfork();
		if (pid < 0)
			err(-1, "test_vfork_exec: vfork");
		if (pid == 0) {
			(void)execve(USR_BIN_TRUE, execve_args, environ);
			err(-1, "execve");
		}
		if (waitpid(pid, NULL, 0) < 0)
			err(-1, "test_vfork_exec: waitpid");
	}
	benchmark_stop();
	return (i);
}

struct test {
	const char	*t_name;
	uintmax_t	(*t_func)(uintmax_t, uintmax_t, const char *);
	int		 t_flags;
	uintmax_t	 t_int;
};

#define	FLAG_PATH	0x00000001
#define	FLAG_NAME	0x00000002

static const struct test tests[] = {
	{ "access", test_access, .t_flags = FLAG_PATH },
	{ "bad_open", test_bad_open, .t_flags = 0 },
	{ "chroot", test_chroot, .t_flags = 0 },
	{ "clock_gettime", test_clock_gettime, .t_flags = 0 },
#ifdef __CHERI_PURE_CAPABILITY__
	{ "coping_8", test_coping, .t_flags = FLAG_NAME, .t_int = 8 },
	{ "coping_80", test_coping, .t_flags = FLAG_NAME, .t_int = 80 },
	{ "coping_800", test_coping, .t_flags = FLAG_NAME, .t_int = 800 },
	{ "coping_8000", test_coping, .t_flags = FLAG_NAME, .t_int = 8000 },
	{ "coping_80000", test_coping, .t_flags = FLAG_NAME, .t_int = 80000 },
	{ "coping_800000", test_coping, .t_flags = FLAG_NAME, .t_int = 800000 },
	{ "coping_8000000", test_coping, .t_flags = FLAG_NAME, .t_int = 8000000 },
	{ "coping_slow_8", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 8 },
	{ "coping_slow_80", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 80 },
	{ "coping_slow_800", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 800 },
	{ "coping_slow_8000", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 8000 },
	{ "coping_slow_80000", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 80000 },
	{ "coping_slow_800000", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 800000 },
	{ "coping_slow_8000000", test_coping_slow, .t_flags = FLAG_NAME, .t_int = 8000000 },
#endif
	{ "create_unlink", test_create_unlink, .t_flags = FLAG_PATH },
	{ "dup", test_dup, .t_flags = 0 },
	{ "fork", test_fork, .t_flags = 0 },
	{ "fork_exec", test_fork_exec, .t_flags = 0 },
	{ "fstat_shmfd", test_fstat_shmfd, .t_flags = 0 },
	{ "getppid", test_getppid, .t_flags = 0 },
	{ "getpriority", test_getpriority, .t_flags = 0 },
	{ "getprogname", test_getprogname, .t_flags = 0 },
	{ "getresuid", test_getresuid, .t_flags = 0 },
	{ "gettimeofday", test_gettimeofday, .t_flags = 0 },
	{ "getuid", test_getuid, .t_flags = 0 },
	{ "lstat", test_lstat, .t_flags = FLAG_PATH },
	{ "memcpy_8", test_memcpy, .t_flags = 0, .t_int = 8 },
	{ "memcpy_80", test_memcpy, .t_flags = 0, .t_int = 80 },
	{ "memcpy_800", test_memcpy, .t_flags = 0, .t_int = 800 },
	{ "memcpy_8000", test_memcpy, .t_flags = 0, .t_int = 8000 },
	{ "memcpy_80000", test_memcpy, .t_flags = 0, .t_int = 80000 },
	{ "memcpy_800000", test_memcpy, .t_flags = 0, .t_int = 800000 },
	{ "memcpy_8000000", test_memcpy, .t_flags = 0, .t_int = 8000000 },
	{ "open_close", test_open_close, .t_flags = FLAG_PATH },
	{ "open_read_close_1", test_open_read_close, .t_flags = FLAG_PATH,
	    .t_int = 1 },
	{ "open_read_close_10", test_open_read_close, .t_flags = FLAG_PATH,
	    .t_int = 10 },
	{ "open_read_close_100", test_open_read_close, .t_flags = FLAG_PATH,
	    .t_int = 100 },
	{ "open_read_close_1000", test_open_read_close, .t_flags = FLAG_PATH,
	    .t_int = 1000 },
	{ "open_read_close_10000", test_open_read_close,
	    .t_flags = FLAG_PATH, .t_int = 10000 },
	{ "open_read_close_100000", test_open_read_close,
	    .t_flags = FLAG_PATH, .t_int = 100000 },
	{ "open_read_close_1000000", test_open_read_close,
	    .t_flags = FLAG_PATH, .t_int = 1000000 },
	{ "pipe", test_pipe, .t_flags = 0 },
	{ "pipeping_8", test_pipeping, .t_flags = 0, .t_int = 8 },
	{ "pipeping_80", test_pipeping, .t_flags = 0, .t_int = 80 },
	{ "pipeping_800", test_pipeping, .t_flags = 0, .t_int = 800 },
	{ "pipeping_8000", test_pipeping, .t_flags = 0, .t_int = 8000 },
	{ "pipeping_80000", test_pipeping, .t_flags = 0, .t_int = 80000 },
	{ "pipeping_800000", test_pipeping, .t_flags = 0, .t_int = 800000 },
	{ "pipeping_8000000", test_pipeping, .t_flags = 0, .t_int = 8000000 },
#ifdef WITH_PTHREAD
	{ "pipepingtd_8", test_pipepingtd, .t_flags = 0, .t_int = 8 },
	{ "pipepingtd_80", test_pipepingtd, .t_flags = 0, .t_int = 80 },
	{ "pipepingtd_800", test_pipepingtd, .t_flags = 0, .t_int = 800 },
	{ "pipepingtd_8000", test_pipepingtd, .t_flags = 0, .t_int = 8000 },
	{ "pipepingtd_80000", test_pipepingtd, .t_flags = 0, .t_int = 80000 },
	{ "pipepingtd_800000", test_pipepingtd, .t_flags = 0, .t_int = 800000 },
	{ "pipepingtd_8000000", test_pipepingtd, .t_flags = 0, .t_int = 8000000 },
#endif
	{ "read_1", test_read, .t_flags = FLAG_PATH, .t_int = 1 },
	{ "read_10", test_read, .t_flags = FLAG_PATH, .t_int = 10 },
	{ "read_100", test_read, .t_flags = FLAG_PATH, .t_int = 100 },
	{ "read_1000", test_read, .t_flags = FLAG_PATH, .t_int = 1000 },
	{ "read_10000", test_read, .t_flags = FLAG_PATH, .t_int = 10000 },
	{ "read_100000", test_read, .t_flags = FLAG_PATH, .t_int = 100000 },
	{ "read_1000000", test_read, .t_flags = FLAG_PATH, .t_int = 1000000 },
	{ "select", test_select, .t_flags = 0 },
	{ "semaping", test_semaping, .t_flags = 0 },
	{ "setuid", test_setuid, .t_flags = 0 },
	{ "shmfd", test_shmfd, .t_flags = 0 },
	{ "socket_local_stream", test_socket_stream, .t_int = PF_LOCAL },
	{ "socket_local_dgram", test_socket_dgram, .t_int = PF_LOCAL },
	{ "socketpair_stream", test_socketpair_stream, .t_flags = 0 },
	{ "socketpair_dgram", test_socketpair_dgram, .t_flags = 0 },
	{ "socket_tcp", test_socket_stream, .t_int = PF_INET },
	{ "socket_udp", test_socket_dgram, .t_int = PF_INET },
	{ "readlink", test_readlink, .t_flags = FLAG_PATH },
	{ "vfork", test_vfork, .t_flags = 0 },
	{ "vfork_exec", test_vfork_exec, .t_flags = 0 },
};
static const int tests_count = sizeof(tests) / sizeof(tests[0]);

static void
usage(void)
{
#ifdef WITH_LIBSTATCOUNTERS
	const char *name;
#endif
	int i;

	fprintf(stderr, "syscall_timing [-c counter,...] [-i iterations] [-l loops] "
	    "[-p path] [-r path] [-s seconds] [-t] test\n");
	fprintf(stderr, "Available tests:\n");
	for (i = 0; i < tests_count; i++)
		fprintf(stderr, "  %s\n", tests[i].t_name);
#ifdef WITH_LIBSTATCOUNTERS
	name = NULL;
	fprintf(stderr, "Available counters, to use with -c:\n");
	while ((name = statcounters_get_next_name(name)) != NULL)
		fprintf(stderr, "  %s\n", name);
#endif
	exit(-1);
}

int
main(int argc, char *argv[])
{
	struct timespec ts_res;
#ifdef RAW
	FILE *raw_fp;
	char *raw_path;
#endif
	const struct test *the_test;
	const char *name;
	const char *path;
	char *tmp_dir, *tmp_path;
	long long ll;
	char *endp;
	int ch, fd, error, j, rv;
	uintmax_t i, iterations, k, loops;

	alarm_timeout = 1;
	iterations = 0;
	loops = 10;
#ifdef CHERI_START_TRACE
	trace = 0;
#endif
	name = NULL;
	path = NULL;
#ifdef RAW
	raw_fp = NULL;
	raw_path = NULL;
#endif
	tmp_path = NULL;
	while ((ch = getopt(argc, argv, "c:i:l:n:p:r:s:t")) != -1) {
		switch (ch) {
		case 'c':
#ifndef WITH_LIBSTATCOUNTERS
			errx(1, "compiled without WITH_LIBSTATCOUNTERS");
#else
			if (raw_len >= RAW_LEN_MAX)
				errx(1, "must specify at most %d counters", RAW_LEN_MAX);
			raw_ids[raw_len] = statcounters_id_from_name(optarg);
			if (raw_ids[raw_len] < 0)
				errx(1, "invalid counter name, see usage for list");
			raw_len++;
#endif
			break;
		case 'i':
			ll = strtol(optarg, &endp, 10);
			if (*endp != 0 || ll < 1)
				usage();
			iterations = ll;
			break;

		case 'l':
			ll = strtol(optarg, &endp, 10);
			if (*endp != 0 || ll < 1 || ll > 100000)
				usage();
			loops = ll;
			break;

		case 'n':
			name = optarg;
			break;

		case 'p':
			path = optarg;
			break;

		case 'r':
#ifdef RAW
			raw_path = optarg;
#else
			errx(1, "compiled without RAW");
#endif
			break;

		case 's':
			ll = strtol(optarg, &endp, 10);
			if (*endp != 0 || ll < 1 || ll > 60*60)
				usage();
			alarm_timeout = ll;
			break;

		case 't':
#ifdef CHERI_START_TRACE
			trace = 1;
#else
			errx(1, "compiled without __CHERI__");
#endif
			break;

		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

#ifdef RAW
	if (raw_path != NULL && iterations <= 0)
		errx(1, "-r must be followed by -i");
#endif
#ifdef WITH_LIBSTATCOUNTERS
	if (raw_len > 1 && raw_path == NULL)
		errx(1, "-c must be followed by -r");
#endif
	if (iterations < 1 && alarm_timeout < 1)
		usage();
	if (iterations < 1)
		iterations = UINT64_MAX;
	if (loops < 1)
		loops = 1;

	if (argc < 1)
		usage();

	/*
	 * Validate test list and that, if a path is required, it is
	 * defined.
	 */
	for (j = 0; j < argc; j++) {
		the_test = NULL;
		for (i = 0; i < tests_count; i++) {
			if (strcmp(argv[j], tests[i].t_name) == 0)
				the_test = &tests[i];
		}
		if (the_test == NULL)
			usage();
		if ((the_test->t_flags & FLAG_PATH) && (path == NULL)) {
			tmp_dir = strdup("/tmp/syscall_timing.XXXXXXXX");
			if (tmp_dir == NULL)
				err(1, "strdup");
			tmp_dir = mkdtemp(tmp_dir);
			if (tmp_dir == NULL)
				err(1, "mkdtemp");
			rv = asprintf(&tmp_path, "%s/testfile", tmp_dir);
			if (rv <= 0)
				err(1, "asprintf");
		}
		if ((the_test->t_flags & FLAG_NAME) && (name == NULL))
			errx(1, "test %s requires -n", the_test->t_name);
	}

#ifdef RAW
	if (raw_path != 0) {
		raw_fp = fopen(raw_path, "w");
		if (raw_fp == NULL)
			err(1, "%s", raw_path);

		raw_numbers = calloc(iterations + 1, sizeof(raw_numbers[0]) * raw_len);
		if (raw_numbers == NULL)
			err(1, "calloc");
	}
#endif

	error = clock_getres(CLOCK_REALTIME, &ts_res);
	assert(error == 0);
	printf("Clock resolution: %ju.%09ju\n", (uintmax_t)ts_res.tv_sec,
	    (uintmax_t)ts_res.tv_nsec);
	printf("test\tloop\ttime\titerations\tperiteration\n");

	for (j = 0; j < argc; j++) {
		uintmax_t calls, nsecsperit;

		the_test = NULL;
		for (i = 0; i < tests_count; i++) {
			if (strcmp(argv[j], tests[i].t_name) == 0)
				the_test = &tests[i];
		}

		if (tmp_path != NULL) {
			fd = open(tmp_path, O_WRONLY | O_CREAT, 0700);
			if (fd < 0)
				err(1, "cannot open %s", tmp_path);
			error = ftruncate(fd, 1000000);
			if (error != 0)
				err(1, "ftruncate");
			error = close(fd);
			if (error != 0)
				err(1, "close");
			path = tmp_path;
		}

		if (the_test->t_flags & FLAG_NAME)
			path = name;

		/*
		 * Run one warmup, then do the real thing (loops) times.
		 */
		the_test->t_func(iterations, the_test->t_int, path);
		calls = 0;
		for (k = 0; k < loops; k++) {
			calls = the_test->t_func(iterations, the_test->t_int,
			    path);
			timespecsub(&ts_end, &ts_start, &ts_end);
			printf("%s\t%ju\t", the_test->t_name, k);
			printf("%ju.%09ju\t%ju\t", (uintmax_t)ts_end.tv_sec,
			    (uintmax_t)ts_end.tv_nsec, calls);

		/*
		 * Note.  This assumes that each iteration takes less than
		 * a second, and that our total nanoseconds doesn't exceed
		 * the room in our arithmetic unit.  Fine for system calls,
		 * but not for long things.
		 */
			nsecsperit = ts_end.tv_sec * 1000000000;
			nsecsperit += ts_end.tv_nsec;
			nsecsperit /= calls;
			printf("0.%09ju\n", (uintmax_t)nsecsperit);
		}
	}

#ifdef RAW
	if (raw_fp != NULL) {
		for (i = 1; i < iterations + 1; i++) {
			for (j = 0; j < raw_len; j++) {
				fprintf(raw_fp, "%d%s", RAW_NUMBER(i, j),
				    j == raw_len - 1 ? "\n" : "\t");
			}
		}
		error = fclose(raw_fp);
		if (error != 0)
			warn("%s", raw_path);
	}
#endif

	if (tmp_path != NULL) {
		error = unlink(tmp_path);
		if (error != 0 && errno != ENOENT)
			warn("cannot unlink %s", tmp_path);
		error = rmdir(tmp_dir);
		if (error != 0)
			warn("cannot rmdir %s", tmp_dir);
	}

	return (0);
}
