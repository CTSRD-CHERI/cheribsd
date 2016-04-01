/*-
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2015 SRI International
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
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1988, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)kdump.c	8.1 (Berkeley) 6/6/93";
#endif
#endif /* not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#define _KERNEL
extern int errno;
#include <sys/errno.h>
#undef _KERNEL
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/errno.h>
#define _KERNEL
#include <sys/time.h>
#undef _KERNEL
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysent.h>
#include <sys/umtx.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/wait.h>
#ifdef HAVE_LIBCAPSICUM
#include <sys/nv.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>
#include <err.h>
#include <grp.h>
#include <inttypes.h>
#ifdef HAVE_LIBCAPSICUM
#include <libcapsicum.h>
#include <libcapsicum_grp.h>
#include <libcapsicum_pwd.h>
#include <libcapsicum_service.h>
#endif
#include <locale.h>
#include <netdb.h>
#include <nl_types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysdecode.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>
#include "ktrace.h"
#include "kdump_subr.h"

u_int abidump(struct ktr_header *);
int fetchprocinfo(struct ktr_header *, u_int *);
int fread_tail(void *, int, int);
void dumpheader(struct ktr_header *);
void ktrsyscall(struct ktr_syscall *, u_int);
void ktrsysret(struct ktr_sysret *, u_int);
void ktrnamei(char *, int);
void hexdump(char *, int, int);
void visdump(char *, int, int);
void ktrgenio(struct ktr_genio *, int);
void ktrpsig(struct ktr_psig *);
void ktrcsw(struct ktr_csw *);
void ktrcsw_old(struct ktr_csw_old *);
void ktruser_malloc(void *);
void ktruser_rtld(int, void *);
void ktruser(int, void *);
void ktrcaprights(cap_rights_t *);
void ktrsockaddr(struct sockaddr *);
void ktrstat(struct stat *);
void ktrstruct(char *, size_t);
void ktrcapfail(struct ktr_cap_fail *);
void ktrfault(struct ktr_fault *);
void ktrfaultend(struct ktr_faultend *);
void ktrccall(struct ktr_ccall *);
void ktrcreturn(struct ktr_creturn *);
void ktrcexception(struct ktr_cexception *);
void limitfd(int fd);
void usage(void);

#define	TIMESTAMP_NONE		0x0
#define	TIMESTAMP_ABSOLUTE	0x1
#define	TIMESTAMP_ELAPSED	0x2
#define	TIMESTAMP_RELATIVE	0x4

extern const char *signames[];

static int timestamp, decimal, fancy = 1, suppressdata, tail, threads, maxdata,
    resolv = 0, abiflag = 0, syscallno = 0;
static const char *tracefile = DEF_TRACEFILE;
static struct ktr_header ktr_header;

#define TIME_FORMAT	"%b %e %T %Y"
#define eqs(s1, s2)	(strcmp((s1), (s2)) == 0)

#define print_number(i,n,c) do {					\
	if (decimal)							\
		printf("%c%jd", c, (intmax_t)*i);			\
	else								\
		printf("%c%#jx", c, (uintmax_t)(u_register_t)*i);	\
	i++;								\
	n--;								\
	c = ',';							\
} while (0)

#if defined(__amd64__) || defined(__i386__)

void linux_ktrsysret(struct ktr_sysret *, u_int);

/*
 * from linux.h
 * Linux syscalls return negative errno's, we do positive and map them
 */
static int bsd_to_linux_errno[ELAST + 1] = {
	-0,  -1,  -2,  -3,  -4,  -5,  -6,  -7,  -8,  -9,
	-10, -35, -12, -13, -14, -15, -16, -17, -18, -19,
	-20, -21, -22, -23, -24, -25, -26, -27, -28, -29,
	-30, -31, -32, -33, -34, -11,-115,-114, -88, -89,
	-90, -91, -92, -93, -94, -95, -96, -97, -98, -99,
	-100,-101,-102,-103,-104,-105,-106,-107,-108,-109,
	-110,-111, -40, -36,-112,-113, -39, -11, -87,-122,
	-116, -66,  -6,  -6,  -6,  -6,  -6, -37, -38,  -9,
	-6,  -6, -43, -42, -75,-125, -84, -95, -16, -74,
	-72, -67, -71
};
#endif

struct proc_info
{
	TAILQ_ENTRY(proc_info)	info;
	u_int			sv_flags;
	pid_t			pid;
};

static TAILQ_HEAD(trace_procs, proc_info) trace_procs;

#ifdef HAVE_LIBCAPSICUM
static cap_channel_t *cappwd, *capgrp;
#endif

static void
strerror_init(void)
{

	/*
	 * Cache NLS data before entering capability mode.
	 * XXXPJD: There should be strerror_init() and strsignal_init() in libc.
	 */
	(void)catopen("libc", NL_CAT_LOCALE);
}

static void
localtime_init(void)
{
	time_t ltime;

	/*
	 * Allow localtime(3) to cache /etc/localtime content before entering
	 * capability mode.
	 * XXXPJD: There should be localtime_init() in libc.
	 */
	(void)time(&ltime);
	(void)localtime(&ltime);
}

#ifdef HAVE_LIBCAPSICUM
static int
cappwdgrp_setup(cap_channel_t **cappwdp, cap_channel_t **capgrpp)
{
	cap_channel_t *capcas, *cappwdloc, *capgrploc;
	const char *cmds[1], *fields[1];

	capcas = cap_init();
	if (capcas == NULL) {
		warn("unable to contact casperd");
		return (-1);
	}
	cappwdloc = cap_service_open(capcas, "system.pwd");
	capgrploc = cap_service_open(capcas, "system.grp");
	/* Casper capability no longer needed. */
	cap_close(capcas);
	if (cappwdloc == NULL || capgrploc == NULL) {
		if (cappwdloc == NULL)
			warn("unable to open system.pwd service");
		if (capgrploc == NULL)
			warn("unable to open system.grp service");
		exit(1);
	}
	/* Limit system.pwd to only getpwuid() function and pw_name field. */
	cmds[0] = "getpwuid";
	if (cap_pwd_limit_cmds(cappwdloc, cmds, 1) < 0)
		err(1, "unable to limit system.pwd service");
	fields[0] = "pw_name";
	if (cap_pwd_limit_fields(cappwdloc, fields, 1) < 0)
		err(1, "unable to limit system.pwd service");
	/* Limit system.grp to only getgrgid() function and gr_name field. */
	cmds[0] = "getgrgid";
	if (cap_grp_limit_cmds(capgrploc, cmds, 1) < 0)
		err(1, "unable to limit system.grp service");
	fields[0] = "gr_name";
	if (cap_grp_limit_fields(capgrploc, fields, 1) < 0)
		err(1, "unable to limit system.grp service");

	*cappwdp = cappwdloc;
	*capgrpp = capgrploc;
	return (0);
}
#endif	/* HAVE_LIBCAPSICUM */

int
main(int argc, char *argv[])
{
	int ch, ktrlen, size;
	void *m;
	int trpoints = ALL_POINTS;
	int drop_logged;
	pid_t pid = 0;
	u_int sv_flags;

	setlocale(LC_CTYPE, "");

	timestamp = TIMESTAMP_NONE;

	while ((ch = getopt(argc,argv,"f:dElm:np:AHRrSsTt:")) != -1)
		switch (ch) {
		case 'A':
			abiflag = 1;
			break;
		case 'f':
			tracefile = optarg;
			break;
		case 'd':
			decimal = 1;
			break;
		case 'l':
			tail = 1;
			break;
		case 'm':
			maxdata = atoi(optarg);
			break;
		case 'n':
			fancy = 0;
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 'r':
			resolv = 1;
			break;
		case 'S':
			syscallno = 1;
			break;
		case 's':
			suppressdata = 1;
			break;
		case 'E':
			timestamp |= TIMESTAMP_ELAPSED;
			break;
		case 'H':
			threads = 1;
			break;
		case 'R':
			timestamp |= TIMESTAMP_RELATIVE;
			break;
		case 'T':
			timestamp |= TIMESTAMP_ABSOLUTE;
			break;
		case 't':
			trpoints = getpoints(optarg);
			if (trpoints < 0)
				errx(1, "unknown trace point in %s", optarg);
			break;
		default:
			usage();
		}

	if (argc > optind)
		usage();

	m = malloc(size = 1025);
	if (m == NULL)
		errx(1, "%s", strerror(ENOMEM));
	if (!freopen(tracefile, "r", stdin))
		err(1, "%s", tracefile);

	strerror_init();
	localtime_init();
#ifdef HAVE_LIBCAPSICUM
	if (resolv != 0) {
		if (cappwdgrp_setup(&cappwd, &capgrp) < 0) {
			cappwd = NULL;
			capgrp = NULL;
		}
	}
	if (resolv == 0 || (cappwd != NULL && capgrp != NULL)) {
		if (cap_enter() < 0 && errno != ENOSYS)
			err(1, "unable to enter capability mode");
	}
#else
	if (resolv == 0) {
		if (cap_enter() < 0 && errno != ENOSYS)
			err(1, "unable to enter capability mode");
	}
#endif
	limitfd(STDIN_FILENO);
	limitfd(STDOUT_FILENO);
	limitfd(STDERR_FILENO);

	TAILQ_INIT(&trace_procs);
	drop_logged = 0;
	while (fread_tail(&ktr_header, sizeof(struct ktr_header), 1)) {
		if (ktr_header.ktr_type & KTR_DROP) {
			ktr_header.ktr_type &= ~KTR_DROP;
			if (!drop_logged && threads) {
				printf(
				    "%6jd %6jd %-8.*s Events dropped.\n",
				    (intmax_t)ktr_header.ktr_pid,
				    ktr_header.ktr_tid > 0 ?
				    (intmax_t)ktr_header.ktr_tid : 0,
				    MAXCOMLEN, ktr_header.ktr_comm);
				drop_logged = 1;
			} else if (!drop_logged) {
				printf("%6jd %-8.*s Events dropped.\n",
				    (intmax_t)ktr_header.ktr_pid, MAXCOMLEN,
				    ktr_header.ktr_comm);
				drop_logged = 1;
			}
		}
		if (trpoints & (1<<ktr_header.ktr_type))
			if (pid == 0 || ktr_header.ktr_pid == pid ||
			    ktr_header.ktr_tid == pid)
				dumpheader(&ktr_header);
		if ((ktrlen = ktr_header.ktr_len) < 0)
			errx(1, "bogus length 0x%x", ktrlen);
		if (ktrlen > size) {
			m = realloc(m, ktrlen+1);
			if (m == NULL)
				errx(1, "%s", strerror(ENOMEM));
			size = ktrlen;
		}
		if (ktrlen && fread_tail(m, ktrlen, 1) == 0)
			errx(1, "data too short");
		if (fetchprocinfo(&ktr_header, (u_int *)m) != 0)
			continue;
		sv_flags = abidump(&ktr_header);
		if (pid && ktr_header.ktr_pid != pid &&
		    ktr_header.ktr_tid != pid)
			continue;
		if ((trpoints & (1<<ktr_header.ktr_type)) == 0)
			continue;
		drop_logged = 0;
		switch (ktr_header.ktr_type) {
		case KTR_SYSCALL:
			ktrsyscall((struct ktr_syscall *)m, sv_flags);
			break;
		case KTR_SYSRET:
#if defined(__amd64__) || defined(__i386__)
			if ((sv_flags & SV_ABI_MASK) == SV_ABI_LINUX)
				linux_ktrsysret((struct ktr_sysret *)m, 
				    sv_flags);
			else
#endif
				ktrsysret((struct ktr_sysret *)m, sv_flags);
			break;
		case KTR_NAMEI:
		case KTR_SYSCTL:
		case KTR_SYSERRCAUSE:
			ktrnamei(m, ktrlen);
			break;
		case KTR_GENIO:
			ktrgenio((struct ktr_genio *)m, ktrlen);
			break;
		case KTR_PSIG:
			ktrpsig((struct ktr_psig *)m);
			break;
		case KTR_CSW:
			if (ktrlen == sizeof(struct ktr_csw_old))
				ktrcsw_old((struct ktr_csw_old *)m);
			else
				ktrcsw((struct ktr_csw *)m);
			break;
		case KTR_USER:
			ktruser(ktrlen, m);
			break;
		case KTR_STRUCT:
			ktrstruct(m, ktrlen);
			break;
		case KTR_CAPFAIL:
			ktrcapfail((struct ktr_cap_fail *)m);
			break;
		case KTR_FAULT:
			ktrfault((struct ktr_fault *)m);
			break;
		case KTR_FAULTEND:
			ktrfaultend((struct ktr_faultend *)m);
			break;
		case KTR_CCALL:
			ktrccall((struct ktr_ccall *)m);
			break;
		case KTR_CRETURN:
			ktrcreturn((struct ktr_creturn *)m);
			break;
		case KTR_CEXCEPTION:
			ktrcexception((struct ktr_cexception *)m);
			break;
		default:
			printf("\n");
			break;
		}
		if (tail)
			fflush(stdout);
	}
	return 0;
}

void
limitfd(int fd)
{
	cap_rights_t rights;
	unsigned long cmd;

	cap_rights_init(&rights, CAP_FSTAT);
	cmd = 0;

	switch (fd) {
	case STDIN_FILENO:
		cap_rights_set(&rights, CAP_READ);
		break;
	case STDOUT_FILENO:
		cap_rights_set(&rights, CAP_IOCTL, CAP_WRITE);
		cmd = TIOCGETA;	/* required by isatty(3) in printf(3) */
		break;
	case STDERR_FILENO:
		cap_rights_set(&rights, CAP_WRITE);
		if (!suppressdata) {
			cap_rights_set(&rights, CAP_IOCTL);
			cmd = TIOCGWINSZ;
		}
		break;
	default:
		abort();
	}

	if (cap_rights_limit(fd, &rights) < 0 && errno != ENOSYS)
		err(1, "unable to limit rights for descriptor %d", fd);
	if (cmd != 0 && cap_ioctls_limit(fd, &cmd, 1) < 0 && errno != ENOSYS)
		err(1, "unable to limit ioctls for descriptor %d", fd);
}

int
fread_tail(void *buf, int size, int num)
{
	int i;

	while ((i = fread(buf, size, num, stdin)) == 0 && tail) {
		sleep(1);
		clearerr(stdin);
	}
	return (i);
}

int
fetchprocinfo(struct ktr_header *kth, u_int *flags)
{
	struct proc_info *pi;

	switch (kth->ktr_type) {
	case KTR_PROCCTOR:
		TAILQ_FOREACH(pi, &trace_procs, info) {
			if (pi->pid == kth->ktr_pid) {
				TAILQ_REMOVE(&trace_procs, pi, info);
				break;
			}
		}
		pi = malloc(sizeof(struct proc_info));
		if (pi == NULL)
			errx(1, "%s", strerror(ENOMEM));
		pi->sv_flags = *flags;
		pi->pid = kth->ktr_pid;
		TAILQ_INSERT_TAIL(&trace_procs, pi, info);
		return (1);

	case KTR_PROCDTOR:
		TAILQ_FOREACH(pi, &trace_procs, info) {
			if (pi->pid == kth->ktr_pid) {
				TAILQ_REMOVE(&trace_procs, pi, info);
				free(pi);
				break;
			}
		}
		return (1);
	}

	return (0);
}

u_int
abidump(struct ktr_header *kth)
{
	struct proc_info *pi;
	const char *abi;
	const char *arch;
	u_int flags = 0;

	TAILQ_FOREACH(pi, &trace_procs, info) {
		if (pi->pid == kth->ktr_pid) {
			flags = pi->sv_flags;
			break;
		}
	}

	if (abiflag == 0)
		return (flags);

	switch (flags & SV_ABI_MASK) {
	case SV_ABI_LINUX:
		abi = "L";
		break;
	case SV_ABI_FREEBSD:
		abi = "F";
		break;
	default:
		abi = "U";
		break;
	}

	if (flags != 0) {
		if (flags & SV_LP64)
			arch = "64";
		else
			arch = "32";
	} else
		arch = "00";

	printf("%s%s  ", abi, arch);

	return (flags);
}

void
dumpheader(struct ktr_header *kth)
{
	static char unknown[64];
	static struct timeval prevtime, prevtime_e, temp;
	const char *type;
	const char *sign;

	switch (kth->ktr_type) {
	case KTR_SYSCALL:
		type = "CALL";
		break;
	case KTR_SYSRET:
		type = "RET ";
		break;
	case KTR_NAMEI:
		type = "NAMI";
		break;
	case KTR_GENIO:
		type = "GIO ";
		break;
	case KTR_PSIG:
		type = "PSIG";
		break;
	case KTR_CSW:
		type = "CSW ";
		break;
	case KTR_USER:
		type = "USER";
		break;
	case KTR_STRUCT:
		type = "STRU";
		break;
	case KTR_SYSCTL:
		type = "SCTL";
		break;
	case KTR_PROCCTOR:
		/* FALLTHROUGH */
	case KTR_PROCDTOR:
		return;
	case KTR_CAPFAIL:
		type = "CAP ";
		break;
	case KTR_FAULT:
		type = "PFLT";
		break;
	case KTR_FAULTEND:
		type = "PRET";
		break;
	case KTR_CCALL:
		type = "CCAL";
		break;
	case KTR_CRETURN:
		type = "CRET";
		break;
	case KTR_CEXCEPTION:
		type = "CEXC";
		break;
	default:
		sprintf(unknown, "UNKNOWN(%d)", kth->ktr_type);
		type = unknown;
	}

	/*
	 * The ktr_tid field was previously the ktr_buffer field, which held
	 * the kernel pointer value for the buffer associated with data
	 * following the record header.  It now holds a threadid, but only
	 * for trace files after the change.  Older trace files still contain
	 * kernel pointers.  Detect this and suppress the results by printing
	 * negative tid's as 0.
	 */
	if (threads)
		printf("%6jd %6jd %-8.*s ", (intmax_t)kth->ktr_pid,
		    kth->ktr_tid > 0 ? (intmax_t)kth->ktr_tid : 0,
		    MAXCOMLEN, kth->ktr_comm);
	else
		printf("%6jd %-8.*s ", (intmax_t)kth->ktr_pid, MAXCOMLEN,
		    kth->ktr_comm);
        if (timestamp) {
		if (timestamp & TIMESTAMP_ABSOLUTE) {
			printf("%jd.%06ld ", (intmax_t)kth->ktr_time.tv_sec,
			    kth->ktr_time.tv_usec);
		}
		if (timestamp & TIMESTAMP_ELAPSED) {
			if (prevtime_e.tv_sec == 0)
				prevtime_e = kth->ktr_time;
			timevalsub(&kth->ktr_time, &prevtime_e);
			printf("%jd.%06ld ", (intmax_t)kth->ktr_time.tv_sec,
			    kth->ktr_time.tv_usec);
			timevaladd(&kth->ktr_time, &prevtime_e);
		}
		if (timestamp & TIMESTAMP_RELATIVE) {
			if (prevtime.tv_sec == 0)
				prevtime = kth->ktr_time;
			temp = kth->ktr_time;
			timevalsub(&kth->ktr_time, &prevtime);
			if ((intmax_t)kth->ktr_time.tv_sec < 0) {
                        	kth->ktr_time = prevtime;
				prevtime = temp;
				timevalsub(&kth->ktr_time, &prevtime);
				sign = "-";
			} else {
				prevtime = temp;
				sign = "";
			}
			printf("%s%jd.%06ld ", sign, (intmax_t)kth->ktr_time.tv_sec,
			    kth->ktr_time.tv_usec);
		}
	}
	printf("%s  ", type);
}

#include <sys/syscall.h>

static void
ioctlname(unsigned long val)
{
	const char *str;

	str = sysdecode_ioctlname(val);
	if (str != NULL)
		printf("%s", str);
	else if (decimal)
		printf("%lu", val);
	else
		printf("%#lx", val);
}

static enum sysdecode_abi
syscallabi(u_int sv_flags)
{

	if (sv_flags == 0)
		return (FREEBSD);
	switch (sv_flags & SV_ABI_MASK) {
	case SV_ABI_FREEBSD:
		return (FREEBSD);
#if defined(__amd64__) || defined(__i386__)
	case SV_ABI_LINUX:
#ifdef __amd64__
		if (sv_flags & SV_ILP32)
			return (LINUX32);
#endif
		return (LINUX);
#endif
	default:
		return (UNKNOWN_ABI);
	}
}

static void
syscallname(u_int code, u_int sv_flags)
{
	const char *name;

	name = sysdecode_syscallname(syscallabi(sv_flags), code);
	if (name == NULL)
		printf("[%d]", code);
	else {
		printf("%s", name);
		if (syscallno)
			printf("[%d]", code);
	}
}

void
ktrsyscall(struct ktr_syscall *ktr, u_int sv_flags)
{
	int narg = ktr->ktr_narg;
	register_t *ip;
	intmax_t arg;

	syscallname(ktr->ktr_code, sv_flags);
	ip = &ktr->ktr_args[0];
	if (narg) {
		char c = '(';
		if (fancy &&
		    (sv_flags == 0 ||
		    (sv_flags & SV_ABI_MASK) == SV_ABI_FREEBSD)) {
			switch (ktr->ktr_code) {
			case SYS_bindat:
			case SYS_connectat:
			case SYS_faccessat:
			case SYS_fchmodat:
			case SYS_fchownat:
			case SYS_fstatat:
			case SYS_futimesat:
			case SYS_linkat:
			case SYS_mkdirat:
			case SYS_mkfifoat:
			case SYS_mknodat:
			case SYS_openat:
			case SYS_readlinkat:
			case SYS_renameat:
			case SYS_unlinkat:
			case SYS_utimensat:
				putchar('(');
				atfdname(*ip, decimal);
				c = ',';
				ip++;
				narg--;
				break;
			}
			switch (ktr->ktr_code) {
			case SYS_ioctl: {
				print_number(ip, narg, c);
				putchar(c);
				ioctlname(*ip);
				c = ',';
				ip++;
				narg--;
				break;
			}
			case SYS_ptrace:
				putchar('(');
				ptraceopname(*ip);
				c = ',';
				ip++;
				narg--;
				break;
			case SYS_access:
			case SYS_eaccess:
			case SYS_faccessat:
				print_number(ip, narg, c);
				putchar(',');
				accessmodename(*ip);
				ip++;
				narg--;
				break;
			case SYS_open:
			case SYS_openat:
				print_number(ip, narg, c);
				putchar(',');
				flagsandmodename(ip[0], ip[1], decimal);
				ip += 2;
				narg -= 2;
				break;
			case SYS_wait4:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				/*
				 * A flags value of zero is valid for
				 * wait4() but not for wait6(), so
				 * handle zero special here.
				 */
				if (*ip == 0) {
					print_number(ip, narg, c);
				} else {
					putchar(',');
					wait6optname(*ip);
					ip++;
					narg--;
				}
				break;
			case SYS_wait6:
				putchar('(');
				idtypename(*ip, decimal);
				c = ',';
				ip++;
				narg--;
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				wait6optname(*ip);
				ip++;
				narg--;
				break;
			case SYS_chmod:
			case SYS_fchmod:
			case SYS_lchmod:
				print_number(ip, narg, c);
				putchar(',');
				modename(*ip);
				ip++;
				narg--;
				break;
			case SYS_mknod:
			case SYS_mknodat:
				print_number(ip, narg, c);
				putchar(',');
				modename(*ip);
				ip++;
				narg--;
				break;
			case SYS_getfsstat:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				getfsstatflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_mount:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				mountflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_unmount:
				print_number(ip, narg, c);
				putchar(',');
				mountflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_recvmsg:
			case SYS_sendmsg:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				sendrecvflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_recvfrom:
			case SYS_sendto:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				sendrecvflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_chflags:
			case SYS_fchflags:
			case SYS_lchflags:
				print_number(ip, narg, c);
				putchar(',');
				modename(*ip);
				ip++;
				narg--;
				break;
			case SYS_kill:
				print_number(ip, narg, c);
				putchar(',');
				signame(*ip);
				ip++;
				narg--;
				break;
			case SYS_reboot:
				putchar('(');
				rebootoptname(*ip);
				ip++;
				narg--;
				break;
			case SYS_umask:
				putchar('(');
				modename(*ip);
				ip++;
				narg--;
				break;
			case SYS_msync:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				msyncflagsname(*ip);
				ip++;
				narg--;
				break;
#ifdef SYS_freebsd6_mmap
			case SYS_freebsd6_mmap:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				mmapprotname(*ip);
				putchar(',');
				ip++;
				narg--;
				mmapflagsname(*ip);
				ip++;
				narg--;
				break;
#endif
			case SYS_mmap:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				mmapprotname(*ip);
				putchar(',');
				ip++;
				narg--;
				mmapflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_mprotect:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				mmapprotname(*ip);
				ip++;
				narg--;
				break;
			case SYS_madvise:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				madvisebehavname(*ip);
				ip++;
				narg--;
				break;
			case SYS_setpriority:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				prioname(*ip);
				ip++;
				narg--;
				break;
			case SYS_fcntl:
				print_number(ip, narg, c);
				putchar(',');
				fcntlcmdname(ip[0], ip[1], decimal);
				ip += 2;
				narg -= 2;
				break;
			case SYS_socket: {
				int sockdomain;
				putchar('(');
				sockdomain = *ip;
				sockdomainname(sockdomain);
				ip++;
				narg--;
				putchar(',');
				socktypenamewithflags(*ip);
				ip++;
				narg--;
				if (sockdomain == PF_INET ||
				    sockdomain == PF_INET6) {
					putchar(',');
					sockipprotoname(*ip);
					ip++;
					narg--;
				}
				c = ',';
				break;
			}
			case SYS_setsockopt:
			case SYS_getsockopt:
				print_number(ip, narg, c);
				putchar(',');
				sockoptlevelname(*ip, decimal);
				if (*ip == SOL_SOCKET) {
					ip++;
					narg--;
					putchar(',');
					sockoptname(*ip);
				}
				ip++;
				narg--;
				break;
#ifdef SYS_freebsd6_lseek
			case SYS_freebsd6_lseek:
				print_number(ip, narg, c);
				/* Hidden 'pad' argument, not in lseek(2) */
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				whencename(*ip);
				ip++;
				narg--;
				break;
#endif
			case SYS_lseek:
				print_number(ip, narg, c);
				/* Hidden 'pad' argument, not in lseek(2) */
				print_number(ip, narg, c);
				putchar(',');
				whencename(*ip);
				ip++;
				narg--;
				break;
			case SYS_flock:
				print_number(ip, narg, c);
				putchar(',');
				flockname(*ip);
				ip++;
				narg--;
				break;
			case SYS_mkfifo:
			case SYS_mkfifoat:
			case SYS_mkdir:
			case SYS_mkdirat:
				print_number(ip, narg, c);
				putchar(',');
				modename(*ip);
				ip++;
				narg--;
				break;
			case SYS_shutdown:
				print_number(ip, narg, c);
				putchar(',');
				shutdownhowname(*ip);
				ip++;
				narg--;
				break;
			case SYS_socketpair:
				putchar('(');
				sockdomainname(*ip);
				ip++;
				narg--;
				putchar(',');
				socktypenamewithflags(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_getrlimit:
			case SYS_setrlimit:
				putchar('(');
				rlimitname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_quotactl:
				print_number(ip, narg, c);
				putchar(',');
				quotactlname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_nfssvc:
				putchar('(');
				nfssvcname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_rtprio:
				putchar('(');
				rtprioname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS___semctl:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				semctlname(*ip);
				ip++;
				narg--;
				break;
			case SYS_semget:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				semgetname(*ip);
				ip++;
				narg--;
				break;
			case SYS_msgctl:
				print_number(ip, narg, c);
				putchar(',');
				shmctlname(*ip);
				ip++;
				narg--;
				break;
			case SYS_shmat:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				shmatname(*ip);
				ip++;
				narg--;
				break;
			case SYS_shmctl:
				print_number(ip, narg, c);
				putchar(',');
				shmctlname(*ip);
				ip++;
				narg--;
				break;
			case SYS_shm_open:
				print_number(ip, narg, c);
				putchar(',');
				flagsname(ip[0]);
				printf(",0%o", (unsigned int)ip[1]);
				ip += 3;
				narg -= 3;
				break;
			case SYS_minherit:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				minheritname(*ip);
				ip++;
				narg--;
				break;
			case SYS_rfork:
				putchar('(');
				rforkname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_lio_listio:
				putchar('(');
				lio_listioname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_mlockall:
				putchar('(');
				mlockallname(*ip);
				ip++;
				narg--;
				break;
			case SYS_sched_setscheduler:
				print_number(ip, narg, c);
				putchar(',');
				schedpolicyname(*ip);
				ip++;
				narg--;
				break;
			case SYS_sched_get_priority_max:
			case SYS_sched_get_priority_min:
				putchar('(');
				schedpolicyname(*ip);
				ip++;
				narg--;
				break;
			case SYS_sendfile:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				sendfileflagsname(*(int *)ip);
				ip++;
				narg--;
				break;
			case SYS_kldsym:
				print_number(ip, narg, c);
				putchar(',');
				kldsymcmdname(*ip);
				ip++;
				narg--;
				break;
			case SYS_sigprocmask:
				putchar('(');
				sigprocmaskhowname(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS___acl_get_file:
			case SYS___acl_set_file:
			case SYS___acl_get_fd:
			case SYS___acl_set_fd:
			case SYS___acl_delete_file:
			case SYS___acl_delete_fd:
			case SYS___acl_aclcheck_file:
			case SYS___acl_aclcheck_fd:
			case SYS___acl_get_link:
			case SYS___acl_set_link:
			case SYS___acl_delete_link:
			case SYS___acl_aclcheck_link:
				print_number(ip, narg, c);
				putchar(',');
				acltypename(*ip);
				ip++;
				narg--;
				break;
			case SYS_sigaction:
				putchar('(');
				signame(*ip);
				ip++;
				narg--;
				c = ',';
				break;
			case SYS_extattrctl:
				print_number(ip, narg, c);
				putchar(',');
				extattrctlname(*ip);
				ip++;
				narg--;
				break;
			case SYS_nmount:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				mountflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_thr_create:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				putchar(',');
				thrcreateflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_thr_kill:
				print_number(ip, narg, c);
				putchar(',');
				signame(*ip);
				ip++;
				narg--;
				break;
			case SYS_kldunloadf:
				print_number(ip, narg, c);
				putchar(',');
				kldunloadfflagsname(*ip);
				ip++;
				narg--;
				break;
			case SYS_linkat:
			case SYS_renameat:
			case SYS_symlinkat:
				print_number(ip, narg, c);
				putchar(',');
				atfdname(*ip, decimal);
				ip++;
				narg--;
				break;
			case SYS_cap_fcntls_limit:
				print_number(ip, narg, c);
				putchar(',');
				arg = *ip;
				ip++;
				narg--;
				capfcntlname(arg);
				break;
			case SYS_posix_fadvise:
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				print_number(ip, narg, c);
				(void)putchar(',');
				fadvisebehavname((int)*ip);
				ip++;
				narg--;
				break;
			case SYS_procctl:
				putchar('(');
				idtypename(*ip, decimal);
				c = ',';
				ip++;
				narg--;
				print_number(ip, narg, c);
				putchar(',');
				procctlcmdname(*ip);
				ip++;
				narg--;
				break;
			case SYS__umtx_op:
				print_number(ip, narg, c);
				putchar(',');
				umtxopname(*ip);
				switch (*ip) {
				case UMTX_OP_CV_WAIT:
					ip++;
					narg--;
					putchar(',');
					umtxcvwaitflags(*ip);
					break;
				case UMTX_OP_RW_RDLOCK:
					ip++;
					narg--;
					putchar(',');
					umtxrwlockflags(*ip);
					break;
				}
				ip++;
				narg--;
			}
		}
		while (narg > 0) {
			print_number(ip, narg, c);
		}
		putchar(')');
	}
	putchar('\n');
}

void
ktrsysret(struct ktr_sysret *ktr, u_int sv_flags)
{
	register_t ret = ktr->ktr_retval;
	int error = ktr->ktr_error;

	syscallname(ktr->ktr_code, sv_flags);
	printf(" ");

	if (error == 0) {
		if (fancy) {
			printf("%ld", (long)ret);
			if (ret < 0 || ret > 9)
				printf("/%#lx", (unsigned long)ret);
		} else {
			if (decimal)
				printf("%ld", (long)ret);
			else
				printf("%#lx", (unsigned long)ret);
		}
	} else if (error == ERESTART)
		printf("RESTART");
	else if (error == EJUSTRETURN)
		printf("JUSTRETURN");
	else {
		printf("-1 errno %d", ktr->ktr_error);
		if (fancy)
			printf(" %s", strerror(ktr->ktr_error));
	}
	putchar('\n');
}

void
ktrnamei(char *cp, int len)
{
	printf("\"%.*s\"\n", len, cp);
}

void
hexdump(char *p, int len, int screenwidth)
{
	int n, i;
	int width;

	width = 0;
	do {
		width += 2;
		i = 13;			/* base offset */
		i += (width / 2) + 1;	/* spaces every second byte */
		i += (width * 2);	/* width of bytes */
		i += 3;			/* "  |" */
		i += width;		/* each byte */
		i += 1;			/* "|" */
	} while (i < screenwidth);
	width -= 2;

	for (n = 0; n < len; n += width) {
		for (i = n; i < n + width; i++) {
			if ((i % width) == 0) {	/* beginning of line */
				printf("       0x%04x", i);
			}
			if ((i % 2) == 0) {
				printf(" ");
			}
			if (i < len)
				printf("%02x", p[i] & 0xff);
			else
				printf("  ");
		}
		printf("  |");
		for (i = n; i < n + width; i++) {
			if (i >= len)
				break;
			if (p[i] >= ' ' && p[i] <= '~')
				printf("%c", p[i]);
			else
				printf(".");
		}
		printf("|\n");
	}
	if ((i % width) != 0)
		printf("\n");
}

void
visdump(char *dp, int datalen, int screenwidth)
{
	int col = 0;
	char *cp;
	int width;
	char visbuf[5];

	printf("       \"");
	col = 8;
	for (;datalen > 0; datalen--, dp++) {
		 vis(visbuf, *dp, VIS_CSTYLE, *(dp+1));
		cp = visbuf;
		/*
		 * Keep track of printables and
		 * space chars (like fold(1)).
		 */
		if (col == 0) {
			putchar('\t');
			col = 8;
		}
		switch(*cp) {
		case '\n':
			col = 0;
			putchar('\n');
			continue;
		case '\t':
			width = 8 - (col&07);
			break;
		default:
			width = strlen(cp);
		}
		if (col + width > (screenwidth-2)) {
			printf("\\\n\t");
			col = 8;
		}
		col += width;
		do {
			putchar(*cp++);
		} while (*cp);
	}
	if (col == 0)
		printf("       ");
	printf("\"\n");
}

void
ktrgenio(struct ktr_genio *ktr, int len)
{
	int datalen = len - sizeof (struct ktr_genio);
	char *dp = (char *)ktr + sizeof (struct ktr_genio);
	static int screenwidth = 0;
	int i, binary;

	printf("fd %d %s %d byte%s\n", ktr->ktr_fd,
		ktr->ktr_rw == UIO_READ ? "read" : "wrote", datalen,
		datalen == 1 ? "" : "s");
	if (suppressdata)
		return;
	if (screenwidth == 0) {
		struct winsize ws;

		if (fancy && ioctl(fileno(stderr), TIOCGWINSZ, &ws) != -1 &&
		    ws.ws_col > 8)
			screenwidth = ws.ws_col;
		else
			screenwidth = 80;
	}
	if (maxdata && datalen > maxdata)
		datalen = maxdata;

	for (i = 0, binary = 0; i < datalen && binary == 0; i++)  {
		if (dp[i] >= 32 && dp[i] < 127)
			continue;
		if (dp[i] == 10 || dp[i] == 13 || dp[i] == 0 || dp[i] == 9)
			continue;
		binary = 1;
	}
	if (binary)
		hexdump(dp, datalen, screenwidth);
	else
		visdump(dp, datalen, screenwidth);
}

const char *signames[] = {
	"NULL", "HUP", "INT", "QUIT", "ILL", "TRAP", "IOT",	/*  1 - 6  */
	"EMT", "FPE", "KILL", "BUS", "SEGV", "SYS",		/*  7 - 12 */
	"PIPE", "ALRM",  "TERM", "URG", "STOP", "TSTP",		/* 13 - 18 */
	"CONT", "CHLD", "TTIN", "TTOU", "IO", "XCPU",		/* 19 - 24 */
	"XFSZ", "VTALRM", "PROF", "WINCH", "29", "USR1",	/* 25 - 30 */
	"USR2", NULL,						/* 31 - 32 */
};

void
ktrpsig(struct ktr_psig *psig)
{
	if (psig->signo > 0 && psig->signo < NSIG)
		printf("SIG%s ", signames[psig->signo]);
	else
		printf("SIG %d ", psig->signo);
	if (psig->action == SIG_DFL) {
		printf("SIG_DFL code=");
		sigcodename(psig->signo, psig->code);
		putchar('\n');
	} else {
		printf("caught handler=0x%lx mask=0x%x code=",
		    (u_long)psig->action, psig->mask.__bits[0]);
		sigcodename(psig->signo, psig->code);
		putchar('\n');
	}
}

void
ktrcsw_old(struct ktr_csw_old *cs)
{
	printf("%s %s\n", cs->out ? "stop" : "resume",
		cs->user ? "user" : "kernel");
}

void
ktrcsw(struct ktr_csw *cs)
{
	printf("%s %s \"%s\"\n", cs->out ? "stop" : "resume",
	    cs->user ? "user" : "kernel", cs->wmesg);
}

void
ktruser(int len, void *p)
{
	unsigned char *cp;

	if (sysdecode_utrace(stdout, p, len)) {
		printf("\n");
		return;
	}

	printf("%d ", len);
	cp = p;
	while (len--)
		if (decimal)
			printf(" %d", *cp++);
		else
			printf(" %02x", *cp++);
	printf("\n");
}

void
ktrcaprights(cap_rights_t *rightsp)
{

	printf("cap_rights_t ");
	capname(rightsp);
	printf("\n");
}

void
ktrsockaddr(struct sockaddr *sa)
{
/*
 TODO: Support additional address families
	#include <netnatm/natm.h>
	struct sockaddr_natm	*natm;
	#include <netsmb/netbios.h>
	struct sockaddr_nb	*nb;
*/
	char addr[64];

	/*
	 * note: ktrstruct() has already verified that sa points to a
	 * buffer at least sizeof(struct sockaddr) bytes long and exactly
	 * sa->sa_len bytes long.
	 */
	printf("struct sockaddr { ");
	sockfamilyname(sa->sa_family);
	printf(", ");

#define check_sockaddr_len(n)					\
	if (sa_##n.s##n##_len < sizeof(struct sockaddr_##n)) {	\
		printf("invalid");				\
		break;						\
	}

	switch(sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in sa_in;

		memset(&sa_in, 0, sizeof(sa_in));
		memcpy(&sa_in, sa, sa->sa_len);
		check_sockaddr_len(in);
		inet_ntop(AF_INET, &sa_in.sin_addr, addr, sizeof addr);
		printf("%s:%u", addr, ntohs(sa_in.sin_port));
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 sa_in6;

		memset(&sa_in6, 0, sizeof(sa_in6));
		memcpy(&sa_in6, sa, sa->sa_len);
		check_sockaddr_len(in6);
		getnameinfo((struct sockaddr *)&sa_in6, sizeof(sa_in6),
		    addr, sizeof(addr), NULL, 0, NI_NUMERICHOST);
		printf("[%s]:%u", addr, htons(sa_in6.sin6_port));
		break;
	}
	case AF_UNIX: {
		struct sockaddr_un sa_un;

		memset(&sa_un, 0, sizeof(sa_un));
		memcpy(&sa_un, sa, sa->sa_len);
		printf("%.*s", (int)sizeof(sa_un.sun_path), sa_un.sun_path);
		break;
	}
	default:
		printf("unknown address family");
	}
	printf(" }\n");
}

void
ktrstat(struct stat *statp)
{
	char mode[12], timestr[PATH_MAX + 4];
	struct passwd *pwd;
	struct group  *grp;
	struct tm *tm;

	/*
	 * note: ktrstruct() has already verified that statp points to a
	 * buffer exactly sizeof(struct stat) bytes long.
	 */
	printf("struct stat {");
	printf("dev=%ju, ino=%ju, ",
		(uintmax_t)statp->st_dev, (uintmax_t)statp->st_ino);
	if (resolv == 0)
		printf("mode=0%jo, ", (uintmax_t)statp->st_mode);
	else {
		strmode(statp->st_mode, mode);
		printf("mode=%s, ", mode);
	}
	printf("nlink=%ju, ", (uintmax_t)statp->st_nlink);
	if (resolv == 0) {
		pwd = NULL;
	} else {
#ifdef HAVE_LIBCAPSICUM
		if (cappwd != NULL)
			pwd = cap_getpwuid(cappwd, statp->st_uid);
		else
#endif
			pwd = getpwuid(statp->st_uid);
	}
	if (pwd == NULL)
		printf("uid=%ju, ", (uintmax_t)statp->st_uid);
	else
		printf("uid=\"%s\", ", pwd->pw_name);
	if (resolv == 0) {
		grp = NULL;
	} else {
#ifdef HAVE_LIBCAPSICUM
		if (capgrp != NULL)
			grp = cap_getgrgid(capgrp, statp->st_gid);
		else
#endif
			grp = getgrgid(statp->st_gid);
	}
	if (grp == NULL)
		printf("gid=%ju, ", (uintmax_t)statp->st_gid);
	else
		printf("gid=\"%s\", ", grp->gr_name);
	printf("rdev=%ju, ", (uintmax_t)statp->st_rdev);
	printf("atime=");
	if (resolv == 0)
		printf("%jd", (intmax_t)statp->st_atim.tv_sec);
	else {
		tm = localtime(&statp->st_atim.tv_sec);
		strftime(timestr, sizeof(timestr), TIME_FORMAT, tm);
		printf("\"%s\"", timestr);
	}
	if (statp->st_atim.tv_nsec != 0)
		printf(".%09ld, ", statp->st_atim.tv_nsec);
	else
		printf(", ");
	printf("stime=");
	if (resolv == 0)
		printf("%jd", (intmax_t)statp->st_mtim.tv_sec);
	else {
		tm = localtime(&statp->st_mtim.tv_sec);
		strftime(timestr, sizeof(timestr), TIME_FORMAT, tm);
		printf("\"%s\"", timestr);
	}
	if (statp->st_mtim.tv_nsec != 0)
		printf(".%09ld, ", statp->st_mtim.tv_nsec);
	else
		printf(", ");
	printf("ctime=");
	if (resolv == 0)
		printf("%jd", (intmax_t)statp->st_ctim.tv_sec);
	else {
		tm = localtime(&statp->st_ctim.tv_sec);
		strftime(timestr, sizeof(timestr), TIME_FORMAT, tm);
		printf("\"%s\"", timestr);
	}
	if (statp->st_ctim.tv_nsec != 0)
		printf(".%09ld, ", statp->st_ctim.tv_nsec);
	else
		printf(", ");
	printf("birthtime=");
	if (resolv == 0)
		printf("%jd", (intmax_t)statp->st_birthtim.tv_sec);
	else {
		tm = localtime(&statp->st_birthtim.tv_sec);
		strftime(timestr, sizeof(timestr), TIME_FORMAT, tm);
		printf("\"%s\"", timestr);
	}
	if (statp->st_birthtim.tv_nsec != 0)
		printf(".%09ld, ", statp->st_birthtim.tv_nsec);
	else
		printf(", ");
	printf("size=%jd, blksize=%ju, blocks=%jd, flags=0x%x",
		(uintmax_t)statp->st_size, (uintmax_t)statp->st_blksize,
		(intmax_t)statp->st_blocks, statp->st_flags);
	printf(" }\n");
}

void
ktrstruct(char *buf, size_t buflen)
{
	char *name, *data;
	size_t namelen, datalen;
	int i;
	cap_rights_t rights;
	struct stat sb;
	struct sockaddr_storage ss;

	for (name = buf, namelen = 0;
	     namelen < buflen && name[namelen] != '\0';
	     ++namelen)
		/* nothing */;
	if (namelen == buflen)
		goto invalid;
	if (name[namelen] != '\0')
		goto invalid;
	data = buf + namelen + 1;
	datalen = buflen - namelen - 1;
	if (datalen == 0)
		goto invalid;
	/* sanity check */
	for (i = 0; i < (int)namelen; ++i)
		if (!isalpha(name[i]))
			goto invalid;
	if (strcmp(name, "caprights") == 0) {
		if (datalen != sizeof(cap_rights_t))
			goto invalid;
		memcpy(&rights, data, datalen);
		ktrcaprights(&rights);
	} else if (strcmp(name, "stat") == 0) {
		if (datalen != sizeof(struct stat))
			goto invalid;
		memcpy(&sb, data, datalen);
		ktrstat(&sb);
	} else if (strcmp(name, "sockaddr") == 0) {
		if (datalen > sizeof(ss))
			goto invalid;
		memcpy(&ss, data, datalen);
		if (datalen != ss.ss_len)
			goto invalid;
		ktrsockaddr((struct sockaddr *)&ss);
	} else {
		printf("unknown structure\n");
	}
	return;
invalid:
	printf("invalid record\n");
}

void
ktrcapfail(struct ktr_cap_fail *ktr)
{
	switch (ktr->cap_type) {
	case CAPFAIL_NOTCAPABLE:
		/* operation on fd with insufficient capabilities */
		printf("operation requires ");
		capname(&ktr->cap_needed);
		printf(", descriptor holds ");
		capname(&ktr->cap_held);
		break;
	case CAPFAIL_INCREASE:
		/* requested more capabilities than fd already has */
		printf("attempt to increase capabilities from ");
		capname(&ktr->cap_held);
		printf(" to ");
		capname(&ktr->cap_needed);
		break;
	case CAPFAIL_SYSCALL:
		/* called restricted syscall */
		printf("disallowed system call");
		break;
	case CAPFAIL_LOOKUP:
		/* used ".." in strict-relative mode */
		printf("restricted VFS lookup");
		break;
	default:
		printf("unknown capability failure: ");
		capname(&ktr->cap_needed);
		printf(" ");
		capname(&ktr->cap_held);
		break;
	}
	printf("\n");
}

void
ktrfault(struct ktr_fault *ktr)
{

	printf("0x%jx ", (uintmax_t)ktr->vaddr);
	vmprotname(ktr->type);
	printf("\n");
}

void
ktrfaultend(struct ktr_faultend *ktr)
{

	vmresultname(ktr->result);
	printf("\n");
}

static void
printcap(const char *name, struct cheri_serial *cap)
{
	static int screenwidth = 0;

	printf("       %s: tag %u", name, cap->cs_tag);
	if (cap->cs_tag) {
		printf(" sealed %u perms %0*x type %x\n",
		    cap->cs_sealed, cap->cs_permbits / 4, cap->cs_perms,
		    cap->cs_tag);
		printf("       base %016lx length %016lx offset %016lx\n",
		    cap->cs_base, cap->cs_length, cap->cs_offset);
	} else {
		if (screenwidth == 0) {
			struct winsize ws;

			if (fancy &&
			    ioctl(fileno(stderr), TIOCGWINSZ, &ws) != -1 &&
			    ws.ws_col > 8)
				screenwidth = ws.ws_col;
			else
				screenwidth = 80;
		}
		printf("\n");
		hexdump(cap->cs_data, cap->cs_storage * 8, screenwidth);
	}
}

void
ktrccall(struct ktr_ccall *ktr)
{

	printf("method 0x%jx\n", ktr->ktr_method);
	printcap("PCC", &ktr->ktr_pcc);
	printcap("IDC", &ktr->ktr_idc);
}

void
ktrcreturn(struct ktr_creturn *ktr)
{

	printf("integer return: %jd\n", (intmax_t)ktr->ktr_iret);
	printcap("capability return", &ktr->ktr_cret);
}

void
ktrcexception(struct ktr_cexception *ktr)
{

	/* XXXBD: Expand exception codes to names */
	printf("ExcCode 0x%x RegNum %d\n", ktr->ktr_exccode, ktr->ktr_regnum);
	printcap("faulting capability", &ktr->ktr_cap);
}

#if defined(__amd64__) || defined(__i386__)
void
linux_ktrsysret(struct ktr_sysret *ktr, u_int sv_flags)
{
	register_t ret = ktr->ktr_retval;
	int error = ktr->ktr_error;

	syscallname(ktr->ktr_code, sv_flags);
	printf(" ");

	if (error == 0) {
		if (fancy) {
			printf("%ld", (long)ret);
			if (ret < 0 || ret > 9)
				printf("/%#lx", (unsigned long)ret);
		} else {
			if (decimal)
				printf("%ld", (long)ret);
			else
				printf("%#lx", (unsigned long)ret);
		}
	} else if (error == ERESTART)
		printf("RESTART");
	else if (error == EJUSTRETURN)
		printf("JUSTRETURN");
	else {
		if (ktr->ktr_error <= ELAST + 1)
			error = abs(bsd_to_linux_errno[ktr->ktr_error]);
		else
			error = 999;
		printf("-1 errno %d", error);
		if (fancy)
			printf(" %s", strerror(ktr->ktr_error));
	}
	putchar('\n');
}
#endif

void
usage(void)
{
	fprintf(stderr, "usage: kdump [-dEnlHRrSsTA] [-f trfile] "
	    "[-m maxdata] [-p pid] [-t trstr]\n");
	exit(1);
}
